import os, sqlite3, json, secrets, time, datetime as dt, hashlib
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

ADMIN_KEY = os.getenv("ADMIN_KEY", "").strip()
DB = os.getenv("DB_PATH", "pc.db")
DATA_DIR = os.getenv("DATA_DIR", "data")
os.makedirs(DATA_DIR, exist_ok=True)
APK_PATH = os.path.join(DATA_DIR, "update.apk")
app = FastAPI(title="ParentControl")

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY, name TEXT, token TEXT UNIQUE,
        template_id INTEGER, blocked TEXT DEFAULT '[]', locked INTEGER DEFAULT 0,
        last_seen INTEGER DEFAULT 0, apps TEXT DEFAULT '[]', admin_active INTEGER DEFAULT 1,
        app_limits TEXT DEFAULT '{}', app_version_code INTEGER DEFAULT 0,
        blocked_domains TEXT DEFAULT '[]', net_filter_enabled INTEGER DEFAULT 0,
        last_cmd_result TEXT, vpn_consent INTEGER DEFAULT 0, net_filter_running INTEGER DEFAULT 0,
        net_filter_error TEXT, loc_lat REAL, loc_lon REAL, loc_accuracy REAL, loc_at INTEGER,
        device_owner INTEGER DEFAULT 0, accessibility_active INTEGER DEFAULT 0, policy_error TEXT);
    CREATE TABLE IF NOT EXISTS codes(code TEXT PRIMARY KEY, exp INTEGER);
    CREATE TABLE IF NOT EXISTS templates(id INTEGER PRIMARY KEY, name TEXT, policy TEXT);
    CREATE TABLE IF NOT EXISTS usage(device_id INTEGER, day TEXT, pkg TEXT, label TEXT, minutes INTEGER,
        PRIMARY KEY(device_id, day, pkg));
    CREATE TABLE IF NOT EXISTS traffic(device_id INTEGER, day TEXT, pkg TEXT, label TEXT, bytes INTEGER,
        PRIMARY KEY(device_id, day, pkg));
    CREATE TABLE IF NOT EXISTS commands(id INTEGER PRIMARY KEY, device_id INTEGER, cmd TEXT, done INTEGER DEFAULT 0,
        status TEXT DEFAULT 'pending', created_at INTEGER DEFAULT 0, delivered_at INTEGER, completed_at INTEGER, result TEXT);
    CREATE TABLE IF NOT EXISTS app_release(id INTEGER PRIMARY KEY CHECK(id=1), version_code INTEGER, version_name TEXT, uploaded_at INTEGER, sha256 TEXT);
    """)
    for col, ddl in [("admin_active", "INTEGER DEFAULT 1"), ("app_limits", "TEXT DEFAULT '{}'"),
                      ("app_version_code", "INTEGER DEFAULT 0"), ("blocked_domains", "TEXT DEFAULT '[]'"),
                      ("net_filter_enabled", "INTEGER DEFAULT 0"), ("last_cmd_result", "TEXT"),
                      ("vpn_consent", "INTEGER DEFAULT 0"), ("net_filter_running", "INTEGER DEFAULT 0"),
                      ("net_filter_error", "TEXT"), ("loc_lat", "REAL"), ("loc_lon", "REAL"),
                      ("loc_accuracy", "REAL"), ("loc_at", "INTEGER"),
                      ("device_owner", "INTEGER DEFAULT 0"), ("accessibility_active", "INTEGER DEFAULT 0"),
                      ("policy_error", "TEXT")]:
        try: c.execute(f"ALTER TABLE devices ADD COLUMN {col} {ddl}")
        except sqlite3.OperationalError: pass
    for col, ddl in [("status", "TEXT DEFAULT 'pending'"), ("created_at", "INTEGER DEFAULT 0"),
                     ("delivered_at", "INTEGER"), ("completed_at", "INTEGER"), ("result", "TEXT")]:
        try: c.execute(f"ALTER TABLE commands ADD COLUMN {col} {ddl}")
        except sqlite3.OperationalError: pass
    c.execute("UPDATE commands SET status=CASE WHEN done=1 THEN 'done' ELSE 'pending' END WHERE status IS NULL OR status=''")
    c.execute("UPDATE commands SET created_at=? WHERE created_at IS NULL OR created_at=0", (int(time.time()),))
    try: c.execute("ALTER TABLE app_release ADD COLUMN sha256 TEXT")
    except sqlite3.OperationalError: pass
    if not c.execute("SELECT 1 FROM templates").fetchone():
        dialer = ["com.google.android.dialer", "com.android.dialer", "com.samsung.android.dialer"]
        seeds = [
            ("Без обмежень", {}),
            ("Навчання (до 2 год)", {"daily_limit": 120, "quiet_start": "08:00", "quiet_end": "14:00", "quiet_allowed": dialer}),
            ("Сон", {"quiet_start": "21:00", "quiet_end": "07:00", "quiet_allowed": dialer}),
            ("Вихідні (до 4 год)", {"daily_limit": 240, "quiet_start": "22:00", "quiet_end": "08:00", "quiet_allowed": dialer}),
        ]
        for n, p in seeds:
            c.execute("INSERT INTO templates(name,policy) VALUES(?,?)", (n, json.dumps(p)))
    c.commit()
init()

def admin(x_admin_key: Optional[str] = Header(None)):
    if not ADMIN_KEY or ADMIN_KEY == "change-me":
        raise HTTPException(503, "ADMIN_KEY is not configured; set a unique administrator password")
    if not x_admin_key or not secrets.compare_digest(x_admin_key, ADMIN_KEY):
        raise HTTPException(401, "bad key")

def device(x_device_token: Optional[str] = Header(None)):
    r = db().execute("SELECT * FROM devices WHERE token=?", (x_device_token or "",)).fetchone()
    if not r: raise HTTPException(401, "bad token")
    return r

def effective(c, d):
    t = c.execute("SELECT policy FROM templates WHERE id=?", (d["template_id"],)).fetchone()
    p = json.loads(t["policy"]) if t else {}
    p["blocked"] = sorted(set(p.get("blocked", [])) | set(json.loads(d["blocked"])))
    p["app_limits"] = {**p.get("app_limits", {}), **json.loads(d["app_limits"])}  # device overrides template per app
    p["blocked_domains"] = sorted(set(p.get("blocked_domains", [])) | set(json.loads(d["blocked_domains"])))
    p["locked"] = bool(d["locked"])
    p["net_filter_enabled"] = bool(d["net_filter_enabled"])
    return p

# ---------- device side ----------
class Enroll(BaseModel):
    code: str
    name: str = "Пристрій"

@app.post("/api/enroll")
def enroll(b: Enroll):
    c = db()
    r = c.execute("SELECT * FROM codes WHERE code=? AND exp>?", (b.code, int(time.time()))).fetchone()
    if not r: raise HTTPException(400, "invalid or expired code")
    c.execute("DELETE FROM codes WHERE code=?", (b.code,))
    tpl = c.execute("SELECT id FROM templates ORDER BY id LIMIT 1").fetchone()["id"]
    token = secrets.token_urlsafe(32)
    cur = c.execute("INSERT INTO devices(name,token,template_id) VALUES(?,?,?)", (b.name, token, tpl))
    c.commit()
    return {"device_id": cur.lastrowid, "token": token}

class Sync(BaseModel):
    day: str
    usage: list = Field(default_factory=list)
    traffic: list = Field(default_factory=list)
    apps: list = Field(default_factory=list)
    admin_active: bool = True
    device_owner: bool = False
    accessibility_active: bool = False
    command_results: list = Field(default_factory=list)
    app_version_code: int = 0
    last_cmd_result: Optional[str] = None
    vpn_consent: bool = False
    net_filter_running: bool = False
    net_filter_error: Optional[str] = None
    policy_error: Optional[str] = None
    location: Optional[dict] = None

ALLOWED_CMDS = {"flashlight_on", "flashlight_off", "alarm"}

@app.post("/api/device/sync")
def sync(b: Sync, d=Depends(device)):
    c = db()
    for u in b.usage:
        c.execute("""INSERT INTO usage VALUES(?,?,?,?,?) ON CONFLICT(device_id,day,pkg)
                     DO UPDATE SET minutes=excluded.minutes,label=excluded.label""",
                  (d["id"], b.day, u["pkg"], u.get("label", u["pkg"]), int(u["minutes"])))
    for t in b.traffic:
        c.execute("""INSERT INTO traffic VALUES(?,?,?,?,?) ON CONFLICT(device_id,day,pkg)
                     DO UPDATE SET bytes=excluded.bytes,label=excluded.label""",
                  (d["id"], b.day, t["pkg"], t.get("label", t["pkg"]), int(t["bytes"])))
    if b.apps:
        c.execute("UPDATE devices SET apps=? WHERE id=?", (json.dumps(b.apps), d["id"]))
    if b.last_cmd_result is not None:
        c.execute("UPDATE devices SET last_cmd_result=? WHERE id=?", (b.last_cmd_result, d["id"]))
    if b.location is not None:
        c.execute("UPDATE devices SET loc_lat=?, loc_lon=?, loc_accuracy=?, loc_at=? WHERE id=?",
                  (b.location.get("lat"), b.location.get("lon"), b.location.get("accuracy"), int(time.time()), d["id"]))
    c.execute("""UPDATE devices SET last_seen=?, admin_active=?, app_version_code=?,
                 vpn_consent=?, net_filter_running=?, net_filter_error=?, device_owner=?, accessibility_active=?, policy_error=? WHERE id=?""",
              (int(time.time()), int(b.admin_active), b.app_version_code,
               int(b.vpn_consent), int(b.net_filter_running), b.net_filter_error,
               int(b.device_owner), int(b.accessibility_active), b.policy_error, d["id"]))
    # Acknowledge only commands whose execution result reached the server.
    for item in b.command_results:
        try:
            command_id = int(item["id"])
            result = str(item.get("result", ""))[:1000]
            c.execute("""UPDATE commands SET done=1,status='done',completed_at=?,result=?
                         WHERE id=? AND device_id=? AND done=0""",
                      (int(time.time()), result, command_id, d["id"]))
        except (KeyError, TypeError, ValueError):
            continue
    now = int(time.time())
    # Lease commands for 60 seconds. Unacknowledged commands are redelivered after lease expiry.
    rows = c.execute("""SELECT id,cmd FROM commands WHERE device_id=? AND done=0
                       AND (status='pending' OR (status='delivered' AND COALESCE(delivered_at,0)<?))
                       ORDER BY id LIMIT 50""", (d["id"], now - 60)).fetchall()
    cmds = [{"id": r["id"], "cmd": r["cmd"]} for r in rows]
    if rows:
        c.executemany("UPDATE commands SET status='delivered',delivered_at=? WHERE id=? AND device_id=?",
                      [(now, r["id"], d["id"]) for r in rows])
    c.commit()
    update = None
    rel = c.execute("SELECT * FROM app_release WHERE id=1").fetchone()
    if rel and os.path.exists(APK_PATH) and rel["version_code"] > b.app_version_code:
        update = {"version_code": rel["version_code"], "version_name": rel["version_name"], "url": "/api/device/update",
                  "sha256": rel["sha256"] if "sha256" in rel.keys() else None}
    return {"policy": effective(c, d), "commands": cmds, "update": update}

@app.get("/api/device/update")
def device_update(d=Depends(device)):
    if not os.path.exists(APK_PATH):
        raise HTTPException(404, "no release uploaded")
    return FileResponse(APK_PATH, media_type="application/vnd.android.package-archive", filename="update.apk")

# ---------- parent side ----------
@app.post("/api/pair-code", dependencies=[Depends(admin)])
def pair_code():
    c = db(); code = f"{secrets.randbelow(10**6):06d}"
    c.execute("INSERT INTO codes VALUES(?,?)", (code, int(time.time()) + 600)); c.commit()
    return {"code": code, "expires_in": 600}

@app.get("/api/known-apps", dependencies=[Depends(admin)])
def known_apps():
    seen = {}
    for r in db().execute("SELECT apps FROM devices"):
        for a in json.loads(r["apps"] or "[]"):
            seen[a["pkg"]] = a.get("label", a["pkg"])
    return [{"pkg": k, "label": v} for k, v in sorted(seen.items(), key=lambda x: x[1].lower())]

@app.get("/api/devices", dependencies=[Depends(admin)])
def devices():
    return [dict(r) for r in db().execute("SELECT id,name,template_id,locked,last_seen,admin_active,device_owner,accessibility_active,app_version_code,net_filter_running,net_filter_error,policy_error FROM devices")]

@app.get("/api/devices/{did}", dependencies=[Depends(admin)])
def device_detail(did: int):
    c = db(); d = c.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()
    if not d: raise HTTPException(404)
    apps = [{"pkg": a["pkg"], "label": a.get("label", a["pkg"])} for a in json.loads(d["apps"])]
    return {"id": did, "name": d["name"], "template_id": d["template_id"], "locked": bool(d["locked"]),
            "blocked": json.loads(d["blocked"]), "last_seen": d["last_seen"], "admin_active": bool(d["admin_active"]),
            "device_owner": bool(d["device_owner"]), "accessibility_active": bool(d["accessibility_active"]),
            "app_version_code": d["app_version_code"], "net_filter_running": bool(d["net_filter_running"]),
            "net_filter_error": d["net_filter_error"], "policy_error": d["policy_error"],
            "app_limits": json.loads(d["app_limits"]),
            "blocked_domains": json.loads(d["blocked_domains"]), "net_filter_enabled": bool(d["net_filter_enabled"]),
            "last_cmd_result": d["last_cmd_result"], "vpn_consent": bool(d["vpn_consent"]),
            "location": ({"lat": d["loc_lat"], "lon": d["loc_lon"], "accuracy": d["loc_accuracy"], "at": d["loc_at"]}
                         if d["loc_lat"] is not None else None),
            "apps": apps, "policy": effective(c, d)}

def _month_bounds(y: int, m: int):
    start = dt.date(y, m, 1)
    ny, nm = (y + 1, 1) if m == 12 else (y, m + 1)
    end = dt.date(ny, nm, 1) - dt.timedelta(days=1)
    return start, end

@app.get("/api/devices/{did}/report", dependencies=[Depends(admin)])
def device_report(did: int, period: str = "day", offset: int = 0):
    c = db(); d = c.execute("SELECT id FROM devices WHERE id=?", (did,)).fetchone()
    if not d: raise HTTPException(404)
    if offset < 0: raise HTTPException(400, "offset must be >= 0")
    today = dt.date.today()
    if period == "day":
        start = end = today - dt.timedelta(days=offset)
    elif period == "week":
        monday = today - dt.timedelta(days=today.weekday()) - dt.timedelta(weeks=offset)
        start, end = monday, monday + dt.timedelta(days=6)
    elif period == "month":
        y, m = today.year, today.month - offset
        while m < 1:
            m += 12; y -= 1
        start, end = _month_bounds(y, m)
    else:
        raise HTTPException(400, "bad period")
    s, e = start.isoformat(), end.isoformat()
    rows = c.execute("SELECT day, pkg, label, minutes FROM usage WHERE device_id=? AND day BETWEEN ? AND ?", (did, s, e)).fetchall()
    trows = c.execute("SELECT day, pkg, label, bytes FROM traffic WHERE device_id=? AND day BETWEEN ? AND ?", (did, s, e)).fetchall()
    by_day_min, by_day_bytes, by_app = {}, {}, {}
    for r in rows:
        by_day_min[r["day"]] = by_day_min.get(r["day"], 0) + r["minutes"]
        key = r["pkg"]
        if key not in by_app: by_app[key] = {"pkg": r["pkg"], "label": r["label"], "minutes": 0, "bytes": 0}
        by_app[key]["minutes"] += r["minutes"]
    for r in trows:
        by_day_bytes[r["day"]] = by_day_bytes.get(r["day"], 0) + r["bytes"]
        key = r["pkg"]
        if key not in by_app: by_app[key] = {"pkg": r["pkg"], "label": r["label"], "minutes": 0, "bytes": 0}
        by_app[key]["bytes"] += r["bytes"]
    daily, cur = [], start
    while cur <= end:
        iso = cur.isoformat()
        daily.append({"day": iso, "minutes": by_day_min.get(iso, 0), "bytes": by_day_bytes.get(iso, 0)})
        cur += dt.timedelta(days=1)
    apps = sorted(by_app.values(), key=lambda a: -a["minutes"])
    return {"start": s, "end": e, "period": period, "offset": offset, "daily": daily, "apps": apps,
            "total_minutes": sum(a["minutes"] for a in apps), "total_bytes": sum(a["bytes"] for a in apps),
            "can_go_forward": offset > 0, "is_today": period == "day" and offset == 0}

class DevUpdate(BaseModel):
    name: Optional[str] = None
    template_id: Optional[int] = None
    blocked: Optional[list] = None
    locked: Optional[bool] = None
    app_limits: Optional[dict] = None
    blocked_domains: Optional[list] = None
    net_filter_enabled: Optional[bool] = None

@app.put("/api/devices/{did}", dependencies=[Depends(admin)])
def device_update(did: int, b: DevUpdate):
    c = db()
    if b.name is not None: c.execute("UPDATE devices SET name=? WHERE id=?", (b.name, did))
    if b.template_id is not None: c.execute("UPDATE devices SET template_id=? WHERE id=?", (b.template_id, did))
    if b.blocked is not None: c.execute("UPDATE devices SET blocked=? WHERE id=?", (json.dumps(b.blocked), did))
    if b.locked is not None: c.execute("UPDATE devices SET locked=? WHERE id=?", (int(b.locked), did))
    if b.app_limits is not None: c.execute("UPDATE devices SET app_limits=? WHERE id=?", (json.dumps(b.app_limits), did))
    if b.blocked_domains is not None: c.execute("UPDATE devices SET blocked_domains=? WHERE id=?", (json.dumps(b.blocked_domains), did))
    if b.net_filter_enabled is not None: c.execute("UPDATE devices SET net_filter_enabled=? WHERE id=?", (int(b.net_filter_enabled), did))
    c.commit(); return {"ok": True}

@app.delete("/api/devices/{did}", dependencies=[Depends(admin)])
def device_delete(did: int):
    c = db(); c.execute("DELETE FROM devices WHERE id=?", (did,)); c.execute("DELETE FROM usage WHERE device_id=?", (did,))
    c.execute("DELETE FROM traffic WHERE device_id=?", (did,)); c.execute("DELETE FROM commands WHERE device_id=?", (did,)); c.commit()
    return {"ok": True}

class Cmd(BaseModel):
    cmd: str  # flashlight_on | flashlight_off | alarm

@app.post("/api/devices/{did}/command", dependencies=[Depends(admin)])
def command(did: int, b: Cmd):
    if b.cmd not in ALLOWED_CMDS: raise HTTPException(400, "unknown command")
    c = db()
    if not c.execute("SELECT 1 FROM devices WHERE id=?", (did,)).fetchone(): raise HTTPException(404, "device not found")
    c.execute("INSERT INTO commands(device_id,cmd,status,created_at) VALUES(?,?,'pending',?)", (did, b.cmd, int(time.time())))
    c.commit()
    return {"ok": True}

class Tpl(BaseModel):
    name: str
    policy: dict

@app.get("/api/templates", dependencies=[Depends(admin)])
def templates():
    return [{"id": r["id"], "name": r["name"], "policy": json.loads(r["policy"])} for r in db().execute("SELECT * FROM templates")]

@app.post("/api/templates", dependencies=[Depends(admin)])
def tpl_create(b: Tpl):
    c = db(); cur = c.execute("INSERT INTO templates(name,policy) VALUES(?,?)", (b.name, json.dumps(b.policy))); c.commit()
    return {"id": cur.lastrowid}

@app.put("/api/templates/{tid}", dependencies=[Depends(admin)])
def tpl_update(tid: int, b: Tpl):
    c = db(); c.execute("UPDATE templates SET name=?,policy=? WHERE id=?", (b.name, json.dumps(b.policy), tid)); c.commit()
    return {"ok": True}

@app.delete("/api/templates/{tid}", dependencies=[Depends(admin)])
def tpl_delete(tid: int):
    c = db(); c.execute("DELETE FROM templates WHERE id=?", (tid,)); c.commit(); return {"ok": True}

@app.get("/api/app-release", dependencies=[Depends(admin)])
def app_release_info():
    r = db().execute("SELECT * FROM app_release WHERE id=1").fetchone()
    if not r or not os.path.exists(APK_PATH):
        return {"version_code": 0, "version_name": None, "uploaded_at": None}
    return {"version_code": r["version_code"], "version_name": r["version_name"], "uploaded_at": r["uploaded_at"]}

@app.post("/api/app-release", dependencies=[Depends(admin)])
async def app_release_upload(version_code: int = Form(...), version_name: str = Form(...), file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "file must be an .apk")
    if version_code <= 0:
        raise HTTPException(400, "version_code must be positive")
    temp_path = APK_PATH + ".uploading"
    digest = hashlib.sha256()
    total = 0
    try:
        with open(temp_path, "wb") as f:
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > 200 * 1024 * 1024:
                    raise HTTPException(413, "APK exceeds 200 MiB")
                digest.update(chunk); f.write(chunk)
        with open(temp_path, "rb") as f:
            if f.read(4) != b"PK\x03\x04": raise HTTPException(400, "uploaded file is not a valid ZIP/APK container")
        os.replace(temp_path, APK_PATH)
    finally:
        if os.path.exists(temp_path): os.remove(temp_path)
    c = db()
    c.execute("""INSERT INTO app_release(id,version_code,version_name,uploaded_at,sha256) VALUES(1,?,?,?,?)
                 ON CONFLICT(id) DO UPDATE SET version_code=excluded.version_code,
                 version_name=excluded.version_name, uploaded_at=excluded.uploaded_at, sha256=excluded.sha256""",
              (version_code, version_name, int(time.time()), digest.hexdigest()))
    c.commit()
    return {"ok": True}

@app.get("/")
def index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))
