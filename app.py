import base64, os, sqlite3, secrets, json, uuid, requests, time, threading
from datetime import datetime
from urllib.parse import urlparse
from flask import (Flask, g, request, session, redirect, render_template, send_from_directory,
                   abort, flash, url_for)
from jinja2 import DictLoader
from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash

DATA = os.environ.get("DATA_DIR", "/data")
MEDIA = os.path.join(DATA, "media")
os.makedirs(MEDIA, exist_ok=True)
KEY = os.environ.get("SETLISTFM_API_KEY", "")
COBALT = os.environ.get("COBALT_URL", "").rstrip("/")
IMG = {"jpg", "jpeg", "png", "gif", "webp", "avif"}
VID = {"mp4", "mov", "webm", "m4v"}

def secret():
    if os.environ.get("SECRET_KEY"): return os.environ["SECRET_KEY"]
    p = os.path.join(DATA, "secret")
    if not os.path.exists(p): open(p, "w").write(secrets.token_hex(32))
    return open(p).read()

app = Flask(__name__)
app.secret_key = secret()
app.config.update(MAX_CONTENT_LENGTH=4 * 1024**3, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_HTTPONLY=True, PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 365)

def conn():
    c = sqlite3.connect(os.path.join(DATA, "app.db")); c.row_factory = sqlite3.Row; return c
with conn() as c:
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT UNIQUE, pw TEXT, admin INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS invites(token TEXT PRIMARY KEY, used_by INT);
    CREATE TABLE IF NOT EXISTS concerts(id INTEGER PRIMARY KEY, user_id INT, artist TEXT, venue TEXT, city TEXT,
      date TEXT, notes TEXT DEFAULT '', setlist TEXT DEFAULT '[]', sid TEXT, UNIQUE(user_id, sid));
    CREATE TABLE IF NOT EXISTS media(id INTEGER PRIMARY KEY, concert_id INT, file TEXT, kind TEXT);
    CREATE TABLE IF NOT EXISTS venues(id INTEGER PRIMARY KEY, name TEXT, city TEXT, file TEXT, tried REAL DEFAULT 0, UNIQUE(name, city));
    CREATE TABLE IF NOT EXISTS attendees(concert_id INT, user_id INT, PRIMARY KEY(concert_id, user_id));
    """)
    for stmt in ("ALTER TABLE users ADD COLUMN sfm_user TEXT DEFAULT ''", "ALTER TABLE users ADD COLUMN last_sync REAL DEFAULT 0",
                 "ALTER TABLE concerts ADD COLUMN poster TEXT", "ALTER TABLE media ADD COLUMN uploader INT",
                 "ALTER TABLE media ADD COLUMN platform TEXT"):
        try: c.execute(stmt)
        except sqlite3.OperationalError: pass

def db():
    if "db" not in g: g.db = conn()
    return g.db
@app.teardown_appcontext
def _close(e):
    d = g.pop("db", None)
    if d: d.close()
def q(sql, *a): return db().execute(sql, a).fetchall()
def run(sql, *a):
    cur = db().execute(sql, a); db().commit(); return cur

def csrf():
    session.setdefault("t", secrets.token_hex(16)); return session["t"]
app.jinja_env.globals["tok"] = lambda: Markup(f'<input type=hidden name=t value="{csrf()}">')

@app.before_request
def guard():
    if request.method == "POST" and not secrets.compare_digest(request.form.get("t", ""), session.get("t", "x")):
        abort(400)
    uid = session.get("uid")
    g.user = (q("SELECT * FROM users WHERE id=?", uid) or [None])[0] if uid else None
    if not g.user and request.endpoint not in ("login", "join", "static", "logo", "touch_icon"):
        return redirect(url_for("login"))

def sfm(path, **params):
    if not KEY: raise RuntimeError("SETLISTFM_API_KEY is not set")
    r = requests.get("https://api.setlist.fm/rest/1.0/" + path, params=params, timeout=20,
                     headers={"x-api-key": KEY, "Accept": "application/json"})
    r.raise_for_status(); return r.json()

def norm(s):
    d, m, y = s["eventDate"].split("-")
    songs = [so["name"] for st in s.get("sets", {}).get("set", []) for so in st.get("song", []) if so.get("name")]
    v = s.get("venue", {}); ci = v.get("city", {})
    city = ", ".join(x for x in [ci.get("name"), ci.get("country", {}).get("name")] if x)
    return dict(sid=s["id"], artist=s["artist"]["name"], venue=v.get("name", ""), city=city, date=f"{y}-{m}-{d}", setlist=songs)

def save(uid, s):
    run("INSERT OR IGNORE INTO concerts(user_id,artist,venue,city,date,setlist,sid) VALUES(?,?,?,?,?,?,?)",
        uid, s["artist"], s["venue"], s["city"], s["date"], json.dumps(s["setlist"]), s["sid"])

# ---------- auth ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = (q("SELECT * FROM users WHERE name=?", request.form["name"].strip()) or [None])[0]
        if u and check_password_hash(u["pw"], request.form["pw"]):
            session.clear(); session["uid"] = u["id"]; session.permanent = True; return redirect("/")
        flash("Wrong name or password")
    return render_template("login", first=not q("SELECT 1 FROM users"))

@app.route("/join", methods=["GET", "POST"])
def join():
    tok = request.values.get("token", "")
    first = not q("SELECT 1 FROM users")
    if not first and not q("SELECT 1 FROM invites WHERE token=? AND used_by IS NULL", tok):
        abort(404)
    if request.method == "POST":
        name, pw = request.form["name"].strip(), request.form["pw"]
        if not name or len(pw) < 8: flash("Name required; password needs 8+ characters")
        elif q("SELECT 1 FROM users WHERE name=?", name): flash("Name taken")
        else:
            uid = run("INSERT INTO users(name,pw,admin) VALUES(?,?,?)", name, generate_password_hash(pw), int(first)).lastrowid
            if not first: run("UPDATE invites SET used_by=? WHERE token=?", uid, tok)
            session.clear(); session["uid"] = uid; session.permanent = True; return redirect("/")
    return render_template("join", tok_value=tok, first=first)

@app.post("/logout")
def logout(): session.clear(); return redirect(url_for("login"))

@app.route("/invites", methods=["GET", "POST"])
def invites():
    if not g.user["admin"]: abort(403)
    if request.method == "POST": run("INSERT INTO invites(token) VALUES(?)", secrets.token_urlsafe(16)); return redirect("/invites")
    return render_template("invites", rows=q("SELECT i.*, u.name AS who FROM invites i LEFT JOIN users u ON u.id=i.used_by"))

# ---------- concerts ----------
SORTS = {"date": "date DESC", "oldest": "date ASC", "artist": "artist COLLATE NOCASE", "venue": "venue COLLATE NOCASE",
         "city": "city COLLATE NOCASE", "added": "c.id DESC"}

def page(u):
    sort = request.args.get("sort", "date"); sort = sort if sort in SORTS else "date"
    year = request.args.get("year", "")
    sql = ("SELECT c.*, (SELECT COUNT(*) FROM media m WHERE m.concert_id=c.id) AS n FROM concerts c "
           "WHERE (c.user_id=? OR c.id IN (SELECT concert_id FROM attendees WHERE user_id=?))")
    a = [u["id"], u["id"]]
    if year.isdigit(): sql += " AND substr(c.date,1,4)=?"; a.append(year)
    years = [r["y"] for r in q("SELECT DISTINCT substr(date,1,4) y FROM concerts ORDER BY y DESC")]
    return render_template("home", who=u, rows=q(sql + " ORDER BY " + SORTS[sort], *a), years=years, sort=sort, year=year,
                           mine=u["id"] == g.user["id"])

@app.route("/")
def home(): return page(g.user)

@app.route("/u/<name>")
def user(name): return page((q("SELECT * FROM users WHERE name=?", name) or [None])[0] or abort(404))

@app.route("/people")
def people():
    return render_template("people", rows=q("SELECT name,(SELECT COUNT(*) FROM concerts WHERE user_id=users.id) n FROM users ORDER BY name"))

@app.route("/search")
def search():
    res, a, y = [], request.args.get("artist", "").strip(), request.args.get("year", "").strip()
    if a:
        try:
            p = {"artistName": a}
            if y: p["year"] = y
            res = [norm(s) for s in sfm("search/setlists", **p).get("setlist", [])]
        except Exception as e:
            flash(f"setlist.fm: {e}")
    return render_template("search", res=res, a=a, y=y)

@app.post("/add")
def add():
    try: save(g.user["id"], norm(sfm("setlist/" + request.form["sid"])))
    except Exception as e: flash(f"setlist.fm: {e}")
    return redirect("/")

def sync_user(uid, name):
    page = 1
    while page <= 100:
        d = sfm(f"user/{name}/attended", p=page)
        for s in d.get("setlist", []): save(uid, norm(s))
        if page * d.get("itemsPerPage", 20) >= d.get("total", 0): break
        page += 1; time.sleep(0.6)

def sync_bg(uid=None):
    with app.app_context():
        if uid: us = q("SELECT * FROM users WHERE id=? AND sfm_user!=''", uid)
        else: us = q("SELECT * FROM users WHERE sfm_user!='' AND last_sync<?", time.time() - 86400)
        for u in us:
            run("UPDATE users SET last_sync=? WHERE id=?", time.time(), u["id"])
            try: sync_user(u["id"], u["sfm_user"])
            except Exception as e: app.logger.warning("sync %s failed: %s", u["name"], e)

def loop():
    while True:
        try: sync_bg()
        except Exception: pass
        time.sleep(3600)

@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        run("UPDATE users SET sfm_user=?, last_sync=0 WHERE id=?", request.form["sfm_user"].strip(), g.user["id"])
        threading.Thread(target=sync_bg, args=(g.user["id"],), daemon=True).start()
        flash("Saved. Importing in the background; refresh in a minute."); return redirect("/settings")
    return render_template("settings", u=q("SELECT * FROM users WHERE id=?", g.user["id"])[0],
        venues=q("SELECT DISTINCT venue, city FROM concerts WHERE user_id=? AND venue!='' ORDER BY venue", g.user["id"]))

@app.post("/sync")
def sync():
    run("UPDATE users SET last_sync=0 WHERE id=?", g.user["id"])
    threading.Thread(target=sync_bg, args=(g.user["id"],), daemon=True).start()
    flash("Sync started; refresh in a minute."); return redirect("/settings")

@app.route("/new", methods=["GET", "POST"])
def new():
    if request.method == "POST":
        f = request.form
        songs = [s.strip() for s in f.get("setlist", "").splitlines() if s.strip()]
        cid = run("INSERT INTO concerts(user_id,artist,venue,city,date,setlist,notes) VALUES(?,?,?,?,?,?,?)",
                  g.user["id"], f["artist"], f["venue"], f["city"], f["date"], json.dumps(songs), f.get("notes", "")).lastrowid
        return redirect(f"/c/{cid}")
    return render_template("new")

def owned(cid):
    c = (q("SELECT * FROM concerts WHERE id=?", cid) or [None])[0] or abort(404)
    return c

@app.route("/c/<int:cid>")
def concert(cid):
    c = owned(cid)
    att = q("SELECT u.id,u.name FROM attendees a JOIN users u ON u.id=a.user_id WHERE a.concert_id=?", cid)
    ids = {a["id"] for a in att} | {c["user_id"]}
    return render_template("concert", c=c, songs=json.loads(c["setlist"]), media=q("SELECT m.*, u.name uname FROM media m LEFT JOIN users u ON u.id=COALESCE(m.uploader,?) WHERE m.concert_id=? ORDER BY m.id", c["user_id"], cid),
        can=g.user["id"] in ids, mine=c["user_id"] == g.user["id"], att=att,
        owner=q("SELECT name FROM users WHERE id=?", c["user_id"])[0]["name"],
        others=[u for u in q("SELECT id,name FROM users ORDER BY name") if u["id"] not in ids])

@app.post("/c/<int:cid>/notes")
def notes(cid):
    editor(cid)
    run("UPDATE concerts SET notes=? WHERE id=?", request.form["notes"], cid); return redirect(f"/c/{cid}")

@app.post("/c/<int:cid>/upload")
def upload(cid):
    editor(cid)
    for f in request.files.getlist("files"):
        ext = (f.filename or "").rsplit(".", 1)[-1].lower()
        kind = "image" if ext in IMG else "video" if ext in VID else None
        if not kind: flash(f"Skipped {f.filename}: unsupported type"); continue
        name = f"{uuid.uuid4().hex}.{ext}"; f.save(os.path.join(MEDIA, name))
        add_media(cid, name, kind)
    return redirect(f"/c/{cid}")

CT = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif", "image/avif": "avif",
      "video/mp4": "mp4", "video/quicktime": "mov", "video/webm": "webm"}

def cobalt_fetch(url):
    """Ask cobalt to resolve a post URL, download every item, return [(path, kind)]."""
    r = requests.post(COBALT + "/", json={"url": url}, timeout=60,
                      headers={"Accept": "application/json", "Content-Type": "application/json"}).json()
    st = r.get("status")
    if st == "error": raise RuntimeError(r.get("error", {}).get("code", "cobalt error"))
    if st in ("tunnel", "redirect"): urls = [r["url"]]
    elif st == "picker": urls = [p["url"] for p in r["picker"]]
    else: raise RuntimeError("unsupported cobalt response: " + str(st))
    out = []
    for u in urls:
        with requests.get(u, stream=True, timeout=120) as d:
            d.raise_for_status()
            ext = CT.get(d.headers.get("content-type", "").split(";")[0].strip())
            if not ext: continue
            name = f"{uuid.uuid4().hex}.{ext}"
            with open(os.path.join(MEDIA, name), "wb") as f:
                for chunk in d.iter_content(1 << 20): f.write(chunk)
            out.append((name, "image" if ext in IMG else "video"))
    if not out: raise RuntimeError("no downloadable media found")
    return out

@app.post("/c/<int:cid>/link")
def link(cid):
    editor(cid)
    url = request.form["url"].strip()
    if not COBALT: flash("COBALT_URL is not configured")
    elif not url.startswith(("http://", "https://")): flash("Paste a full link")
    else:
        try:
            for name, kind in cobalt_fetch(url):
                add_media(cid, name, kind, platform(url))
        except Exception as e: flash(f"cobalt: {e}")
    return redirect(f"/c/{cid}")

@app.get("/media/<int:mid>")
def media(mid):
    m = (q("SELECT * FROM media WHERE id=?", mid) or [None])[0] or abort(404)
    return send_from_directory(MEDIA, m["file"], conditional=True)

def rm_media(rows):
    for m in rows:
        try: os.remove(os.path.join(MEDIA, m["file"]))
        except OSError: pass
        run("UPDATE concerts SET poster=NULL WHERE poster=?", m["file"])
        run("DELETE FROM media WHERE id=?", m["id"])

@app.post("/media/<int:mid>/delete")
def del_media(mid):
    m = (q("SELECT m.*, c.user_id FROM media m JOIN concerts c ON c.id=m.concert_id WHERE m.id=?", mid) or [None])[0] or abort(404)
    editor(m["concert_id"])
    rm_media([m]); return redirect(f"/c/{m['concert_id']}")

@app.post("/c/<int:cid>/delete")
def del_concert(cid):
    if owned(cid)["user_id"] != g.user["id"]: abort(403)
    rm_media(q("SELECT * FROM media WHERE concert_id=?", cid)); run("DELETE FROM concerts WHERE id=?", cid); return redirect("/")

def editor(cid):
    c = owned(cid)
    if c["user_id"] != g.user["id"] and not q("SELECT 1 FROM attendees WHERE concert_id=? AND user_id=?", cid, g.user["id"]): abort(403)
    return c

@app.post("/c/<int:cid>/tag")
def tag(cid):
    if owned(cid)["user_id"] != g.user["id"]: abort(403)
    if request.form["uid"].isdigit() and q("SELECT 1 FROM users WHERE id=?", request.form["uid"]):
        run("INSERT OR IGNORE INTO attendees VALUES(?,?)", cid, int(request.form["uid"]))
    return redirect(f"/c/{cid}")

@app.post("/c/<int:cid>/untag")
def untag(cid):
    if owned(cid)["user_id"] != g.user["id"]: abort(403)
    run("DELETE FROM attendees WHERE concert_id=? AND user_id=?", cid, request.form["uid"]); return redirect(f"/c/{cid}")

@app.post("/c/<int:cid>/poster")
def poster(cid):
    editor(cid); mid, f = request.form.get("mid"), request.files.get("file")
    if mid:
        m = q("SELECT file FROM media WHERE id=? AND concert_id=? AND kind='image'", mid, cid)
        if m: run("UPDATE concerts SET poster=? WHERE id=?", m[0]["file"], cid)
    elif f and f.filename:
        ext = f.filename.rsplit(".", 1)[-1].lower()
        if ext in IMG:
            name = f"{uuid.uuid4().hex}.{ext}"; f.save(os.path.join(MEDIA, name))
            add_media(cid, name, "image")
            run("UPDATE concerts SET poster=? WHERE id=?", name, cid)
        else: flash("Cover must be an image")
    return redirect(f"/c/{cid}")

@app.get("/cover/<int:cid>")
def cover(cid):
    return send_from_directory(MEDIA, owned(cid)["poster"] or abort(404), conditional=True)

LOGO = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#7c3aed"/><stop offset="1" stop-color="#db2777"/></linearGradient></defs>
<rect width="64" height="64" rx="14" fill="url(#g)"/><g fill="#fff"><rect x="14" y="13" width="9" height="20" rx="4.5"/><rect x="24" y="10" width="9" height="23" rx="4.5"/>
<rect x="34" y="10" width="9" height="23" rx="4.5"/><rect x="44" y="13" width="7" height="20" rx="3.5"/><rect x="14" y="26" width="37" height="24" rx="9"/></g>
<rect x="12" y="35" width="24" height="9" rx="4.5" fill="#fff" stroke="#9d3fd8" stroke-width="2.5"/><rect x="42" y="41" width="10" height="10" fill="#1a1030"/></svg>"""

@app.get("/logo.svg")
def logo(): return app.response_class(LOGO, mimetype="image/svg+xml", headers={"Cache-Control": "public, max-age=86400"})

ICON_PNG = base64.b64decode("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")

@app.get("/apple-touch-icon.png")
@app.get("/apple-touch-icon-precomposed.png")
def touch_icon(): return app.response_class(ICON_PNG, mimetype="image/png", headers={"Cache-Control": "public, max-age=86400"})

app.jinja_env.filters["hue"] = lambda s: sum(map(ord, s or "x")) % 360
app.jinja_env.filters["ts"] = lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M") if t else "never"

def platform(url):
    h = (urlparse(url).hostname or "").lower()
    for k, p in (("instagram", "instagram"), ("tiktok", "tiktok"), ("youtu", "youtube"), ("twitter", "x"), ("x.com", "x")):
        if k in h: return p
    return "link"

def add_media(cid, name, kind, plat=None):
    run("INSERT INTO media(concert_id,file,kind,uploader,platform) VALUES(?,?,?,?,?)", cid, name, kind, g.user["id"], plat)

def venue_row(n, c):
    run("INSERT OR IGNORE INTO venues(name,city) VALUES(?,?)", n, c)
    return q("SELECT * FROM venues WHERE name=? AND city=?", n, c)[0]

def venue_fetch(n, c):
    r = requests.get("https://en.wikipedia.org/w/api.php", timeout=10, headers={"User-Agent": "ShowProof/1.0 (self-hosted)"},
        params={"action": "query", "generator": "search", "gsrsearch": f"{n} {c}", "gsrlimit": 1, "prop": "pageimages",
                "piprop": "thumbnail", "pithumbsize": 900, "format": "json"}).json()
    for p in r.get("query", {}).get("pages", {}).values():
        words = [w.lower() for w in n.split() if len(w) > 3] or [n.lower()]
        src = p.get("thumbnail", {}).get("source")
        if src and any(w in p.get("title", "").lower() for w in words):
            d = requests.get(src, timeout=20, headers={"User-Agent": "ShowProof/1.0 (self-hosted)"})
            ext = CT.get(d.headers.get("content-type", "").split(";")[0].strip())
            if d.ok and ext in IMG:
                name = f"venue-{uuid.uuid4().hex}.{ext}"; open(os.path.join(MEDIA, name), "wb").write(d.content); return name

@app.get("/venue.img")
def venue_img():
    n, c = request.args.get("n", "").strip(), request.args.get("c", "").strip()
    if not n: abort(404)
    v = venue_row(n, c)
    if not v["file"] and not v["tried"]:
        run("UPDATE venues SET tried=? WHERE id=?", time.time(), v["id"])
        try:
            f = venue_fetch(n, c)
            if f: run("UPDATE venues SET file=? WHERE id=?", f, v["id"])
        except Exception as e: app.logger.info("venue image %s: %s", n, e)
        v = venue_row(n, c)
    return send_from_directory(MEDIA, v["file"] or abort(404), conditional=True)

@app.post("/venue/replace")
def venue_replace():
    n, c, f = request.form["n"].strip(), request.form["c"].strip(), request.files.get("file")
    ext = (f.filename or "").rsplit(".", 1)[-1].lower() if f else ""
    if ext not in IMG: flash("Venue image must be a picture"); return redirect("/settings")
    v = venue_row(n, c); name = f"venue-{uuid.uuid4().hex}.{ext}"; f.save(os.path.join(MEDIA, name))
    if v["file"]:
        try: os.remove(os.path.join(MEDIA, v["file"]))
        except OSError: pass
    run("UPDATE venues SET file=?, tried=? WHERE id=?", name, time.time(), v["id"])
    flash("Venue image updated"); return redirect("/settings")

ICONS = {"instagram": '<rect x="3" y="3" width="18" height="18" rx="5"/><circle cx="12" cy="12" r="4"/><circle cx="17.5" cy="6.5" r=".8"/>',
         "youtube": '<rect x="2" y="5" width="20" height="14" rx="5"/><path d="M10 9l5 3-5 3z"/>',
         "tiktok": '<path d="M14 3v11.5a3.5 3.5 0 11-3.5-3.5M14 3c.3 2.5 2 4 4.5 4.2"/>', "x": '<path d="M4 4l16 16M20 4L4 20"/>',
         "link": '<path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1"/>'}
app.jinja_env.globals["ICONS"] = ICONS

# ---------- templates ----------
CSS = """:root{color-scheme:dark;--bg:#0b0b10;--s1:#15151c;--s2:#1f1f29;--bd:#ffffff14;--fg:#f4f4f6;--mu:#9a9aaa;--ac:#a855f7;--r1:12px;--r2:16px;--rp:999px;--ch:44px}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.4 system-ui,-apple-system,sans-serif}
a{color:var(--ac)}h1,h2{font-size:1.6rem;line-height:1.2;margin:.4rem 0 1rem}h3{font-size:1.05rem;margin:1.5rem 0 .6rem}
header{position:sticky;top:0;z-index:8;display:flex;align-items:center;justify-content:space-between;height:calc(60px + env(safe-area-inset-top));padding:env(safe-area-inset-top) 16px 0;background:#0b0b10e6;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-bottom:1px solid var(--bd)}
.brand{display:flex;align-items:center;gap:10px;color:var(--fg);text-decoration:none}.brand img{width:32px;height:32px;border-radius:8px}.brand b{font-size:1.15rem}
.ib{width:40px;height:40px;border-radius:50%;background:var(--s2);border:1px solid var(--bd);display:flex;align-items:center;justify-content:center;color:var(--fg)}
.ib svg{width:20px;height:20px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round}
main{max-width:900px;margin:0 auto;padding:16px 16px 120px}
.row{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r2);padding:14px 16px;margin:0 0 12px;display:block;color:inherit;text-decoration:none}
.mu{color:var(--mu);font-size:.9rem;font-weight:400}h1 .mu{font-size:1rem}
input,select,textarea,button{font:inherit;color:var(--fg);background:var(--s2);border:1px solid var(--bd);border-radius:var(--r1);padding:0 14px;min-height:var(--ch);max-width:100%;margin:4px 0}
textarea{padding:10px 14px}input[type=file]{padding:9px 12px}button{background:var(--ac);border:0;font-weight:600;color:#fff;cursor:pointer}
button.l{background:none;color:var(--ac);padding:0;min-height:0;margin:0;font-weight:500}
.flash{background:#a855f722;border:1px solid #a855f744;padding:10px 14px;border-radius:var(--r1)}
form.i{display:inline}.g{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px}
.chips{display:flex;gap:8px;overflow-x:auto;margin-bottom:16px}.chips select,.chips a{height:40px;min-height:40px;border-radius:var(--rp);padding:0 16px;margin:0;display:flex;align-items:center;white-space:nowrap;text-decoration:none;color:var(--fg);flex:none}
.chips a.x{background:var(--ac);width:40px;padding:0;justify-content:center}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.card{position:relative;aspect-ratio:16/9;border-radius:var(--r2);overflow:hidden;display:block;color:#fff;text-decoration:none;border:1px solid var(--bd);
background:linear-gradient(135deg,hsl(var(--h) 55% 38%),hsl(calc(var(--h) + 50) 65% 16%))}
.card img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}.hero{margin-bottom:12px}
.ov{position:absolute;inset:auto 0 0;padding:32px 16px 14px;background:linear-gradient(transparent,#000d)}.ov b{display:block;font-size:1.2rem}.ov span{color:#ddd;font-size:.85rem;display:block}
.dot{position:absolute;top:12px;right:12px;background:var(--ac);border-radius:var(--rp);min-width:24px;height:24px;font:600 .75rem/24px system-ui;text-align:center;font-style:normal;padding:0 7px}
.bar{position:fixed;left:0;right:0;bottom:0;display:flex;gap:12px;justify-content:center;padding:16px 16px calc(12px + env(safe-area-inset-bottom));background:linear-gradient(transparent,#000a 60%);z-index:9}
.pill,.sb{background:#1f1f29d9;backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border:1px solid #ffffff1f;height:64px}
.pill{display:flex;flex:1;max-width:420px;padding:4px;border-radius:32px}
.pill a{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;border-radius:28px;color:#bbb;text-decoration:none;font-size:11px;font-weight:600}
.pill a.on{background:#a855f729;color:var(--ac)}.sb{width:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#ddd}.sb.on{color:var(--ac)}
.bar svg{width:22px;height:22px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.tile{position:relative;aspect-ratio:1;border-radius:var(--r1);overflow:hidden;cursor:pointer;background:var(--s2)}.tile img,.tile video{width:100%;height:100%;object-fit:cover;display:block}
.play{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:1.6rem;color:#fff;text-shadow:0 1px 6px #000}.acts{display:flex;gap:16px;margin:6px 0 8px}
.bd{position:absolute;left:8px;bottom:8px;width:24px;height:24px;border-radius:50%;background:#000a;color:#fff;font:700 .75rem system-ui;font-style:normal;display:flex;align-items:center;justify-content:center}
.bd svg{width:14px;height:14px;stroke:#fff;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
#viewer{position:fixed;inset:0;background:#000;z-index:20;display:none}#viewer.on{display:block}#vs{height:100%;overflow-y:auto;scroll-snap-type:y mandatory}
#vs section{height:100%;scroll-snap-align:start;scroll-snap-stop:always;display:flex;align-items:center;justify-content:center;position:relative}#vs img,#vs video{max-width:100%;max-height:100%}
#vs .bd{left:16px;bottom:calc(16px + env(safe-area-inset-bottom));width:30px;height:30px}#vx{position:fixed;top:calc(12px + env(safe-area-inset-top));right:16px;z-index:21;background:#000a;border-radius:50%;width:40px;height:40px;padding:0}
.venrow{display:flex;gap:12px;align-items:center;margin:12px 0}.venrow img{width:96px;aspect-ratio:16/9;object-fit:cover;border-radius:var(--r1);background:var(--s2);flex:none}"""
T = {
"base": """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover"><title>ShowProof</title><link rel=icon href="/logo.svg"><link rel=apple-touch-icon href="/apple-touch-icon.png"><meta name=apple-mobile-web-app-title content="ShowProof"><meta name=theme-color content="#0d0d12"><style>""" + CSS + """</style>
<header><a class=brand href="/"><img src="/logo.svg" alt=""><b>ShowProof</b></a>{% if g.user %}<a class=ib href="/new" aria-label="Add show"><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg></a>{% endif %}</header><main>{% for m in get_flashed_messages() %}<p class=flash>{{m}}</p>{% endfor %}{% block c %}{% endblock %}</main>
{% if g.user %}{% set e=request.endpoint %}<div class=bar><nav class=pill>
<a href="/" class="{{'on' if e in ('home','user','concert','new')}}"><svg viewBox="0 0 24 24"><path d="M3 11l9-8 9 8v10H3z"/></svg>Shows</a>
<a href="/people" class="{{'on' if e=='people'}}"><svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.5"/><path d="M2 21c0-4 3-6 7-6s7 2 7 6M16 4.5a3.5 3.5 0 010 7M18 15c2.5.6 4 2.4 4 6"/></svg>People</a>
<a href="/settings" class="{{'on' if e in ('settings','invites')}}"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.5 3.5-7 8-7s8 2.5 8 7"/></svg>Me</a></nav>
<a class="sb {{'on' if e=='search'}}" href="/search"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-5-5"/></svg></a></div>{% endif %}""",
"login": """{% extends "base" %}{% block c %}<h2>Log in</h2>{% if first %}<p>No users yet. <a href="/join">Create the admin account</a>.</p>{% endif %}
<form method=post>{{tok()}}<input name=name placeholder=Name required><br><input name=pw type=password placeholder=Password required><br><button>Log in</button></form>{% endblock %}""",
"join": """{% extends "base" %}{% block c %}<h2>{{'Create admin account' if first else 'Join ShowProof'}}</h2><form method=post>{{tok()}}<input type=hidden name=token value="{{tok_value}}">
<input name=name placeholder=Name required><br><input name=pw type=password placeholder="Password (8+ chars)" required><br><button>Create account</button></form>{% endblock %}""",
"invites": """{% extends "base" %}{% block c %}<h2>Invites</h2><form method=post>{{tok()}}<button>New invite link</button></form>
{% for r in rows %}<div class=row>{% if r.who %}<span class=mu>Used by {{r.who}}</span>{% else %}<code>{{request.host_url}}join?token={{r.token}}</code>{% endif %}</div>{% endfor %}{% endblock %}""",
"home": """{% extends "base" %}{% block c %}<h1>{{who.name}}'s shows <span class=mu>{{rows|length}}</span></h1>
<form class=chips>{% if sort!='date' or year %}<a class=x href="{{request.path}}">✕</a>{% endif %}
<select name=year onchange="this.form.submit()"><option value="">Years</option>{% for y in years %}<option {{'selected' if y==year}}>{{y}}</option>{% endfor %}</select>
<select name=sort onchange="this.form.submit()">{% for k,l in [('date','Newest'),('oldest','Oldest'),('artist','Artist'),('venue','Venue'),('city','City'),('added','Recently added')] %}<option value={{k}} {{'selected' if k==sort}}>Sort: {{l}}</option>{% endfor %}</select></form>
<div class=grid>{% for r in rows %}<a class=card href="/c/{{r.id}}" style="--h:{{r.artist|hue}}">{% if r.poster %}<img loading=lazy src="/cover/{{r.id}}?v={{r.poster[:8]}}">{% elif r.venue %}<img loading=lazy src="/venue.img?n={{r.venue|urlencode}}&c={{r.city|urlencode}}" onerror="this.remove()">{% endif %}
<div class=ov><b>{{r.artist}}</b><span>{{r.date}} · {{r.venue}}</span></div>{% if r.n %}<i class=dot>{{r.n}}</i>{% endif %}</a>{% else %}<p class=mu>Nothing yet. Set your setlist.fm username under Me, or tap + at the top.</p>{% endfor %}</div>{% endblock %}""",
"people": """{% extends "base" %}{% block c %}<h2>People</h2>{% for r in rows %}<a class=row href="/u/{{r.name}}"><b>{{r.name}}</b> <span class=mu>{{r.n}} shows</span></a>{% endfor %}{% endblock %}""",
"settings": """{% extends "base" %}{% block c %}<h2>{{u.name}}</h2><h3>setlist.fm</h3><p class=mu>Shows you attended are imported daily. Last sync: {{u.last_sync|ts}}</p>
<form method=post>{{tok()}}<input name=sfm_user value="{{u.sfm_user or ''}}" placeholder="setlist.fm username"><button>Save &amp; import</button></form>
{% if u.sfm_user %}<form method=post action="/sync">{{tok()}}<button class=l>Sync now</button></form>{% endif %}
<h3>Venue images</h3><p class=mu>Picked automatically from Wikipedia when a match exists. Replace any that are wrong or missing.</p>
{% for v in venues %}<form class=venrow method=post action="/venue/replace" enctype=multipart/form-data>{{tok()}}<img src="/venue.img?n={{v.venue|urlencode}}&c={{v.city|urlencode}}" onerror="this.style.visibility='hidden'"><div><b>{{v.venue}}</b><br><input type=hidden name=n value="{{v.venue}}"><input type=hidden name=c value="{{v.city}}"><input type=file name=file accept="image/*" required><button>Replace</button></div></form>{% endfor %}
{% if u.admin %}<p><a href="/invites">Manage invites</a></p>{% endif %}<form method=post action="/logout">{{tok()}}<button>Log out</button></form>{% endblock %}""",
"search": """{% extends "base" %}{% block c %}<h2>Search setlist.fm</h2><form><input name=artist value="{{a}}" placeholder=Artist required><input name=year value="{{y}}" placeholder="Year" size=6><button>Search</button></form>
{% for r in res %}<div class=row><b>{{r.artist}}</b> · {{r.date}}<br><span class=mu>{{r.venue}}, {{r.city}} · {{r.setlist|length}} songs</span>
<form method=post action="/add">{{tok()}}<input type=hidden name=sid value="{{r.sid}}"><button>I was there</button></form></div>{% endfor %}{% endblock %}""",
"new": """{% extends "base" %}{% block c %}<h2>Add a show</h2><form method=post>{{tok()}}<input name=artist placeholder=Artist required><br><input name=venue placeholder=Venue><br>
<input name=city placeholder=City><br><input type=date name=date required><br><textarea name=setlist rows=6 cols=36 placeholder="Setlist, one song per line"></textarea><br>
<textarea name=notes rows=3 cols=36 placeholder=Notes></textarea><br><button>Save</button></form>{% endblock %}""",
"concert": """{% extends "base" %}{% block c %}{% from "macros" import badge %}<div class="card hero" style="--h:{{c.artist|hue}}">{% if c.poster %}<img src="/cover/{{c.id}}?v={{c.poster[:8]}}">{% elif c.venue %}<img src="/venue.img?n={{c.venue|urlencode}}&c={{c.city|urlencode}}" onerror="this.remove()">{% endif %}
<div class=ov><b>{{c.artist}}</b><span>{{c.date}}</span></div></div>
<p class=mu>{{c.venue}}{% if c.city %}, {{c.city}}{% endif %}</p>
<p>Who went: <a href="/u/{{owner}}">{{owner}}</a>{% for a in att %}, <a href="/u/{{a.name}}">{{a.name}}</a>{% if mine %} <form class=i method=post action="/c/{{c.id}}/untag">{{tok()}}<input type=hidden name=uid value="{{a.id}}"><button class=l>×</button></form>{% endif %}{% endfor %}</p>
{% if mine and others %}<form method=post action="/c/{{c.id}}/tag">{{tok()}}<select name=uid>{% for o in others %}<option value="{{o.id}}">{{o.name}}</option>{% endfor %}</select><button>Tag</button></form>{% endif %}
{% if can %}<form method=post action="/c/{{c.id}}/notes">{{tok()}}<textarea name=notes rows=3 style="width:100%" placeholder=Notes>{{c.notes}}</textarea><button>Save notes</button></form>
<form method=post action="/c/{{c.id}}/poster" enctype=multipart/form-data>{{tok()}}<input type=file name=file accept="image/*" required><button>Change cover</button></form>
{% elif c.notes %}<p>{{c.notes}}</p>{% endif %}
<h3>Media</h3><div class=g>{% for m in media %}<div><div class=tile data-i="{{loop.index0}}">{% if m.kind=='image' %}<img loading=lazy src="/media/{{m.id}}">{% else %}<video preload=metadata muted playsinline src="/media/{{m.id}}#t=0.1"></video><span class=play>▶</span>{% endif %}{{badge(m)}}</div>
{% if can %}<div class=acts><form method=post action="/media/{{m.id}}/delete">{{tok()}}<button class=l>remove</button></form>{% if m.kind=='image' %}<form method=post action="/c/{{c.id}}/poster">{{tok()}}<input type=hidden name=mid value="{{m.id}}"><button class=l>set cover</button></form>{% endif %}</div>{% endif %}</div>{% endfor %}</div>
{% if can %}<form method=post action="/c/{{c.id}}/upload" enctype=multipart/form-data>{{tok()}}<input type=file name=files multiple accept="image/*,video/*" required><button>Upload</button></form>
<form method=post action="/c/{{c.id}}/link">{{tok()}}<input name=url type=url placeholder="Paste an Instagram post/reel link" size=34 required><button>Fetch</button></form>{% endif %}
{% if songs %}<h3>Setlist</h3><ol>{% for s in songs %}<li>{{s}}</li>{% endfor %}</ol>{% endif %}
{% if mine %}<form method=post action="/c/{{c.id}}/delete" onsubmit="return confirm('Delete this show and its media?')">{{tok()}}<button class=l>Delete show</button></form>{% endif %}
<div id=viewer><button id=vx>✕</button><div id=vs>{% for m in media %}<section>{% if m.kind=='image' %}<img src="/media/{{m.id}}">{% else %}<video src="/media/{{m.id}}" controls muted loop playsinline preload=none></video>{% endif %}{{badge(m)}}</section>{% endfor %}</div></div>
<script>const V=document.getElementById('viewer'),S=document.getElementById('vs');
const io=new IntersectionObserver(es=>es.forEach(e=>{const v=e.target.querySelector('video');if(v){e.isIntersecting?v.play().catch(()=>{}):v.pause()}}),{threshold:.6});
S.querySelectorAll('section').forEach(s=>io.observe(s));
document.querySelectorAll('.tile').forEach(t=>t.onclick=()=>{V.classList.add('on');document.body.style.overflow='hidden';S.children[t.dataset.i].scrollIntoView()});
function cl(){V.classList.remove('on');document.body.style.overflow='';S.querySelectorAll('video').forEach(v=>v.pause())}
document.getElementById('vx').onclick=cl;document.addEventListener('keydown',e=>{if(e.key=='Escape')cl()});</script>{% endblock %}""",
}
T["macros"] = """{% macro badge(m) %}<i class=bd>{% if m.platform %}<svg viewBox="0 0 24 24">{{ICONS[m.platform]|safe}}</svg>{% else %}{{(m.uname or '?')[:1]|upper}}{% endif %}</i>{% endmacro %}"""
app.jinja_loader = DictLoader(T)
threading.Thread(target=loop, daemon=True).start()
