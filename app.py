import os, sqlite3, secrets, json, uuid, requests, time, threading
from datetime import datetime
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
app.config.update(MAX_CONTENT_LENGTH=4 * 1024**3, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_HTTPONLY=True)

def conn():
    c = sqlite3.connect(os.path.join(DATA, "app.db")); c.row_factory = sqlite3.Row; return c
with conn() as c:
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT UNIQUE, pw TEXT, admin INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS invites(token TEXT PRIMARY KEY, used_by INT);
    CREATE TABLE IF NOT EXISTS concerts(id INTEGER PRIMARY KEY, user_id INT, artist TEXT, venue TEXT, city TEXT,
      date TEXT, notes TEXT DEFAULT '', setlist TEXT DEFAULT '[]', sid TEXT, UNIQUE(user_id, sid));
    CREATE TABLE IF NOT EXISTS media(id INTEGER PRIMARY KEY, concert_id INT, file TEXT, kind TEXT);
    CREATE TABLE IF NOT EXISTS attendees(concert_id INT, user_id INT, PRIMARY KEY(concert_id, user_id));
    """)
    for stmt in ("ALTER TABLE users ADD COLUMN sfm_user TEXT DEFAULT ''", "ALTER TABLE users ADD COLUMN last_sync REAL DEFAULT 0",
                 "ALTER TABLE concerts ADD COLUMN poster TEXT"):
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
    if not g.user and request.endpoint not in ("login", "join", "static", "logo"):
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
            session.clear(); session["uid"] = u["id"]; return redirect("/")
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
            session.clear(); session["uid"] = uid; return redirect("/")
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
    return render_template("settings", u=q("SELECT * FROM users WHERE id=?", g.user["id"])[0])

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
    return render_template("concert", c=c, songs=json.loads(c["setlist"]), media=q("SELECT * FROM media WHERE concert_id=?", cid),
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
        run("INSERT INTO media(concert_id,file,kind) VALUES(?,?,?)", cid, name, kind)
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
                run("INSERT INTO media(concert_id,file,kind) VALUES(?,?,?)", cid, name, kind)
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
            run("INSERT INTO media(concert_id,file,kind) VALUES(?,?,?)", cid, name, "image")
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

app.jinja_env.filters["hue"] = lambda s: sum(map(ord, s or "x")) % 360
app.jinja_env.filters["ts"] = lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M") if t else "never"

# ---------- templates ----------
CSS = """:root{color-scheme:dark;--bg:#0d0d12;--fg:#f2f2f5;--mu:#9a9aa8;--ac:#a855f7;--cd:#1b1b24}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px system-ui,sans-serif}
a{color:var(--ac)}header{display:flex;gap:.6rem;align-items:center;justify-content:center;padding:calc(.8rem + env(safe-area-inset-top)) 1rem .8rem;border-bottom:1px solid #fff1}
header img{width:30px;height:30px}header b{font-size:1.3rem}main{max-width:900px;margin:auto;padding:1rem 1rem 8rem}
h2{margin:.4rem 0 .8rem}.row{background:var(--cd);border-radius:10px;padding:.8rem 1rem;margin:.6rem 0;display:block;color:inherit;text-decoration:none}
.mu{color:var(--mu);font-size:.9rem}input,select,textarea,button{font:inherit;padding:.5rem .7rem;border-radius:8px;border:1px solid #fff2;background:var(--cd);color:var(--fg);margin:.2rem 0;max-width:100%}
button{background:var(--ac);color:#fff;border:0;cursor:pointer}button.l{background:none;color:var(--ac);padding:0}.flash{background:#a855f733;padding:.5rem .8rem;border-radius:8px}
form.i{display:inline}.g{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:.5rem}.g img,.g video{width:100%;border-radius:8px}
.chips{display:flex;gap:.5rem;overflow-x:auto;margin-bottom:.8rem}.chips select,.chips a{border-radius:99px;padding:.55rem 1rem;background:var(--cd);color:var(--fg);text-decoration:none;white-space:nowrap}
.chips a.x{background:var(--ac)}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:.8rem}
.card{position:relative;aspect-ratio:16/9;border-radius:16px;overflow:hidden;display:block;color:#fff;text-decoration:none;
background:linear-gradient(135deg,hsl(var(--h) 55% 38%),hsl(calc(var(--h) + 50) 65% 16%))}
.card img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}.hero{margin-bottom:.8rem}
.ov{position:absolute;inset:auto 0 0;padding:2rem .9rem .7rem;background:linear-gradient(transparent,#000d)}.ov b{display:block;font-size:1.2rem}.ov span{color:#ddd;font-size:.85rem;display:block}
.dot{position:absolute;top:10px;right:10px;background:var(--ac);border-radius:99px;min-width:24px;height:24px;font:600 .75rem/24px system-ui;text-align:center;font-style:normal;padding:0 6px}
.bar{position:fixed;left:0;right:0;bottom:0;display:flex;gap:.6rem;justify-content:center;padding:1.2rem .8rem calc(.7rem + env(safe-area-inset-bottom));background:linear-gradient(transparent,#000 70%);z-index:9}
.pill,.sb{background:#26262fcc;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid #fff2;border-radius:99px}
.pill{display:flex;flex:1;max-width:420px;padding:.3rem}.pill a{flex:1;text-align:center;padding:.5rem 0;border-radius:99px;color:#ccc;text-decoration:none;font-size:.75rem;font-weight:600}
.pill a.on{background:#a855f733;color:var(--ac)}.sb{width:62px;display:flex;align-items:center;justify-content:center;color:#ddd}.sb.on{color:var(--ac)}
.bar svg{width:24px;height:24px;display:block;margin:0 auto 2px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}"""
T = {
"base": """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover"><title>ShowProof</title><link rel=icon href="/logo.svg"><meta name=theme-color content="#0d0d12"><style>""" + CSS + """</style>
<header><img src="/logo.svg" alt=""><b>ShowProof</b></header><main>{% for m in get_flashed_messages() %}<p class=flash>{{m}}</p>{% endfor %}{% block c %}{% endblock %}</main>
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
"home": """{% extends "base" %}{% block c %}<h2>{{who.name}}'s shows <span class=mu>({{rows|length}})</span>{% if mine %} <a href="/new">＋</a>{% endif %}</h2>
<form class=chips>{% if sort!='date' or year %}<a class=x href="{{request.path}}">✕</a>{% endif %}
<select name=year onchange="this.form.submit()"><option value="">Years</option>{% for y in years %}<option {{'selected' if y==year}}>{{y}}</option>{% endfor %}</select>
<select name=sort onchange="this.form.submit()">{% for k,l in [('date','Newest'),('oldest','Oldest'),('artist','Artist'),('venue','Venue'),('city','City'),('added','Recently added')] %}<option value={{k}} {{'selected' if k==sort}}>Sort: {{l}}</option>{% endfor %}</select></form>
<div class=grid>{% for r in rows %}<a class=card href="/c/{{r.id}}" style="--h:{{r.artist|hue}}">{% if r.poster %}<img loading=lazy src="/cover/{{r.id}}?v={{r.poster[:8]}}">{% endif %}
<div class=ov><b>{{r.artist}}</b><span>{{r.date}} · {{r.venue}}</span></div>{% if r.n %}<i class=dot>{{r.n}}</i>{% endif %}</a>{% else %}<p class=mu>Nothing yet. Set your setlist.fm username under Me, or tap ＋.</p>{% endfor %}</div>{% endblock %}""",
"people": """{% extends "base" %}{% block c %}<h2>People</h2>{% for r in rows %}<a class=row href="/u/{{r.name}}"><b>{{r.name}}</b> <span class=mu>{{r.n}} shows</span></a>{% endfor %}{% endblock %}""",
"settings": """{% extends "base" %}{% block c %}<h2>{{u.name}}</h2><h3>setlist.fm</h3><p class=mu>Shows you attended are imported daily. Last sync: {{u.last_sync|ts}}</p>
<form method=post>{{tok()}}<input name=sfm_user value="{{u.sfm_user or ''}}" placeholder="setlist.fm username"><button>Save &amp; import</button></form>
{% if u.sfm_user %}<form method=post action="/sync">{{tok()}}<button class=l>Sync now</button></form>{% endif %}
{% if u.admin %}<p><a href="/invites">Manage invites</a></p>{% endif %}<form method=post action="/logout">{{tok()}}<button>Log out</button></form>{% endblock %}""",
"search": """{% extends "base" %}{% block c %}<h2>Search setlist.fm</h2><form><input name=artist value="{{a}}" placeholder=Artist required><input name=year value="{{y}}" placeholder="Year" size=6><button>Search</button></form>
{% for r in res %}<div class=row><b>{{r.artist}}</b> · {{r.date}}<br><span class=mu>{{r.venue}}, {{r.city}} · {{r.setlist|length}} songs</span>
<form method=post action="/add">{{tok()}}<input type=hidden name=sid value="{{r.sid}}"><button>I was there</button></form></div>{% endfor %}{% endblock %}""",
"new": """{% extends "base" %}{% block c %}<h2>Add a show</h2><form method=post>{{tok()}}<input name=artist placeholder=Artist required><br><input name=venue placeholder=Venue><br>
<input name=city placeholder=City><br><input type=date name=date required><br><textarea name=setlist rows=6 cols=36 placeholder="Setlist, one song per line"></textarea><br>
<textarea name=notes rows=3 cols=36 placeholder=Notes></textarea><br><button>Save</button></form>{% endblock %}""",
"concert": """{% extends "base" %}{% block c %}<div class="card hero" style="--h:{{c.artist|hue}}">{% if c.poster %}<img src="/cover/{{c.id}}?v={{c.poster[:8]}}">{% endif %}
<div class=ov><b>{{c.artist}}</b><span>{{c.date}}</span></div></div>
<p class=mu>{{c.venue}}{% if c.city %}, {{c.city}}{% endif %}</p>
<p>Who went: <a href="/u/{{owner}}">{{owner}}</a>{% for a in att %}, <a href="/u/{{a.name}}">{{a.name}}</a>{% if mine %} <form class=i method=post action="/c/{{c.id}}/untag">{{tok()}}<input type=hidden name=uid value="{{a.id}}"><button class=l>×</button></form>{% endif %}{% endfor %}</p>
{% if mine and others %}<form method=post action="/c/{{c.id}}/tag">{{tok()}}<select name=uid>{% for o in others %}<option value="{{o.id}}">{{o.name}}</option>{% endfor %}</select><button>Tag</button></form>{% endif %}
{% if can %}<form method=post action="/c/{{c.id}}/notes">{{tok()}}<textarea name=notes rows=3 style="width:100%" placeholder=Notes>{{c.notes}}</textarea><button>Save notes</button></form>
<form method=post action="/c/{{c.id}}/poster" enctype=multipart/form-data>{{tok()}}<input type=file name=file accept="image/*" required><button>Change cover</button></form>
{% elif c.notes %}<p>{{c.notes}}</p>{% endif %}
<h3>Media</h3><div class=g>{% for m in media %}<div>{% if m.kind=='image' %}<a href="/media/{{m.id}}"><img loading=lazy src="/media/{{m.id}}"></a>{% else %}<video controls preload=metadata src="/media/{{m.id}}"></video>{% endif %}
{% if can %}<form class=i method=post action="/media/{{m.id}}/delete">{{tok()}}<button class=l>remove</button></form>{% if m.kind=='image' %}<form class=i method=post action="/c/{{c.id}}/poster">{{tok()}}<input type=hidden name=mid value="{{m.id}}"><button class=l>make cover</button></form>{% endif %}{% endif %}</div>{% endfor %}</div>
{% if can %}<form method=post action="/c/{{c.id}}/upload" enctype=multipart/form-data>{{tok()}}<input type=file name=files multiple accept="image/*,video/*" required><button>Upload</button></form>
<form method=post action="/c/{{c.id}}/link">{{tok()}}<input name=url type=url placeholder="Paste an Instagram post/reel link" size=34 required><button>Fetch</button></form>{% endif %}
{% if songs %}<h3>Setlist</h3><ol>{% for s in songs %}<li>{{s}}</li>{% endfor %}</ol>{% endif %}
{% if mine %}<form method=post action="/c/{{c.id}}/delete" onsubmit="return confirm('Delete this show and its media?')">{{tok()}}<button class=l>Delete show</button></form>{% endif %}{% endblock %}""",
}
app.jinja_loader = DictLoader(T)
threading.Thread(target=loop, daemon=True).start()
