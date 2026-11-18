import os, sqlite3, secrets, json, uuid, requests
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
    """)

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
    if not g.user and request.endpoint not in ("login", "join", "static"):
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
LIST = "SELECT c.*, (SELECT COUNT(*) FROM media m WHERE m.concert_id=c.id) AS n FROM concerts c WHERE user_id=? ORDER BY date DESC"

@app.route("/")
def home():
    return render_template("home", who=g.user, rows=q(LIST, g.user["id"]), mine=True, users=q("SELECT name FROM users ORDER BY name"))

@app.route("/u/<name>")
def user(name):
    u = (q("SELECT * FROM users WHERE name=?", name) or [None])[0] or abort(404)
    return render_template("home", who=u, rows=q(LIST, u["id"]), mine=u["id"] == g.user["id"], users=q("SELECT name FROM users ORDER BY name"))

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

@app.post("/import")
def imp():
    n, page = 0, 1
    try:
        while page <= 100:
            d = sfm(f"user/{request.form['username'].strip()}/attended", p=page)
            for s in d.get("setlist", []): save(g.user["id"], norm(s)); n += 1
            if page * d.get("itemsPerPage", 20) >= d.get("total", 0): break
            page += 1
        flash(f"Imported {n} shows")
    except Exception as e: flash(f"setlist.fm: {e}")
    return redirect("/")

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
    return render_template("concert", c=c, songs=json.loads(c["setlist"]), media=q("SELECT * FROM media WHERE concert_id=?", cid),
                           mine=c["user_id"] == g.user["id"], owner=q("SELECT name FROM users WHERE id=?", c["user_id"])[0]["name"])

@app.post("/c/<int:cid>/notes")
def notes(cid):
    if owned(cid)["user_id"] != g.user["id"]: abort(403)
    run("UPDATE concerts SET notes=? WHERE id=?", request.form["notes"], cid); return redirect(f"/c/{cid}")

@app.post("/c/<int:cid>/upload")
def upload(cid):
    if owned(cid)["user_id"] != g.user["id"]: abort(403)
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
    if owned(cid)["user_id"] != g.user["id"]: abort(403)
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
        run("DELETE FROM media WHERE id=?", m["id"])

@app.post("/media/<int:mid>/delete")
def del_media(mid):
    m = (q("SELECT m.*, c.user_id FROM media m JOIN concerts c ON c.id=m.concert_id WHERE m.id=?", mid) or [None])[0] or abort(404)
    if m["user_id"] != g.user["id"]: abort(403)
    rm_media([m]); return redirect(f"/c/{m['concert_id']}")

@app.post("/c/<int:cid>/delete")
def del_concert(cid):
    if owned(cid)["user_id"] != g.user["id"]: abort(403)
    rm_media(q("SELECT * FROM media WHERE concert_id=?", cid)); run("DELETE FROM concerts WHERE id=?", cid); return redirect("/")

# ---------- templates ----------
CSS = """:root{color-scheme:dark light;--bg:#14141a;--fg:#eee;--mu:#9a9aa8;--ac:#ff6b6b;--cd:#1f1f28}
@media(prefers-color-scheme:light){:root{--bg:#f6f6f8;--fg:#18181c;--mu:#666;--cd:#fff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px system-ui,sans-serif}
a{color:var(--ac)}nav{display:flex;gap:1rem;align-items:center;padding:.8rem 1rem;background:var(--cd);flex-wrap:wrap}
nav b{margin-right:auto}main{max-width:860px;margin:auto;padding:1rem}
.card{background:var(--cd);border-radius:10px;padding:.8rem 1rem;margin:.6rem 0;display:block;color:inherit;text-decoration:none}
.mu{color:var(--mu);font-size:.9rem}input,textarea,button{font:inherit;padding:.5rem;border-radius:6px;border:1px solid #8884;background:var(--cd);color:var(--fg);margin:.2rem 0;max-width:100%}
button{background:var(--ac);color:#fff;border:0;cursor:pointer}button.l{background:none;color:var(--ac);padding:0}
.g{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:.5rem}.g img,.g video{width:100%;border-radius:8px}
.flash{background:#ff6b6b33;padding:.5rem;border-radius:6px}form.i{display:inline}"""
T = {
"base": """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>Concert Tracker</title><style>""" + CSS + """</style>
<nav><b><a href="/">🎸 Concert Tracker</a></b>{% if g.user %}<a href="/search">Search</a><a href="/new">Add</a>
{% if g.user.admin %}<a href="/invites">Invites</a>{% endif %}<form class=i method=post action="/logout">{{tok()}}<button class=l>Log out ({{g.user.name}})</button></form>{% endif %}</nav>
<main>{% for m in get_flashed_messages() %}<p class=flash>{{m}}</p>{% endfor %}{% block c %}{% endblock %}</main>""",
"login": """{% extends "base" %}{% block c %}<h2>Log in</h2>{% if first %}<p>No users yet — <a href="/join">create the admin account</a>.</p>{% endif %}
<form method=post>{{tok()}}<input name=name placeholder=Name required><br><input name=pw type=password placeholder=Password required><br><button>Log in</button></form>{% endblock %}""",
"join": """{% extends "base" %}{% block c %}<h2>{{'Create admin account' if first else 'Join'}}</h2>
<form method=post>{{tok()}}<input type=hidden name=token value="{{tok_ if false else ''}}"><input name=name placeholder=Name required><br>
<input name=pw type=password placeholder="Password (8+ chars)" required><br><button>Create account</button></form>{% endblock %}""",
"invites": """{% extends "base" %}{% block c %}<h2>Invites</h2><form method=post>{{tok()}}<button>New invite link</button></form>
{% for r in rows %}<div class=card>{% if r.who %}<span class=mu>Used by {{r.who}}</span>{% else %}<code>{{request.host_url}}join?token={{r.token}}</code>{% endif %}</div>{% endfor %}{% endblock %}""",
"home": """{% extends "base" %}{% block c %}<h2>{{who.name}}'s concerts <span class=mu>({{rows|length}})</span></h2>
{% for r in rows %}<a class=card href="/c/{{r.id}}"><b>{{r.artist}}</b><br><span class=mu>{{r.date}} · {{r.venue}}{% if r.city %}, {{r.city}}{% endif %}{% if r.n %} · 📷 {{r.n}}{% endif %}</span></a>{% else %}<p class=mu>Nothing yet.</p>{% endfor %}
{% if mine %}<h3>Import from setlist.fm</h3><form method=post action="/import">{{tok()}}<input name=username placeholder="setlist.fm username" required><button>Import attended</button></form>{% endif %}
<p class=mu>Members: {% for u in users %}<a href="/u/{{u.name}}">{{u.name}}</a> {% endfor %}</p>{% endblock %}""",
"search": """{% extends "base" %}{% block c %}<h2>Search setlist.fm</h2><form><input name=artist value="{{a}}" placeholder=Artist required><input name=year value="{{y}}" placeholder="Year (optional)" size=8><button>Search</button></form>
{% for r in res %}<div class=card><b>{{r.artist}}</b> — {{r.date}}<br><span class=mu>{{r.venue}}, {{r.city}} · {{r.setlist|length}} songs</span>
<form method=post action="/add">{{tok()}}<input type=hidden name=sid value="{{r.sid}}"><button>I was there</button></form></div>{% endfor %}{% endblock %}""",
"new": """{% extends "base" %}{% block c %}<h2>Add a concert</h2><form method=post>{{tok()}}<input name=artist placeholder=Artist required><br><input name=venue placeholder=Venue><br>
<input name=city placeholder=City><br><input type=date name=date required><br><textarea name=setlist rows=6 cols=40 placeholder="Setlist, one song per line"></textarea><br>
<textarea name=notes rows=3 cols=40 placeholder=Notes></textarea><br><button>Save</button></form>{% endblock %}""",
"concert": """{% extends "base" %}{% block c %}<h2>{{c.artist}}</h2><p class=mu>{{c.date}} · {{c.venue}}{% if c.city %}, {{c.city}}{% endif %} · <a href="/u/{{owner}}">{{owner}}</a></p>
{% if mine %}<form method=post action="/c/{{c.id}}/notes">{{tok()}}<textarea name=notes rows=3 style="width:100%" placeholder=Notes>{{c.notes}}</textarea><button>Save notes</button></form>
{% elif c.notes %}<p>{{c.notes}}</p>{% endif %}
<h3>Media</h3><div class=g>{% for m in media %}<div>{% if m.kind=='image' %}<a href="/media/{{m.id}}"><img loading=lazy src="/media/{{m.id}}"></a>{% else %}<video controls preload=metadata src="/media/{{m.id}}"></video>{% endif %}
{% if mine %}<form method=post action="/media/{{m.id}}/delete">{{tok()}}<button class=l>remove</button></form>{% endif %}</div>{% endfor %}</div>
{% if mine %}<form method=post action="/c/{{c.id}}/upload" enctype=multipart/form-data>{{tok()}}<input type=file name=files multiple accept="image/*,video/*" required><button>Upload</button></form>
<form method=post action="/c/{{c.id}}/link">{{tok()}}<input name=url type=url placeholder="Paste an Instagram post/reel link" size=36 required><button>Fetch</button></form>{% endif %}
{% if songs %}<h3>Setlist</h3><ol>{% for s in songs %}<li>{{s}}</li>{% endfor %}</ol>{% endif %}
{% if mine %}<form method=post action="/c/{{c.id}}/delete" onsubmit="return confirm('Delete this concert and its media?')">{{tok()}}<button class=l>Delete concert</button></form>{% endif %}{% endblock %}""",
}
T["join"] = T["join"].replace("""{{tok_ if false else ''}}""", """{{ tok_value }}""")
app.jinja_loader = DictLoader(T)
