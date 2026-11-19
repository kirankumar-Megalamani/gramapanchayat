"""
Gram Panchayat Digital Complaint Portal
Single-file Flask + SQLite application.
Run:  pip install flask   (once)   then   python app.py
Open: http://127.0.0.1:5000
Admin login (auto-created): admin@panchayat.gov / Admin@123
"""
import os, re, secrets, sqlite3
from datetime import datetime
from functools import wraps
from flask import (Flask, g, request, session, redirect, url_for, flash,
                   render_template_string, abort)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-for-production")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "panchayat.db")

CATEGORIES = [
    ("Road Damage and Potholes", "🛣️", "Broken roads, potholes and damaged village paths."),
    ("Drinking Water Problems", "🚰", "No supply, dirty water or damaged handpumps."),
    ("Water Leakage", "💧", "Leaking pipelines, taps and overflowing tanks."),
    ("Streetlight Problems", "💡", "Streetlights that are off, broken or flickering."),
    ("Garbage Collection", "🗑️", "Uncollected waste and illegal dumping."),
    ("Drainage and Sanitation", "🚿", "Blocked drains, sewage overflow and toilet issues."),
    ("Public Infrastructure", "🏛️", "Community halls, schools, bus stops and public buildings."),
    ("Other Village Problems", "📌", "Anything else affecting your village."),
]
STATUSES = ["Pending", "In Progress", "Resolved", "Rejected"]
PRIORITIES = ["Low", "Medium", "High"]

# ----------------------------------------------------------------- database
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, mobile TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
        village TEXT NOT NULL, password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'citizen', created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS complaints(
        id INTEGER PRIMARY KEY AUTOINCREMENT, cid TEXT UNIQUE,
        user_id INTEGER NOT NULL, category TEXT NOT NULL, title TEXT NOT NULL,
        description TEXT NOT NULL, location TEXT NOT NULL,
        priority TEXT NOT NULL DEFAULT 'Medium', status TEXT NOT NULL DEFAULT 'Pending',
        remarks TEXT DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id));
    """)
    if not con.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        con.execute("INSERT INTO users(name,mobile,email,village,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
                    ("Panchayat Officer", "9000000000", "admin@panchayat.gov", "Gram Panchayat Office",
                     generate_password_hash("Admin@123"), "admin", now()))
    con.commit(); con.close()

def now():
    return datetime.now().strftime("%d %b %Y, %I:%M %p")

# ----------------------------------------------------------------- helpers
def login_required(role=None):
    def deco(f):
        @wraps(f)
        def wrap(*a, **k):
            if "uid" not in session:
                flash("Please log in to continue.", "error")
                return redirect(url_for("login", next=request.path))
            if role and session.get("role") != role:
                abort(403)
            return f(*a, **k)
        return wrap
    return deco

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]

@app.before_request
def check_csrf():
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
            flash("Your session expired. Please try again.", "error")
            return redirect(request.referrer or url_for("home"))

def stats(user_id=None):
    where, args = ("WHERE user_id=?", (user_id,)) if user_id else ("", ())
    q = lambda extra="": db().execute(
        f"SELECT COUNT(*) FROM complaints {where} {('AND' if where else 'WHERE') + ' ' + extra if extra else ''}",
        args).fetchone()[0]
    return dict(total=q(), pending=q("status='Pending'"), progress=q("status='In Progress'"),
                resolved=q("status='Resolved'"))

def page(body_tpl, title="", **ctx):
    body = render_template_string(body_tpl, **ctx)
    return render_template_string(BASE, body=body, title=title)

@app.context_processor
def inject():
    return dict(csrf=csrf_token, categories=CATEGORIES, statuses=STATUSES, priorities=PRIORITIES)

# ------------------------------------------------------------------- routes
@app.route("/")
def home():
    s = stats()
    villages = db().execute("SELECT COUNT(DISTINCT village) FROM users WHERE role='citizen'").fetchone()[0]
    rate = round(s["resolved"] * 100 / s["total"]) if s["total"] else 0
    return page(HOME, "Home", s=s, villages=villages, rate=rate)

@app.route("/about")
def about():
    return page(ABOUT, "About")

@app.route("/services")
def services():
    return page(SERVICES, "Services")

@app.route("/register", methods=["GET", "POST"])
def register():
    f = request.form
    if request.method == "POST":
        name, mobile, email = f.get("name", "").strip(), f.get("mobile", "").strip(), f.get("email", "").strip().lower()
        village, pw, pw2 = f.get("village", "").strip(), f.get("password", ""), f.get("confirm", "")
        errs = []
        if len(name) < 3 or not re.fullmatch(r"[A-Za-z .'-]+", name): errs.append("Enter your full name using letters only.")
        if not re.fullmatch(r"[6-9]\d{9}", mobile): errs.append("Enter a valid 10-digit mobile number starting with 6, 7, 8 or 9.")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email): errs.append("Enter a valid email address.")
        if len(village) < 2: errs.append("Enter your village name.")
        if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
            errs.append("Password must be at least 8 characters with a letter and a number.")
        if pw != pw2: errs.append("Passwords do not match.")
        if not errs and db().execute("SELECT 1 FROM users WHERE email=? OR mobile=?", (email, mobile)).fetchone():
            errs.append("An account with this email or mobile number already exists.")
        if errs:
            for e in errs: flash(e, "error")
        else:
            db().execute("INSERT INTO users(name,mobile,email,village,password_hash,created_at) VALUES(?,?,?,?,?,?)",
                         (name, mobile, email, village, generate_password_hash(pw), now()))
            db().commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
    return page(REGISTER, "Register", f=f)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ident, pw = request.form.get("identity", "").strip().lower(), request.form.get("password", "")
        u = db().execute("SELECT * FROM users WHERE email=? OR mobile=?", (ident, ident)).fetchone()
        if u and check_password_hash(u["password_hash"], pw):
            session.clear()
            session.update(uid=u["id"], name=u["name"], role=u["role"])
            flash(f"Welcome, {u['name']}.", "success")
            nxt = request.args.get("next", "")
            if nxt.startswith("/") and not nxt.startswith("//"):
                return redirect(nxt)
            return redirect(url_for("admin" if u["role"] == "admin" else "dashboard"))
        flash("Incorrect email/mobile or password.", "error")
    return page(LOGIN, "Login")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))

@app.route("/submit", methods=["GET", "POST"])
@login_required()
def submit():
    f = request.form
    if request.method == "POST":
        cat, title, desc = f.get("category", ""), f.get("title", "").strip(), f.get("description", "").strip()
        loc, pr = f.get("location", "").strip(), f.get("priority", "Medium")
        errs = []
        if cat not in [c[0] for c in CATEGORIES]: errs.append("Choose a complaint category.")
        if len(title) < 5: errs.append("Give the complaint a title of at least 5 characters.")
        if len(desc) < 20: errs.append("Describe the problem in at least 20 characters.")
        if len(loc) < 3: errs.append("Tell us where the problem is.")
        if pr not in PRIORITIES: pr = "Medium"
        if errs:
            for e in errs: flash(e, "error")
        else:
            c = db().execute("""INSERT INTO complaints(user_id,category,title,description,location,priority,created_at,updated_at)
                                VALUES(?,?,?,?,?,?,?,?)""", (session["uid"], cat, title, desc, loc, pr, now(), now()))
            cid = f"GP{datetime.now().year}{c.lastrowid:05d}"
            db().execute("UPDATE complaints SET cid=? WHERE id=?", (cid, c.lastrowid))
            db().commit()
            flash(f"Complaint submitted. Your complaint ID is {cid}. Save it to track progress.", "success")
            return redirect(url_for("track", cid=cid))
    return page(SUBMIT, "Submit Complaint", f=f or request.args)

@app.route("/track", methods=["GET", "POST"])
def track():
    cid = (request.values.get("cid") or "").strip().upper()
    c = None
    if cid:
        c = db().execute("""SELECT c.*, u.name AS uname, u.village FROM complaints c
                            JOIN users u ON u.id=c.user_id WHERE c.cid=?""", (cid,)).fetchone()
        if not c: flash("No complaint found with that ID. Check the ID and try again.", "error")
    return page(TRACK, "Track Complaint", c=c, cid=cid)

@app.route("/dashboard")
@login_required()
def dashboard():
    if session["role"] == "admin": return redirect(url_for("admin"))
    rows = db().execute("SELECT * FROM complaints WHERE user_id=? ORDER BY id DESC", (session["uid"],)).fetchall()
    return page(DASH, "My Dashboard", s=stats(session["uid"]), rows=rows)

@app.route("/admin")
@login_required("admin")
def admin():
    st, cat, q = request.args.get("status", ""), request.args.get("category", ""), request.args.get("q", "").strip()
    sql, args = "SELECT c.*, u.name AS uname, u.village, u.mobile FROM complaints c JOIN users u ON u.id=c.user_id WHERE 1=1", []
    if st in STATUSES: sql += " AND c.status=?"; args.append(st)
    if cat: sql += " AND c.category=?"; args.append(cat)
    if q: sql += " AND (c.cid LIKE ? OR c.title LIKE ? OR u.name LIKE ?)"; args += [f"%{q}%"] * 3
    rows = db().execute(sql + " ORDER BY c.id DESC", args).fetchall()
    bycat = db().execute("SELECT category, COUNT(*) n FROM complaints GROUP BY category ORDER BY n DESC").fetchall()
    users = db().execute("SELECT COUNT(*) FROM users WHERE role='citizen'").fetchone()[0]
    return page(ADMIN, "Admin Panel", s=stats(), rows=rows, bycat=bycat, users=users, st=st, cat=cat, q=q)

@app.route("/admin/update/<int:cid>", methods=["POST"])
@login_required("admin")
def update(cid):
    status, remarks = request.form.get("status"), request.form.get("remarks", "").strip()[:500]
    if status not in STATUSES: abort(400)
    db().execute("UPDATE complaints SET status=?, remarks=?, updated_at=? WHERE id=?", (status, remarks, now(), cid))
    db().commit()
    flash("Complaint updated.", "success")
    return redirect(request.referrer or url_for("admin"))

@app.errorhandler(403)
def e403(_): return page(ERR, "Access denied", code=403, msg="You do not have permission to open this page."), 403

@app.errorhandler(404)
def e404(_): return page(ERR, "Not found", code=404, msg="This page does not exist."), 404

# --------------------------------------------------------------- templates
BASE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title + ' | ' if title }}Gram Panchayat Digital Complaint Portal</title>
<style>
:root{--green:#1f8a4c;--green-d:#166a3a;--green-l:#e6f4ea;--navy:#0b2a4a;--navy-2:#143d6b;--ink:#1d2b3a;--mute:#5b6b7b;--line:#dbe4ea;--bg:#f5f8f7;--white:#fff;--red:#c0392b;--amber:#d98e04}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:"Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;background:var(--bg);color:var(--ink);line-height:1.6}
a{color:inherit;text-decoration:none}
:focus-visible{outline:3px solid #f2b705;outline-offset:2px}
.wrap{max-width:1140px;margin:0 auto;padding:0 20px}
/* header */
.topbar{background:var(--navy);color:#cfe0ee;font-size:.82rem;padding:6px 0}
.topbar .wrap{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
header.nav{background:var(--white);border-bottom:3px solid var(--green);position:sticky;top:0;z-index:50;box-shadow:0 2px 10px rgba(11,42,74,.08)}
header.nav .wrap{display:flex;align-items:center;justify-content:space-between;min-height:70px;gap:14px}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:46px;height:46px;border-radius:50%;background:var(--green);color:#fff;display:grid;place-items:center;font-size:1.5rem;border:3px solid var(--navy);flex:none}
.brand b{display:block;color:var(--navy);font-size:1.02rem;line-height:1.2}
.brand small{color:var(--mute);font-size:.75rem}
nav ul{display:flex;list-style:none;gap:2px;align-items:center}
nav a{display:block;padding:9px 13px;border-radius:6px;font-weight:600;font-size:.84rem;letter-spacing:.3px;color:var(--navy);transition:.2s}
nav a:hover,nav a.on{background:var(--green-l);color:var(--green-d)}
nav a.cta{background:var(--green);color:#fff}
nav a.cta:hover{background:var(--green-d);color:#fff}
.burger{display:none;background:none;border:2px solid var(--navy);color:var(--navy);border-radius:6px;font-size:1.3rem;padding:2px 10px;cursor:pointer}
@media(max-width:960px){.burger{display:block}nav{display:none;position:absolute;left:0;right:0;top:100%;background:#fff;border-bottom:3px solid var(--green);padding:10px 20px}nav.open{display:block}nav ul{flex-direction:column;align-items:stretch}}
/* buttons */
.btn{display:inline-block;border:0;cursor:pointer;font:inherit;font-weight:700;padding:12px 26px;border-radius:8px;transition:transform .2s,box-shadow .2s,background .2s}
.btn:hover{transform:translateY(-2px);box-shadow:0 8px 18px rgba(0,0,0,.18)}
.btn-g{background:var(--green);color:#fff}.btn-g:hover{background:var(--green-d)}
.btn-w{background:#fff;color:var(--navy)}
.btn-o{border:2px solid #fff;color:#fff;background:transparent}
.btn-n{background:var(--navy);color:#fff}
.btn-sm{padding:6px 14px;font-size:.85rem}
/* hero */
.hero{background:linear-gradient(105deg,rgba(11,42,74,.96) 0%,rgba(11,42,74,.86) 48%,rgba(31,138,76,.72) 100%),
 radial-gradient(circle at 80% 20%,#2fb36a 0,transparent 45%),#0b2a4a;color:#fff;position:relative;overflow:hidden;padding:84px 0 110px}
.hero:before{content:"";position:absolute;inset:auto 0 0 0;height:90px;background:
 linear-gradient(#0000,#0000),url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1200 90' preserveAspectRatio='none'%3E%3Cpath d='M0 90V55q150-45 300-10t300 5 300-25 300 15V90z' fill='%23f5f8f7'/%3E%3C/svg%3E") bottom/100% 100% no-repeat}
.hero .wrap{position:relative;display:grid;grid-template-columns:1.25fr 1fr;gap:40px;align-items:center}
.hero h1{font-size:clamp(2rem,4.6vw,3.4rem);line-height:1.12;margin-bottom:18px;animation:rise .9s ease both}
.hero p{max-width:560px;color:#d6e6f2;font-size:1.08rem;margin-bottom:28px}
.hero .btns{display:flex;gap:14px;flex-wrap:wrap}
.hero-card{background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.25);border-radius:16px;padding:26px;backdrop-filter:blur(6px)}
.hero-card h3{margin-bottom:12px}
.hero-card li{list-style:none;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.15);display:flex;gap:10px}
.hero-card li:last-child{border:0}
@keyframes rise{from{opacity:0;transform:translateY(22px)}to{opacity:1;transform:none}}
@media(max-width:860px){.hero .wrap{grid-template-columns:1fr}.hero{padding:56px 0 90px}}
/* sections */
section{padding:64px 0}
.sh{text-align:center;max-width:640px;margin:0 auto 38px}
.sh h2{font-size:clamp(1.6rem,3vw,2.1rem);color:var(--navy)}
.sh p{color:var(--mute)}
.sh:after{content:"";display:block;width:64px;height:4px;background:var(--green);border-radius:4px;margin:14px auto 0}
.grid{display:grid;gap:22px}
.g4{grid-template-columns:repeat(auto-fit,minmax(230px,1fr))}
.g3{grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}
.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:26px;transition:transform .25s,box-shadow .25s,border-color .25s}
.card:hover{transform:translateY(-5px);box-shadow:0 14px 30px rgba(11,42,74,.12);border-color:var(--green)}
.ico{width:56px;height:56px;border-radius:14px;background:var(--green-l);display:grid;place-items:center;font-size:1.7rem;margin-bottom:14px}
.card h3{color:var(--navy);font-size:1.06rem;margin-bottom:6px}
.card p{color:var(--mute);font-size:.93rem}
.stats{margin-top:-60px;position:relative;z-index:5;padding:0}
.stat{text-align:center;border-top:4px solid var(--green)}
.stat b{display:block;font-size:2.3rem;color:var(--navy);line-height:1.1}
.stat span{color:var(--mute);font-weight:600;font-size:.92rem}
.steps .card{text-align:center}
.steps .n{width:44px;height:44px;margin:0 auto 12px;border-radius:50%;background:var(--navy);color:#fff;display:grid;place-items:center;font-weight:800}
.band{background:var(--navy);color:#fff}
.band .sh h2{color:#fff}.band .sh p{color:#b8cde0}
.contact .card{background:rgba(255,255,255,.07);border-color:rgba(255,255,255,.2)}
.contact .card h3{color:#fff}.contact .card p{color:#c4d6e6}
/* forms */
.formbox{max-width:620px;margin:44px auto;background:#fff;border:1px solid var(--line);border-radius:16px;padding:34px;box-shadow:0 10px 30px rgba(11,42,74,.08)}
.formbox.wide{max-width:780px}
.formbox h1{color:var(--navy);font-size:1.7rem}
.formbox .sub{color:var(--mute);margin-bottom:22px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:600px){.row{grid-template-columns:1fr}.formbox{padding:22px}}
label{display:block;font-weight:600;font-size:.9rem;margin:14px 0 5px;color:var(--navy)}
input,select,textarea{width:100%;padding:11px 13px;border:1.5px solid var(--line);border-radius:8px;font:inherit;background:#fff;transition:border .2s,box-shadow .2s}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--green);box-shadow:0 0 0 3px rgba(31,138,76,.18)}
textarea{min-height:120px;resize:vertical}
.hint{font-size:.8rem;color:var(--mute);margin-top:3px}
.formbox .btn{width:100%;margin-top:22px}
.alt{text-align:center;margin-top:16px;color:var(--mute)}
.alt a{color:var(--green-d);font-weight:700}
/* toasts */
#toasts{position:fixed;top:16px;right:16px;z-index:999;display:grid;gap:10px;max-width:min(420px,calc(100vw - 32px))}
.toast{background:#fff;border-left:6px solid var(--green);padding:13px 40px 13px 16px;border-radius:8px;box-shadow:0 10px 28px rgba(0,0,0,.18);position:relative;animation:slide .35s ease both}
.toast.error{border-color:var(--red)}
.toast button{position:absolute;top:6px;right:8px;border:0;background:none;font-size:1.2rem;cursor:pointer;color:var(--mute)}
@keyframes slide{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:none}}
/* tables & badges */
.tbl{overflow-x:auto;background:#fff;border:1px solid var(--line);border-radius:12px}
table{width:100%;border-collapse:collapse;min-width:720px}
th{background:var(--navy);color:#fff;text-align:left;padding:12px 14px;font-size:.86rem}
td{padding:12px 14px;border-bottom:1px solid var(--line);font-size:.92rem;vertical-align:top}
tr:hover td{background:#f8fbfa}
.badge{display:inline-block;padding:3px 11px;border-radius:99px;font-size:.78rem;font-weight:700}
.b-Pending{background:#fff3d6;color:#8a5d00}.b-In-Progress{background:#dbeafe;color:#1e4f9c}
.b-Resolved{background:#d8f2e1;color:#146c37}.b-Rejected{background:#fde0dc;color:#9b2318}
.pr-High{color:var(--red);font-weight:700}.pr-Medium{color:var(--amber);font-weight:700}.pr-Low{color:var(--green-d);font-weight:700}
.empty{text-align:center;padding:44px;color:var(--mute)}
.bar{display:flex;align-items:center;gap:10px;margin:8px 0;font-size:.9rem}
.bar i{display:block;height:10px;background:var(--green);border-radius:6px;min-width:6px}
.filters{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}
.filters input,.filters select{width:auto;flex:1;min-width:150px}
.pagehead{background:var(--navy);color:#fff;padding:34px 0}
.pagehead h1{font-size:1.8rem}.pagehead p{color:#b8cde0}
/* timeline */
.tl{list-style:none;margin:20px 0 4px;display:grid;grid-template-columns:repeat(3,1fr);position:relative}
.tl li{text-align:center;position:relative;color:var(--mute);font-weight:600;font-size:.88rem}
.tl li:before{content:"";display:block;width:34px;height:34px;border-radius:50%;background:#e3eaee;margin:0 auto 6px;position:relative;z-index:2}
.tl li:after{content:"";position:absolute;top:16px;left:-50%;width:100%;height:4px;background:#e3eaee;z-index:1}
.tl li:first-child:after{display:none}
.tl li.done{color:var(--green-d)}.tl li.done:before{background:var(--green);content:"✓";color:#fff;display:grid;place-items:center}
.tl li.done:after{background:var(--green)}
.tl.rej li.cur:before{background:var(--red);content:"✕";color:#fff;display:grid;place-items:center}
dl.det{display:grid;grid-template-columns:150px 1fr;gap:8px 14px;margin-top:16px}
dl.det dt{font-weight:700;color:var(--navy)}
@media(max-width:560px){dl.det{grid-template-columns:1fr}}
footer{background:#071b30;color:#a9bfd2;padding:34px 0 20px;font-size:.9rem}
footer .wrap{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap}
footer a:hover{color:#fff}
.copy{text-align:center;margin-top:20px;padding-top:16px;border-top:1px solid rgba(255,255,255,.1);font-size:.82rem}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style></head>
<body>
<div class="topbar"><div class="wrap"><span>🇮🇳 Government of India &nbsp;|&nbsp; Panchayati Raj</span><span>📞 Helpline: 1800-000-0000 (Mon–Sat, 10 AM–5 PM)</span></div></div>
<header class="nav"><div class="wrap">
 <a class="brand" href="{{ url_for('home') }}"><div class="logo">🏛️</div><div><b>Gram Panchayat</b><small>Digital Complaint Portal</small></div></a>
 <button class="burger" aria-label="Menu" onclick="document.getElementById('nv').classList.toggle('open')">☰</button>
 <nav id="nv"><ul>
  {% set ep = request.endpoint %}
  <li><a href="{{ url_for('home') }}" class="{{ 'on' if ep=='home' }}">HOME</a></li>
  <li><a href="{{ url_for('about') }}" class="{{ 'on' if ep=='about' }}">ABOUT</a></li>
  <li><a href="{{ url_for('services') }}" class="{{ 'on' if ep=='services' }}">SERVICES</a></li>
  <li><a href="{{ url_for('submit') }}" class="{{ 'on' if ep=='submit' }}">SUBMIT COMPLAINT</a></li>
  <li><a href="{{ url_for('track') }}" class="{{ 'on' if ep=='track' }}">TRACK COMPLAINT</a></li>
  {% if session.uid %}
   <li><a href="{{ url_for('dashboard') }}" class="{{ 'on' if ep in ('dashboard','admin') }}">{{ 'ADMIN' if session.role=='admin' else 'MY DASHBOARD' }}</a></li>
   <li><a class="cta" href="{{ url_for('logout') }}">LOGOUT</a></li>
  {% else %}
   <li><a class="cta" href="{{ url_for('login') }}">LOGIN</a></li>
  {% endif %}
 </ul></nav></div></header>
<div id="toasts">
{% with m = get_flashed_messages(with_categories=true) %}{% for c,t in m %}
 <div class="toast {{ c }}" role="alert">{{ t }}<button onclick="this.parentNode.remove()" aria-label="Close">×</button></div>
{% endfor %}{% endwith %}</div>
{{ body|safe }}
<footer><div class="wrap">
 <div><b style="color:#fff">Gram Panchayat Digital Complaint Portal</b><br>Your Village, Your Voice, Our Responsibility.</div>
 <div><a href="{{ url_for('about') }}">About</a> · <a href="{{ url_for('services') }}">Services</a> · <a href="{{ url_for('track') }}">Track Complaint</a> · <a href="{{ url_for('register') }}">Register</a></div>
</div><div class="copy">© <span id="yr"></span> Gram Panchayat. College community project.</div></footer>
<script>
document.getElementById('yr').textContent=new Date().getFullYear();
setTimeout(function(){document.querySelectorAll('.toast').forEach(function(t){t.style.transition='opacity .5s';t.style.opacity=0;setTimeout(function(){t.remove()},500)})},7000);
document.querySelectorAll('[data-count]').forEach(function(el){
 var end=parseInt(el.dataset.count,10),suf=el.dataset.suffix||'',n=0,step=Math.max(1,Math.ceil(end/40));
 var t=setInterval(function(){n=Math.min(end,n+step);el.textContent=n+suf;if(n>=end)clearInterval(t)},30)});
</script>
</body></html>"""

HOME = r"""
<div class="hero"><div class="wrap">
 <div>
  <h1>Your Village, Your Voice, Our Responsibility.</h1>
  <p>Report broken roads, water problems, streetlights, garbage and more from your phone. Get a complaint ID and follow every step until the problem is fixed.</p>
  <div class="btns"><a class="btn btn-g" href="{{ url_for('submit') }}">Submit Complaint</a>
  <a class="btn btn-o" href="{{ url_for('track') }}">Track Complaint</a></div>
 </div>
 <div class="hero-card"><h3>Raise a complaint in 3 steps</h3><ul>
  <li><span>👤</span><span>Create a free citizen account</span></li>
  <li><span>📝</span><span>Describe the problem and its location</span></li>
  <li><span>🔎</span><span>Track the status with your complaint ID</span></li></ul></div>
</div></div>
<section class="stats"><div class="wrap grid g4">
 <div class="card stat"><b data-count="{{ s.total }}">0</b><span>Complaints received</span></div>
 <div class="card stat"><b data-count="{{ s.resolved }}">0</b><span>Complaints resolved</span></div>
 <div class="card stat"><b data-count="{{ s.pending + s.progress }}">0</b><span>Being worked on</span></div>
 <div class="card stat"><b data-count="{{ rate }}" data-suffix="%">0</b><span>Resolution rate</span></div>
</div></section>
<section><div class="wrap">
 <div class="sh"><h2>Complaint categories</h2><p>Choose the category that best matches your problem.</p></div>
 <div class="grid g4">{% for n,i,d in categories %}
  <a class="card" href="{{ url_for('submit', category=n) }}"><div class="ico">{{ i }}</div><h3>{{ n }}</h3><p>{{ d }}</p></a>{% endfor %}</div>
</div></section>
<section style="background:#fff"><div class="wrap steps">
 <div class="sh"><h2>How it works</h2><p>From complaint to resolution in four simple steps.</p></div>
 <div class="grid g4">
  <div class="card"><div class="n">1</div><h3>Register and log in</h3><p>Sign up with your mobile number and village name.</p></div>
  <div class="card"><div class="n">2</div><h3>Submit your complaint</h3><p>Pick a category, describe the issue and give the location.</p></div>
  <div class="card"><div class="n">3</div><h3>Panchayat takes action</h3><p>An officer reviews it and updates the status with remarks.</p></div>
  <div class="card"><div class="n">4</div><h3>Track until resolved</h3><p>Enter your complaint ID any time to see progress.</p></div>
 </div></div></section>
<section class="band contact" id="contact"><div class="wrap">
 <div class="sh"><h2>Contact the Gram Panchayat</h2><p>Visit us or call during office hours.</p></div>
 <div class="grid g3">
  <div class="card"><div class="ico">📍</div><h3>Office address</h3><p>Gram Panchayat Bhawan, Main Road, Village Centre, District – 000000</p></div>
  <div class="card"><div class="ico">📞</div><h3>Phone</h3><p>Helpline 1800-000-0000<br>Office 0000-000000</p></div>
  <div class="card"><div class="ico">✉️</div><h3>Email and hours</h3><p>help@grampanchayat.gov.in<br>Mon–Sat, 10 AM – 5 PM</p></div>
 </div></div></section>
"""

ABOUT = r"""
<div class="pagehead"><div class="wrap"><h1>About the portal</h1><p>A simple way for villagers to reach their Panchayat.</p></div></div>
<section><div class="wrap grid g3">
 <div class="card"><div class="ico">🎯</div><h3>Our objective</h3><p>Give every villager an easy, transparent way to report public problems and see what is done about them.</p></div>
 <div class="card"><div class="ico">🤝</div><h3>Accountability</h3><p>Every complaint gets a unique ID, a status and officer remarks, so nothing gets lost.</p></div>
 <div class="card"><div class="ico">📱</div><h3>Works anywhere</h3><p>Designed for phones, tablets and computers, so you can report a problem on the spot.</p></div>
</div></section>
"""

SERVICES = r"""
<div class="pagehead"><div class="wrap"><h1>Our services</h1><p>What you can do on this portal.</p></div></div>
<section><div class="wrap grid g3">
 <div class="card"><div class="ico">📝</div><h3>Register complaints</h3><p>Report issues in eight categories with title, description, location and priority.</p><br><a class="btn btn-g btn-sm" href="{{ url_for('submit') }}">Submit Complaint</a></div>
 <div class="card"><div class="ico">🔎</div><h3>Track status</h3><p>Follow Pending, In Progress and Resolved stages using your complaint ID. No login needed.</p><br><a class="btn btn-n btn-sm" href="{{ url_for('track') }}">Track Complaint</a></div>
 <div class="card"><div class="ico">📊</div><h3>Personal dashboard</h3><p>See all your complaints and their latest status in one place.</p><br><a class="btn btn-n btn-sm" href="{{ url_for('dashboard') }}">Open dashboard</a></div>
</div></section>
"""

REGISTER = r"""
<div class="formbox wide"><h1>Create your citizen account</h1><p class="sub">Register once to submit and track complaints.</p>
<form method="post" novalidate><input type="hidden" name="csrf" value="{{ csrf() }}">
 <div class="row"><div><label for="name">Full name</label><input id="name" name="name" value="{{ f.get('name','') }}" required autocomplete="name"></div>
 <div><label for="mobile">Mobile number</label><input id="mobile" name="mobile" value="{{ f.get('mobile','') }}" inputmode="numeric" maxlength="10" required autocomplete="tel"></div></div>
 <div class="row"><div><label for="email">Email address</label><input id="email" type="email" name="email" value="{{ f.get('email','') }}" required autocomplete="email"></div>
 <div><label for="village">Village name</label><input id="village" name="village" value="{{ f.get('village','') }}" required></div></div>
 <div class="row"><div><label for="password">Password</label><input id="password" type="password" name="password" required autocomplete="new-password"><div class="hint">At least 8 characters, with a letter and a number.</div></div>
 <div><label for="confirm">Confirm password</label><input id="confirm" type="password" name="confirm" required autocomplete="new-password"></div></div>
 <button class="btn btn-g" type="submit">Create account</button>
</form><p class="alt">Already registered? <a href="{{ url_for('login') }}">Log in</a></p></div>
"""

LOGIN = r"""
<div class="formbox"><h1>Log in</h1><p class="sub">Use your email or mobile number.</p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf() }}">
 <label for="identity">Email or mobile number</label><input id="identity" name="identity" required autocomplete="username">
 <label for="password">Password</label><input id="password" type="password" name="password" required autocomplete="current-password">
 <button class="btn btn-g" type="submit">Log in</button>
</form><p class="alt">New citizen? <a href="{{ url_for('register') }}">Create an account</a></p>
<p class="hint" style="text-align:center;margin-top:10px">Demo admin: admin@panchayat.gov / Admin@123</p></div>
"""

SUBMIT = r"""
<div class="formbox wide"><h1>Submit a complaint</h1><p class="sub">Give clear details so the Panchayat can act quickly.</p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf() }}">
 <div class="row"><div><label for="category">Category</label>
  <select id="category" name="category" required><option value="">Select a category</option>
  {% for n,i,d in categories %}<option value="{{ n }}" {{ 'selected' if f.get('category')==n }}>{{ i }} {{ n }}</option>{% endfor %}</select></div>
 <div><label for="priority">Priority</label><select id="priority" name="priority">
  {% for p in priorities %}<option {{ 'selected' if (f.get('priority') or 'Medium')==p }}>{{ p }}</option>{% endfor %}</select></div></div>
 <label for="title">Complaint title</label><input id="title" name="title" value="{{ f.get('title','') }}" maxlength="100" required>
 <label for="location">Location of the problem</label><input id="location" name="location" value="{{ f.get('location','') }}" placeholder="Ward, street or landmark" required>
 <label for="description">Description</label><textarea id="description" name="description" required>{{ f.get('description','') }}</textarea>
 <div class="hint">Mention since when the problem exists and how it affects people.</div>
 <button class="btn btn-g" type="submit">Submit complaint</button>
</form></div>
"""

TRACK = r"""
<div class="formbox wide"><h1>Track your complaint</h1><p class="sub">Enter the complaint ID you received, for example GP202600001.</p>
<form method="post" style="display:flex;gap:10px;flex-wrap:wrap"><input type="hidden" name="csrf" value="{{ csrf() }}">
 <input name="cid" value="{{ cid }}" placeholder="Complaint ID" style="flex:1;min-width:200px" required aria-label="Complaint ID">
 <button class="btn btn-g" style="width:auto;margin:0" type="submit">Track complaint</button></form>
{% if c %}
 <hr style="border:0;border-top:1px solid var(--line);margin:24px 0">
 <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px"><h2 style="color:var(--navy)">{{ c.cid }}</h2>
 <span class="badge b-{{ c.status.replace(' ','-') }}">{{ c.status }}</span></div>
 {% set rej = c.status=='Rejected' %}
 <ul class="tl {{ 'rej' if rej }}">
  <li class="done">Submitted</li>
  <li class="{{ 'done' if c.status in ('In Progress','Resolved') }} {{ 'cur' if rej }}">{{ 'Rejected' if rej else 'In Progress' }}</li>
  <li class="{{ 'done' if c.status=='Resolved' }}">Resolved</li></ul>
 <dl class="det">
  <dt>Title</dt><dd>{{ c.title }}</dd><dt>Category</dt><dd>{{ c.category }}</dd>
  <dt>Location</dt><dd>{{ c.location }}, {{ c.village }}</dd>
  <dt>Priority</dt><dd class="pr-{{ c.priority }}">{{ c.priority }}</dd>
  <dt>Description</dt><dd>{{ c.description }}</dd>
  <dt>Submitted on</dt><dd>{{ c.created_at }}</dd><dt>Last updated</dt><dd>{{ c.updated_at }}</dd>
  <dt>Officer remarks</dt><dd>{{ c.remarks or 'No remarks yet.' }}</dd></dl>
{% endif %}</div>
"""

DASH = r"""
<div class="pagehead"><div class="wrap"><h1>Welcome, {{ session.name }}</h1><p>Your complaints and their latest status.</p></div></div>
<section style="padding-top:34px"><div class="wrap">
 <div class="grid g4">
  <div class="card stat"><b>{{ s.total }}</b><span>Total</span></div><div class="card stat"><b>{{ s.pending }}</b><span>Pending</span></div>
  <div class="card stat"><b>{{ s.progress }}</b><span>In progress</span></div><div class="card stat"><b>{{ s.resolved }}</b><span>Resolved</span></div></div>
 <div style="margin:26px 0 12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
  <h2 style="color:var(--navy)">My complaints</h2><a class="btn btn-g btn-sm" href="{{ url_for('submit') }}">New complaint</a></div>
 {% if rows %}<div class="tbl"><table><tr><th>ID</th><th>Category</th><th>Title</th><th>Date</th><th>Status</th><th></th></tr>
 {% for r in rows %}<tr><td><b>{{ r.cid }}</b></td><td>{{ r.category }}</td><td>{{ r.title }}</td><td>{{ r.created_at }}</td>
  <td><span class="badge b-{{ r.status.replace(' ','-') }}">{{ r.status }}</span></td>
  <td><a class="btn btn-n btn-sm" href="{{ url_for('track', cid=r.cid) }}">View</a></td></tr>{% endfor %}</table></div>
 {% else %}<div class="card empty">You have not submitted any complaints yet.<br><br><a class="btn btn-g" href="{{ url_for('submit') }}">Submit your first complaint</a></div>{% endif %}
</div></section>
"""

ADMIN = r"""
<div class="pagehead"><div class="wrap"><h1>Admin panel</h1><p>Review complaints and update their status.</p></div></div>
<section style="padding-top:34px"><div class="wrap">
 <div class="grid g4">
  <div class="card stat"><b>{{ s.total }}</b><span>Total complaints</span></div><div class="card stat"><b>{{ s.pending }}</b><span>Pending</span></div>
  <div class="card stat"><b>{{ s.progress }}</b><span>In progress</span></div><div class="card stat"><b>{{ s.resolved }}</b><span>Resolved</span></div>
  <div class="card stat"><b>{{ users }}</b><span>Registered citizens</span></div></div>
 {% if bycat %}<div class="card" style="margin-top:22px"><h3>Complaints by category</h3>
  {% for b in bycat %}<div class="bar"><span style="width:200px;flex:none">{{ b.category }}</span><i style="width:{{ (b.n*100/bycat[0].n)|int }}%"></i><b>{{ b.n }}</b></div>{% endfor %}</div>{% endif %}
 <form class="filters" method="get">
  <input name="q" value="{{ q }}" placeholder="Search ID, title or citizen" aria-label="Search">
  <select name="status" aria-label="Status"><option value="">All statuses</option>{% for x in statuses %}<option {{ 'selected' if st==x }}>{{ x }}</option>{% endfor %}</select>
  <select name="category" aria-label="Category"><option value="">All categories</option>{% for n,i,d in categories %}<option {{ 'selected' if cat==n }}>{{ n }}</option>{% endfor %}</select>
  <button class="btn btn-n btn-sm" type="submit">Filter</button></form>
 {% if rows %}<div class="tbl"><table><tr><th>ID</th><th>Citizen</th><th>Complaint</th><th>Priority</th><th>Status and remarks</th></tr>
 {% for r in rows %}<tr>
  <td><b>{{ r.cid }}</b><br><small>{{ r.created_at }}</small></td>
  <td>{{ r.uname }}<br><small>{{ r.village }} · {{ r.mobile }}</small></td>
  <td><b>{{ r.title }}</b><br><small>{{ r.category }} · {{ r.location }}</small><br>{{ r.description }}</td>
  <td class="pr-{{ r.priority }}">{{ r.priority }}</td>
  <td><form method="post" action="{{ url_for('update', cid=r.id) }}"><input type="hidden" name="csrf" value="{{ csrf() }}">
   <select name="status" aria-label="Status">{% for x in statuses %}<option {{ 'selected' if r.status==x }}>{{ x }}</option>{% endfor %}</select>
   <input name="remarks" value="{{ r.remarks }}" placeholder="Remarks for citizen" style="margin:6px 0" aria-label="Remarks">
   <button class="btn btn-g btn-sm" type="submit">Save</button></form></td></tr>{% endfor %}</table></div>
 {% else %}<div class="card empty">No complaints match these filters.</div>{% endif %}
</div></section>
"""

ERR = r"""<div class="formbox" style="text-align:center"><h1 style="font-size:3rem">{{ code }}</h1><p class="sub">{{ msg }}</p>
<a class="btn btn-g" href="{{ url_for('home') }}">Back to home</a></div>"""

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
