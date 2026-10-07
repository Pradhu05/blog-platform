import sqlite3
from flask import Flask, g, jsonify, request, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-me"
DB = "blog.db"


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS posts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS comments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id),
        body TEXT NOT NULL,
        created TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    c.close()


def err(msg, code=400):
    return jsonify(error=msg), code


def login_required():
    return "uid" not in session


@app.route("/")
def index():
    return render_template("index.html")


# ---------- auth ----------
@app.post("/api/register")
def register():
    d = request.get_json(silent=True) or {}
    u, p = (d.get("username") or "").strip(), d.get("password") or ""
    if not u or len(p) < 4:
        return err("username required, password min 4 chars")
    try:
        cur = db().execute("INSERT INTO users(username,password) VALUES(?,?)",
                           (u, generate_password_hash(p)))
        db().commit()
    except sqlite3.IntegrityError:
        return err("username taken", 409)
    session["uid"], session["username"] = cur.lastrowid, u
    return jsonify(id=cur.lastrowid, username=u), 201


@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    r = db().execute("SELECT * FROM users WHERE username=?", (d.get("username"),)).fetchone()
    if not r or not check_password_hash(r["password"], d.get("password") or ""):
        return err("invalid credentials", 401)
    session["uid"], session["username"] = r["id"], r["username"]
    return jsonify(id=r["id"], username=r["username"])


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    if login_required():
        return jsonify(user=None)
    return jsonify(user=dict(id=session["uid"], username=session["username"]))


# ---------- posts ----------
POST_SQL = """SELECT p.id,p.title,p.body,p.created,p.user_id,u.username AS author
              FROM posts p JOIN users u ON u.id=p.user_id"""


@app.get("/api/posts")
def list_posts():
    rows = db().execute(POST_SQL + " ORDER BY p.id DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/posts/<int:pid>")
def get_post(pid):
    p = db().execute(POST_SQL + " WHERE p.id=?", (pid,)).fetchone()
    if not p:
        return err("not found", 404)
    cs = db().execute("""SELECT c.id,c.body,c.created,c.user_id,u.username AS author
                         FROM comments c JOIN users u ON u.id=c.user_id
                         WHERE c.post_id=? ORDER BY c.id""", (pid,)).fetchall()
    return jsonify(**dict(p), comments=[dict(c) for c in cs])


@app.post("/api/posts")
def create_post():
    if login_required():
        return err("login required", 401)
    d = request.get_json(silent=True) or {}
    t, b = (d.get("title") or "").strip(), (d.get("body") or "").strip()
    if not t or not b:
        return err("title and body required")
    cur = db().execute("INSERT INTO posts(user_id,title,body) VALUES(?,?,?)",
                       (session["uid"], t, b))
    db().commit()
    return jsonify(id=cur.lastrowid), 201


@app.put("/api/posts/<int:pid>")
def edit_post(pid):
    if login_required():
        return err("login required", 401)
    p = db().execute("SELECT user_id FROM posts WHERE id=?", (pid,)).fetchone()
    if not p:
        return err("not found", 404)
    if p["user_id"] != session["uid"]:
        return err("forbidden", 403)
    d = request.get_json(silent=True) or {}
    t, b = (d.get("title") or "").strip(), (d.get("body") or "").strip()
    if not t or not b:
        return err("title and body required")
    db().execute("UPDATE posts SET title=?, body=? WHERE id=?", (t, b, pid))
    db().commit()
    return jsonify(ok=True)


@app.delete("/api/posts/<int:pid>")
def delete_post(pid):
    if login_required():
        return err("login required", 401)
    p = db().execute("SELECT user_id FROM posts WHERE id=?", (pid,)).fetchone()
    if not p:
        return err("not found", 404)
    if p["user_id"] != session["uid"]:
        return err("forbidden", 403)
    db().execute("DELETE FROM posts WHERE id=?", (pid,))
    db().commit()
    return jsonify(ok=True)


# ---------- comments ----------
@app.post("/api/posts/<int:pid>/comments")
def add_comment(pid):
    if login_required():
        return err("login required", 401)
    if not db().execute("SELECT 1 FROM posts WHERE id=?", (pid,)).fetchone():
        return err("not found", 404)
    b = ((request.get_json(silent=True) or {}).get("body") or "").strip()
    if not b:
        return err("comment required")
    cur = db().execute("INSERT INTO comments(post_id,user_id,body) VALUES(?,?,?)",
                       (pid, session["uid"], b))
    db().commit()
    return jsonify(id=cur.lastrowid), 201


@app.delete("/api/comments/<int:cid>")
def delete_comment(cid):
    if login_required():
        return err("login required", 401)
    c = db().execute("SELECT user_id FROM comments WHERE id=?", (cid,)).fetchone()
    if not c:
        return err("not found", 404)
    if c["user_id"] != session["uid"]:
        return err("forbidden", 403)
    db().execute("DELETE FROM comments WHERE id=?", (cid,))
    db().commit()
    return jsonify(ok=True)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
