from flask import Flask, render_template, request, redirect, session, g, url_for
import urllib.parse
import sqlite3
import requests

app = Flask(__name__)
app.secret_key = "REDACTED"

FLAG1 = "REDACTED"
FLAG2 = "REDACTED"
FLAG3 = "REDACTED"

DATABASE = 'eiffel.db'

def connect_db():
    return sqlite3.connect(DATABASE)

@app.before_request
def before_request():
    g.db = connect_db()

@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()

def verify_user(username, password):
    c = g.db.cursor()
    c.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
    return c.fetchone()

@app.get("/")
def index():
    if session.get("username") is not None:
        return redirect(url_for('lights'))
    else:
        return redirect(url_for('login'))

@app.get("/login")
def login():
    return render_template('login.html')

@app.post("/login")
def login_post():
    username = request.form.get("username") or ""
    password = request.form.get("password") or ""

    # We've disabled john's account since he's been fired
    username = username.replace("john", "")
    role_data = verify_user(username, password)
    if not role_data:
        return render_template('login.html', error='Wrong username or password')

    session["username"] = username
    session["role"] = role_data[0]

    return redirect(url_for('lights'))


@app.get("/logout")
def logout():
    session.pop('username')
    session.pop('role')
    return redirect(url_for('login'))

lights_db = {
    1: "off",
    2: "off",
    3: "on"
}

users_db = {
    "admin": {"password": "REDACTED", "role": "admin"},
    "john": {"password": "johns_super_secret_password", "role": "user"}
}

def init_db():
    conn = connect_db()
    c = conn.cursor()
    c.execute("CREATE TABLE lights (id INTEGER PRIMARY KEY, status TEXT)")
    for id, status in lights_db.items():
        c.execute("INSERT INTO lights (id, status) VALUES (?, ?)", (id, status))
    c.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT, role TEXT)")
    for username, info in users_db.items():
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  (username, info["password"], info["role"]))
    conn.commit()

init_db()

@app.get("/lights")
def lights():
    if session.get("username") is not None:
        if session["username"] == "admin":
            return render_template('lights.html', flag=FLAG2)
    
        return render_template('lights.html', flag=FLAG1)
    else:
        return redirect(url_for('login'))

@app.post("/lights")
def lights_post():
    if session.get("username") is None:
        return redirect(url_for('login'))
    
    id = request.form["id"] or ""
    query = f"SELECT status FROM lights WHERE id = '{id}'"
    try:
        c = g.db.cursor()
        result = c.execute(query).fetchall()
        light_enabled = False
        if result and result[0][0] == "on":
            light_enabled = True
        return render_template('lights.html', light_status=light_enabled)
    except Exception as e:
        print(e)
        return render_template('lights.html', error="An error occurred while fetching the light status.")
    

@app.get("/admin")
def admin():
    if session.get("role") != "admin":
        return redirect(url_for('index'))
    else:
        return render_template('admin.html')
    
@app.post("/admin")
def admin_post():
    if session.get("role") != "admin":
        return redirect(url_for('index'))
    
    url = request.form.get("url") or ""
    url += "/clock"

    (scheme, host, path, query, fragment) = urllib.parse.urlsplit(url)

    # Validate that only the clock service can be called
    if host == "127.0.0.1:5123":
        requestUrl = urllib.parse.urlunsplit(
            ('http', '127.0.0.1:5123', path, query, fragment))
    else:
        requestUrl = urllib.parse.urlunsplit(('', '', path, query, fragment))
    try:
        res = requests.get(requestUrl)
    except Exception as e:
        return render_template('admin.html', message="An error occurred while fetching the URL.")

    if ("12:00AM" == res.text):
        return render_template('admin.html', message="✨ Congratulations, the lights are now on! ✨", flag=FLAG3)
    else:
        return render_template('admin.html', message="It is not midnight yet, it is currently {}".format(res.text))
