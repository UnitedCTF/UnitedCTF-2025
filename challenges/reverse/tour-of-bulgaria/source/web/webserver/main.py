import os
from flask import Flask, request, render_template, jsonify
from datetime import datetime
app = Flask(__name__)

FLAG = "FLAG-DUMMY"
try:
    with open("/42dc8201-4f3b-47bf-80d0-84db141dbd20", "r") as f:
        FLAG = f.read().strip()
except Exception:
    pass

def log_event(event):
    """
    Log an event to the event log file.
    """
    with open(config["EVENT_LOG"], "a") as f:
        try:
            f.write(f"{datetime.now()}: {event} | User: [{request.cookies.get('user')}] | IP: {request.remote_addr}\n")
        except Exception:
            f.write(f"{datetime.now()}: {event}\n")


def _load_config(file_path):
    """
    Load the configuration from a file.
    """
    try:
        with open(file_path, "r") as f:
            config = [tuple(x.split("=")) for x in f.read().strip().splitlines()]
        return dict(config)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        return None


conf_path = "/server_data/server.conf"
config = _load_config(conf_path)
if config is None:
    raise ValueError("Configuration file not found or invalid")
log_event(f"Configuration loaded from {conf_path}")


@app.route("/", methods=["GET"])
def index():
    log_event("Home page accessed")
    events = open(config["EVENT_LOG"], "r").read().splitlines()
    return render_template("home.html", events=events)


@app.route("/admin", methods=["GET"])
def admin():
    user = request.cookies.get("user")
    if user is None:
        log_event("Unauthorized access attempt to admin page. (No 'user' cookie)")
        return render_template("error.html")
    try:
        admin_users = open(config["ADMIN_USERS_LOCATION"], "r").read().splitlines()
        if user not in admin_users:
            log_event(f"Unauthorized access attempt to admin page. (User '{user}' not in admin users list)")
            return render_template("error.html")
        log_event(f"Admin page accessed by user: {user}")
        return render_template(
            "admin.html", flag=FLAG
        )
    except FileNotFoundError:
        log_event("ADMIN_USERS_LOCATION file not found")
        return render_template("error.html")


app.run(
    host="0.0.0.0",
    port=int(config.get("PORT")),
)
