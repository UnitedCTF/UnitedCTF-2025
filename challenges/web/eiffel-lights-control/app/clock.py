from flask import Flask, Response

clock_app = Flask(__name__)

@clock_app.get("/clock")
def clock():
    return Response("10:32AM", mimetype="text/plain")

if __name__ == "__main__":
    clock_app.run(host="127.0.0.1", port=5123, debug=False, use_reloader=False)