from flask import Flask, render_template, request, redirect, session
import bot_controller
import auth
import threading

app = Flask(__name__)
app.secret_key = "super-secret-key"

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form["username"]
        pwd = request.form["password"]

        if auth.check_login(user, pwd):
            session["logged_in"] = True
            return redirect("/dashboard")

    return render_template("login.html")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if not session.get("logged_in"):
        return redirect("/")

    if request.method == "POST":
        uid = request.form["uid"]
        hours = float(request.form["hours"])

        threading.Thread(
            target=bot_controller.start_bot,
            args=(uid, hours),
            daemon=True
        ).start()

    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

app.run(host="0.0.0.0", port=5000)