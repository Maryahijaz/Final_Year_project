from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import requests

app = Flask(__name__)
app.secret_key = "monitoring-web-secret-2025"

MONITORING_API = "http://localhost:6000"

@app.route("/")
def index():
    if "token" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        try:
            response = requests.post(
                f"{MONITORING_API}/login",
                data={"username": username, "password": password}
            )
            if response.status_code == 200:
                data = response.json()
                session["token"] = data["access_token"]
                session["role"] = data["role"]
                session["username"] = username
                return redirect(url_for("dashboard"))
            else:
                return render_template("login.html", error="Invalid credentials")
        except Exception as e:
            return render_template("login.html", error="Server unavailable")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "token" not in session:
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role")
    )

@app.route("/api/stats")
def stats():
    if "token" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    try:
        response = requests.get(
            f"{MONITORING_API}/stats",
            headers={"Authorization": f"Bearer {session['token']}"}
        )
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/logs/<log_type>")
def logs(log_type):
    if "token" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    try:
        response = requests.get(
            f"{MONITORING_API}/logs/{log_type}",
            headers={"Authorization": f"Bearer {session['token']}"}
        )
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "token" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json()
    try:
        response = requests.post(
            f"{MONITORING_API}/analyze",
            headers={"Authorization": f"Bearer {session['token']}"},
            json={"question": data.get("question")},
            timeout=1000
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000, debug=True)
