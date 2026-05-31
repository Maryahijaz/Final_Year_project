from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import requests

app = Flask(__name__)
app.secret_key = "trustzai-web-secret-2025"

TRUSTZAI_API = "http://localhost:8000"

@app.route("/")
def index():
    if "token" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("chat"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        try:
            response = requests.post(
                f"{TRUSTZAI_API}/login",
                data={"username": username, "password": password}
            )
            if response.status_code == 200:
                data = response.json()
                session["token"] = data["access_token"]
                session["role"] = data["role"]
                session["username"] = username
                return redirect(url_for("chat"))
            else:
                return render_template("login.html", error="Invalid credentials")
        except Exception as e:
            return render_template("login.html", error="Server unavailable")
    return render_template("login.html")

@app.route("/chat")
def chat():
    if "token" not in session:
        return redirect(url_for("login"))
    return render_template(
        "chat.html",
        username=session.get("username"),
        role=session.get("role")
    )

@app.route("/api/query", methods=["POST"])
def query():
    if "token" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json()
    prompt = data.get("prompt", "")
    try:
        response = requests.post(
            f"{TRUSTZAI_API}/query",
            headers={"Authorization": f"Bearer {session['token']}"},
            json={"prompt": prompt}
        )
        # نرجع الـ detail كاملاً للـ frontend
        if response.status_code != 200:
            try:
                error_data = response.json()
                return jsonify({"detail": error_data.get("detail", "Error")}), response.status_code
            except:
                return jsonify({"detail": response.text}), response.status_code
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
