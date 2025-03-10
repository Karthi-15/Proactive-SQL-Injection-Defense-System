# from flask import Flask, render_template, request, redirect, session, abort
# import sqlite3
# from python_firewall import firewall_check, enforce_firewall
# from auto_retrain import retrain_model

# app = Flask(__name__, template_folder="templates")
# app.secret_key = "supersecretkey"

# # ✅ Database Connection
# def get_db_connection():
#     conn = sqlite3.connect("test.db")
#     conn.row_factory = sqlite3.Row
#     return conn

# # ✅ Enforce Firewall Before Every Request
# @app.before_request
# def check_firewall():
#     enforce_firewall()

# # ✅ Home Page (Login)
# @app.route("/")
# def home():
#     if "user" in session:
#         return redirect("/dashboard")
#     return render_template("login.html")

# # ✅ Login Route
# @app.route("/login", methods=["GET", "POST"])
# def login():
#     if request.method == "POST":
#         username = request.form["username"]
#         password = request.form["password"]

#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
#         user = cursor.fetchone()
#         conn.close()

#         if user:
#             session["user"] = username
#             return redirect("/dashboard")
#         else:
#             return render_template("login.html", error="🚫 Login Failed! Invalid credentials.")

#     return render_template("login.html")

# # ✅ Dashboard
# @app.route("/dashboard")
# def dashboard():
#     if "user" not in session:
#         return redirect("/")
#     return render_template("dashboard.html", user=session["user"])

# # ✅ Search Functionality (SQL Injection Protected)
# @app.route("/search", methods=["GET", "POST"])
# def search():
#     if "user" not in session:
#         return redirect("/")
    
#     results = None
#     blocked_query = None

#     if request.method == "POST":
#         query = request.form["query"].strip()
#         print(f"🔎 User Entered Query: {query}")

#         # ✅ Run Firewall Check Before Executing Query
#         if not firewall_check(query):
#             print(f"❌ [APP] SQL Injection Detected! Query Blocked: {query}")
#             blocked_query = query
#             return render_template("search.html", results=None, blocked_query=blocked_query)

#         # ✅ Execute Query if Safe
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         try:
#             cursor.execute(query)
#             results = [dict(row) for row in cursor.fetchall()]
#             print(f"✅ [APP] Query Executed Successfully: {results}")

#         except sqlite3.Error as e:
#             results = None
#             print("❌ SQL Error:", e)

#         conn.close()

#     return render_template("search.html", results=results, blocked_query=blocked_query)

# # ✅ Admin Panel to View & Manage Blocked IPs
# @app.route("/blocked_ips", methods=["GET", "POST"])
# def blocked_ips():
#     if "user" not in session or session["user"] != "admin":
#         return redirect("/")
    
#     conn = get_db_connection()
#     cursor = conn.cursor()

#     # ✅ Remove Unblocked IPs
#     if request.method == "POST":
#         ip_to_unblock = request.form.get("unblock_ip")
#         if ip_to_unblock:
#             cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_to_unblock,))
#             conn.commit()

#     cursor.execute("SELECT ip_address FROM blocked_ips")
#     ips = [row["ip_address"] for row in cursor.fetchall()]
#     conn.close()

#     return render_template("blocked_ips.html", ips=ips)

# # ✅ Admin Review for Feedback Log
# @app.route("/admin", methods=["GET", "POST"])
# def admin():
#     if "user" not in session or session["user"] != "admin":
#         print("❌ Access Denied: Not an Admin!")
#         return redirect("/")

#     conn = get_db_connection()
#     cursor = conn.cursor()
    
#     if request.method == "POST":
#         query_id = request.form.get("query_id")
#         actual_label = request.form.get("actual_label")

#         if query_id and actual_label:
#             cursor.execute("UPDATE feedback_log SET actual_label = ?, reviewed = 1 WHERE id = ?", (actual_label, query_id))
#             conn.commit()
    
#     cursor.execute("SELECT COUNT(*) FROM feedback_log WHERE actual_label IS NOT NULL")
#     feedback_count = cursor.fetchone()[0]

#     if feedback_count >= 10:
#         print("🔄 Auto-Retraining Triggered: 10+ feedback entries found!")
#         retrain_model()

#     cursor.execute("SELECT * FROM feedback_log WHERE reviewed = 0")
#     logs = [dict(row) for row in cursor.fetchall()]
#     conn.close()
    
#     if len(logs) == 0:
#         print("✅ No pending queries for review.")
    
#     return render_template("admin.html", logs=logs)

# # ✅ Logout
# @app.route("/logout")
# def logout():
#     session.pop("user", None)
#     return redirect("/")

# if __name__ == "__main__":
#     app.run(debug=True)

from flask import Flask, render_template, request, redirect, session
import sqlite3
from python_firewall import firewall_check, enforce_firewall
from auto_retrain import retrain_model

app = Flask(__name__, template_folder="templates")
app.secret_key = "supersecretkey"


def get_db_connection():
    conn = sqlite3.connect("test.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.before_request
def check_firewall():
    enforce_firewall()


@app.route("/", methods=["GET", "POST"])
def home():
    if "user" in session:
        return redirect("/dashboard")
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session["user"] = username
            return redirect("/dashboard")
        else:
            return render_template("login.html", error="Invalid credentials. Please try again.")
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html", user=session["user"])


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user" not in session:
        return redirect("/")
    
    message = None
    if request.method == "POST":
        new_password = request.form["new_password"]
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, session["user"]))
        conn.commit()
        conn.close()
        message = "Password updated successfully."
    
    return render_template("profile.html", user=session["user"], message=message)


@app.route("/search", methods=["GET", "POST"])
def search():
    if "user" not in session:
        return redirect("/")
    
    results = None
    blocked_query = None

    if request.method == "POST":
        query = request.form["query"].strip()
        print(f"User Entered Query: {query}")

        
        if not firewall_check(query):
            print(f"SQL Injection Detected! Query Blocked: {query}")
            blocked_query = query
            return render_template("search.html", results=None, blocked_query=blocked_query)

        
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query)
            results = [dict(row) for row in cursor.fetchall()]
            print(f"Query Executed Successfully: {results}")

        except sqlite3.Error as e:
            results = None
            print("SQL Error:", e)

        conn.close()

    return render_template("search.html", results=results, blocked_query=blocked_query)


@app.route("/blocked_ips", methods=["GET", "POST"])
def blocked_ips():
    if "user" not in session or session["user"] != "admin":
        return redirect("/")
    
    conn = get_db_connection()
    cursor = conn.cursor()

   
    if request.method == "POST":
        ip_to_unblock = request.form.get("unblock_ip")
        if ip_to_unblock:
            cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_to_unblock,))
            conn.commit()

    cursor.execute("SELECT ip_address FROM blocked_ips")
    ips = [row["ip_address"] for row in cursor.fetchall()]
    conn.close()

    return render_template("blocked_ips.html", ips=ips)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if "user" not in session or session["user"] != "admin":
        print("Access Denied: Not an Admin!")
        return redirect("/")

    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == "POST":
        query_id = request.form.get("query_id")
        actual_label = request.form.get("actual_label")

        if query_id and actual_label:
            cursor.execute("UPDATE feedback_log SET actual_label = ?, reviewed = 1 WHERE id = ?", (actual_label, query_id))
            conn.commit()
    
    cursor.execute("SELECT COUNT(*) FROM feedback_log WHERE actual_label IS NOT NULL")
    feedback_count = cursor.fetchone()[0]

    if feedback_count >= 10:
        print("Auto-Retraining Triggered: 10+ feedback entries found!")
        retrain_model()

    cursor.execute("SELECT * FROM feedback_log WHERE reviewed = 0")
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    if len(logs) == 0:
        print("No pending queries for review.")
    
    return render_template("admin.html", logs=logs)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
    
