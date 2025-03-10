# # import sqlite3
# import joblib
# import pandas as pd
# from flask import request, abort

# # ✅ Load trained ML model
# model = joblib.load("models/random_forest_sqli_model.pkl")

# # ✅ Database connection
# def get_db_connection():
#     conn = sqlite3.connect("test.db")
#     conn.row_factory = sqlite3.Row
#     return conn

# # ✅ Function to block an IP in the database
# def block_ip(ip_address):
#     conn = get_db_connection()
#     cursor = conn.cursor()
    
#     # Insert the blocked IP only if it does not already exist
#     cursor.execute("INSERT OR IGNORE INTO blocked_ips (ip_address) VALUES (?)", (ip_address,))
#     conn.commit()
#     conn.close()
    
#     print(f"🚫 [FIREWALL] Blocked IP: {ip_address}")

# # ✅ Function to check if an IP is blocked
# def is_ip_blocked(ip_address):
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     cursor.execute("SELECT * FROM blocked_ips WHERE ip_address = ?", (ip_address,))
#     result = cursor.fetchone()
#     conn.close()
    
#     return result is not None  # Return True if IP is found (blocked), False otherwise

# # ✅ Extract features dynamically for ML model
# def extract_features(query):
#     SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "ALTER", "EXEC", "OR", "AND"]
#     SPECIAL_CHARACTERS = ["'", '"', ";", "--", "#", "(", ")", "="]

#     return pd.DataFrame([{
#         "length": len(query),
#         "keyword_count": sum(query.upper().count(keyword) for keyword in SQL_KEYWORDS),
#         "special_character_count": sum(1 for char in query if char in SPECIAL_CHARACTERS)
#     }])

# # ✅ Enforce firewall before every request
# def enforce_firewall():
#     user_ip = request.remote_addr  # Get User IP Address

#     # 🚫 If IP is blocked, return HTTP 403 (Forbidden)
#     if is_ip_blocked(user_ip):
#         print(f"🚫 [FIREWALL] BLOCKED ATTEMPT FROM: {user_ip}")
#         abort(403)

# # ✅ Main function to check SQL Injection attempts
# def firewall_check(query):
#     try:
#         user_ip = request.remote_addr  # Get user's IP address

#         # 🚫 Check if IP is already blocked
#         if is_ip_blocked(user_ip):
#             print(f"🚫 [FIREWALL] BLOCKED ATTEMPT FROM: {user_ip}")
#             abort(403)

#         # ✅ ML Model Prediction
#         features = extract_features(query)
#         prediction_proba = model.predict_proba(features)[0]
#         prediction = model.predict(features)[0]

#         print(f"🔍 Query Features: {features}")  
#         print(f"🔍 Model Prediction: {prediction}, Probability: {prediction_proba}")

#         # 🚫 Block if model is confident the query is malicious
#         if prediction == 1 and prediction_proba[1] > 0.9:
#             print(f"❌ [FIREWALL] SQL Injection Detected! Blocking Query: {query}")
            
#             # ✅ Block IP in database
#             block_ip(user_ip)
            
#             # ✅ Immediately stop the request
#             abort(403)

#         return True  # ✅ Allow the request if it's safe

#     except Exception as e:
#         print(f"🔥 [FIREWALL] Error: {e}")
#         return False  
import sqlite3
import joblib
import pandas as pd
from flask import request, abort

# ✅ Load trained ML model
print("📂 Loading trained model...")
model = joblib.load("models/random_forest_sqli_model.pkl")

# ✅ Define SQL-related patterns
SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "ALTER", "EXEC", "OR", "AND"]
SPECIAL_CHARACTERS = ["'", '"', ";", "--", "#", "(", ")", "="]
SENSITIVE_COLUMNS = ["password", "user_id", "card_number", "ssn", "credit_card"]

# ✅ Database Connection
def get_db_connection():
    conn = sqlite3.connect("test.db")
    conn.row_factory = sqlite3.Row
    return conn

# ✅ Function to Block Malicious IPs
def block_ip(ip_address):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("INSERT OR IGNORE INTO blocked_ips (ip_address) VALUES (?)", (ip_address,))
    conn.commit()
    conn.close()
    
    print(f"🚫 [FIREWALL] Blocked IP: {ip_address}")

# ✅ Function to Check if an IP is Blocked
def is_ip_blocked(ip_address):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocked_ips WHERE ip_address = ?", (ip_address,))
    result = cursor.fetchone()
    conn.close()
    
    return result is not None  

def enforce_firewall():
    user_ip = request.remote_addr  # Get User IP Address

    # 🚫 If IP is blocked, return HTTP 403 (Forbidden)
    if is_ip_blocked(user_ip):
        print(f"🚫 [FIREWALL] BLOCKED ATTEMPT FROM: {user_ip}")
        abort(403)


# ✅ Extract Features for ML Model
def extract_features(query):
    return pd.DataFrame([{
        "length": len(query),
        "keyword_count": sum(query.upper().count(word) for word in SQL_KEYWORDS),
        "special_character_count": sum(1 for char in query if char in SPECIAL_CHARACTERS),
        "contains_sensitive_column": int(any(col in query.lower() for col in SENSITIVE_COLUMNS)),
        "contains_select_star": int("SELECT *" in query.upper()),
        "contains_union": int("UNION SELECT" in query.upper()),
        "contains_or_true": int("OR 1=1" in query.upper()),
        "contains_update_delete": int(any(x in query.upper() for x in ["UPDATE", "DELETE", "DROP"]))
    }])

# ✅ Check for SQL Injection
def firewall_check(query):
    try:
        user_ip = request.remote_addr  

        if is_ip_blocked(user_ip):
            print(f"🚫 [FIREWALL] BLOCKED ATTEMPT FROM: {user_ip}")
            abort(403)

        # 🚨 **Manually Block Dangerous Queries**
        if "SELECT *" in query.upper():
            print(f"❌ [FIREWALL] SELECT * Query Blocked: {query}")
            block_ip(user_ip)
            abort(403)

        # ✅ Extract Features & Predict with ML Model
        features = extract_features(query)

        # 🚨 **BLOCK QUERIES THAT ACCESS SENSITIVE COLUMNS!**
        if features["contains_sensitive_column"][0] == 1:
            print(f"❌ [FIREWALL] Sensitive Column Access Detected! Blocking Query: {query}")
            block_ip(user_ip)
            abort(403)

        prediction_proba = model.predict_proba(features)[0]
        prediction = model.predict(features)[0]

        print(f"🔍 Query Features: {features}")
        print(f"🔍 Model Prediction: {prediction}, Probability: {prediction_proba}")

        # 🚨 Block if ML Model Confidence ≥ 70%
        if prediction == 1 and prediction_proba[1] >= 0.70:
            print(f"❌ [FIREWALL] SQL Injection Detected! Blocking Query: {query}")
            block_ip(user_ip)
            abort(403)

        return True  

    except Exception as e:
        print(f"🔥 [FIREWALL] Error: {e}")
        return False  
