import sqlite3
import sqlparse
import random
import re
import joblib
import pandas as pd
import numpy as np
import xgboost as xgb
from faker import Faker
from tensorflow.keras.models import load_model
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler


def log_feedback(query, predicted_label):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO feedback_log (query, predicted_label) VALUES (?, ?)", (query, predicted_label))
    conn.commit()
    conn.close()

rf_model = joblib.load("models/random_forest_sqli_model.pkl")
xgb_model = joblib.load("models/xgboost_anomaly_model.pkl")
mlp_model = load_model("models/mlp_anomaly_model.h5")
vectorizer = joblib.load("models/tfidf_vectorizer.pkl")
scaler = joblib.load("models/scaler.pkl")


fake = Faker()


SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "OR", "AND", "--", "#"]
SPECIAL_CHARACTERS = ["'", '"', ";", "--", "#"]


class QueryMutationEngine:
    def __init__(self, query):
        self.query = query

    def mutate(self):
        mutations = [
            self.query.replace("=", " OR 1=1"),
            self.query + " -- SQL Injection Test",
            self.query + " UNION SELECT username, password FROM users;",
            self.query.replace("'admin'", f"'{fake.user_name()}'"),
            self.query.replace(" ", "   ").replace("AND", "\nAND"),
            self.query.replace("SELECT", "S%E%L%E%C%T").replace("UNION", "U%N%I%O%N"),
            f"SELECT * FROM ({self.query}) AS subquery;"
        ]
        return mutations

def extract_features(query):
    return pd.DataFrame([{ 
        "length": len(query), 
        "keyword_count": sum(query.upper().count(keyword) for keyword in SQL_KEYWORDS),
        "special_character_count": sum(1 for char in query if char in SPECIAL_CHARACTERS)
    }])


def detect_sqli(query):
    features = extract_features(query)
    prediction = rf_model.predict(features)[0]
    return "Malicious" if prediction == 1 else "Safe"

def detect_anomaly(query):
    tfidf_features = vectorizer.transform([query]).toarray()
    numeric_features = np.array([
        [
            len(query),
            sum(1 for char in query if char in SPECIAL_CHARACTERS),
            sum(query.upper().count(keyword) for keyword in SQL_KEYWORDS),
            len(QueryMutationEngine(query).mutate()),
            0.5,  # Placeholder for anomaly score
            0.3,  # Placeholder for special char ratio
            0.2,  # Placeholder for keyword density
            0.1   # Placeholder for lexical diversity
        ]
    ])
    X = np.hstack((tfidf_features, numeric_features))
    X_scaled = scaler.transform(X)
    pred_xgb = xgb_model.predict(X_scaled)
    pred_mlp = (mlp_model.predict(X_scaled) > 0.5).astype(int).flatten()
    final_pred = (pred_xgb + pred_mlp) / 2 > 0.5
    return "Anomalous" if final_pred else "Normal"


def analyze_query(query):
    print(f"\n🔹 Input Query: {query}")
    
    
    qme = QueryMutationEngine(query)
    mutations = qme.mutate()
    print(f"\n🔹 Mutated Queries:")
    for i, mut in enumerate(mutations, 1):
        print(f"{i}. {mut}")
    
    
    sqli_result = detect_sqli(query)
    print(f"\n🔍 SQL Injection Detection Result: {sqli_result}")
    
    
    anomaly_result = detect_anomaly(query)
    
    
    final_status = "Safe"
    if sqli_result == "Malicious" or anomaly_result == "Anomalous":
        final_status = "Malicious"
        print("\n❌ Query is Unsafe!")
    else:
        print("\n✅ Query is Safe.")
    
    
    log_feedback(query, final_status)

if __name__ == "__main__":
    while True:
        user_query = input("\n🔹 Enter an SQL Query (or type 'exit' to quit): ")
        if user_query.lower() == "exit":
            break
        analyze_query(user_query)
