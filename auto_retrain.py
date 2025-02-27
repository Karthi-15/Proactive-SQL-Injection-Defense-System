import sqlite3
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

def get_feedback_data():
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT query, actual_label FROM feedback_log WHERE actual_label IS NOT NULL")
    data = cursor.fetchall()
    conn.close()
    return pd.DataFrame(data, columns=["query", "label"])

def extract_features(df):
    SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "OR", "AND", "--", "#"]
    SPECIAL_CHARACTERS = ["'", '"', ";", "--", "#"]

    df["length"] = df["query"].apply(len)
    df["keyword_count"] = df["query"].apply(lambda q: sum(q.upper().count(k) for k in SQL_KEYWORDS))
    df["special_character_count"] = df["query"].apply(lambda q: sum(1 for c in q if c in SPECIAL_CHARACTERS))
    df["label"] = df["label"].map({"Safe": 0, "Malicious": 1})

    return df[["length", "keyword_count", "special_character_count"]], df["label"]

def retrain_model():
    df = get_feedback_data()
    if len(df) < 10:
        print("✅ Not enough new feedback data for retraining. Minimum 10 required.")
        return

    X, y = extract_features(df)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    rf_model = RandomForestClassifier(n_estimators=200, random_state=42)
    rf_model.fit(X_train, y_train)
    y_pred_rf = rf_model.predict(X_test)

    # print(f"✅ Model Retrained. New Accuracy: {accuracy_score(y_test, y_pred_rf) * 100:.2f}%")
    joblib.dump(rf_model, "models/random_forest_sqli_model.pkl")
    print("✅ Model saved successfully!")

if __name__ == "__main__":
    retrain_model()
