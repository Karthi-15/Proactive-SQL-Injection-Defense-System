# import pandas as pd
# import re
# import nltk
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.model_selection import train_test_split
# from sklearn.metrics import accuracy_score, classification_report
# import joblib
# from tqdm import tqdm

# nltk.download('punkt')

# # ✅ Define SQL-related keywords & special characters
# SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "OR", "AND", "--", "#", "ALTER", "EXEC"]
# SPECIAL_CHARACTERS = ["'", '"', ";", "--", "#", "(", ")", "="]

# def preprocess_query(query):
#     """Cleans and normalizes SQL queries."""
#     return re.sub(r"[^a-zA-Z0-9\s]", " ", query).lower()

# def count_sql_keywords(query):
#     return sum(query.upper().count(keyword) for keyword in SQL_KEYWORDS)

# def count_special_characters(query):
#     return sum(1 for char in query if char in SPECIAL_CHARACTERS)

# def extract_features(df):
#     """Extracts numerical features for ML classification."""
#     tqdm.pandas()
#     df["query_cleaned"] = df["query"].progress_apply(preprocess_query)
#     df["length"] = df["query"].apply(len)
#     df["keyword_count"] = df["query"].apply(count_sql_keywords)
#     df["special_character_count"] = df["query"].apply(count_special_characters)

#     return df[["length", "keyword_count", "special_character_count"]], df["label"]

# def train_model():
#     """Trains the Random Forest model for SQL injection detection."""

#     # ✅ Load dataset (Ensure it contains real-world SQL queries)
#     df = pd.read_csv("query_dataset_BA (1).csv")  

#     # ✅ Add more SQL Injection examples
#     attack_queries = [
#         "SELECT username, password FROM users WHERE id=1 UNION SELECT username, password FROM users;",
#         "SELECT * FROM users WHERE username='admin' OR 1=1;",
#         "SELECT id, username, password FROM accounts WHERE id=1 OR '1'='1';",
#         "SELECT * FROM customers WHERE email='hacker@xyz.com' OR 'a'='a';",
#         "SELECT password FROM users WHERE email='victim@xyz.com';",
#         "SELECT * FROM accounts WHERE username='' OR '1'='1';",
#         "UNION SELECT username, password FROM admin;",
#         "DROP TABLE users;",
#         "INSERT INTO users (username, password) VALUES ('hacker', '1234');"
#     ]
#     attack_labels = [1] * len(attack_queries)  # 1 = Malicious
#     additional_data = pd.DataFrame({"query": attack_queries, "label": attack_labels})

#     df = pd.concat([df, additional_data])

#     # ✅ Ensure dataset balance
#     safe_queries = df[df["label"] == 0]
#     malicious_queries = df[df["label"] == 1]
#     min_count = min(len(safe_queries), len(malicious_queries))
#     df_balanced = pd.concat([safe_queries.sample(min_count), malicious_queries.sample(min_count)])

#     # ✅ Train model dynamically based on dataset
#     X, y = extract_features(df_balanced)
#     X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

#     rf_model = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42)
#     rf_model.fit(X_train, y_train)

#     y_pred = rf_model.predict(X_test)
#     accuracy = accuracy_score(y_test, y_pred)
#     print(f"✅ Model Accuracy: {accuracy * 100:.2f}%")
#     print(classification_report(y_test, y_pred))

#     joblib.dump(rf_model, "models/random_forest_sqli_model.pkl")

# if __name__ == "__main__":
#     train_model()

import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score, classification_report

# ✅ Load Dataset
print("📂 Loading dataset...")
df = pd.read_csv("sql_injection_unique_dataset.csv")

# ✅ Extract Features (Must Match `python_firewall.py`)
def extract_features(df):
    SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "ALTER", "EXEC", "OR", "AND"]
    SPECIAL_CHARACTERS = ["'", '"', ";", "--", "#", "(", ")", "="]
    SENSITIVE_COLUMNS = ["password", "user_id", "card_number", "ssn", "credit_card"]

    df["length"] = df["query"].apply(len)
    df["keyword_count"] = df["query"].apply(lambda q: sum(q.upper().count(word) for word in SQL_KEYWORDS))
    df["special_character_count"] = df["query"].apply(lambda q: sum(1 for char in q if char in SPECIAL_CHARACTERS))
    
    # ✅ Block queries targeting **any sensitive column**
    df["contains_sensitive_column"] = df["query"].apply(lambda q: int(any(col in q.lower() for col in SENSITIVE_COLUMNS)))

    df["contains_select_star"] = df["query"].apply(lambda q: int("SELECT *" in q.upper()))
    df["contains_union"] = df["query"].apply(lambda q: int("UNION SELECT" in q.upper()))
    df["contains_or_true"] = df["query"].apply(lambda q: int("OR 1=1" in q.upper()))
    df["contains_update_delete"] = df["query"].apply(lambda q: int(any(x in q.upper() for x in ["UPDATE", "DELETE", "DROP"])))

    return df[["length", "keyword_count", "special_character_count", "contains_sensitive_column", "contains_select_star", "contains_union", "contains_or_true", "contains_update_delete"]], df["label"]

# ✅ Extract Features & Labels
X, y = extract_features(df)

# ✅ Balance Data (Ensure Equal Malicious & Safe Queries)
safe_queries = df[df["label"] == 0]
malicious_queries = df[df["label"] == 1]
min_count = min(len(safe_queries), len(malicious_queries))
df_balanced = pd.concat([safe_queries.sample(min_count, random_state=42), malicious_queries.sample(min_count, random_state=42)])

X_balanced, y_balanced = extract_features(df_balanced)

# ✅ Split Data into Training & Test Sets
X_train, X_test, y_train, y_test = train_test_split(X_balanced, y_balanced, test_size=0.2, random_state=42, stratify=y_balanced)

# ✅ Hyperparameter Tuning with GridSearchCV
print("🔍 Finding the best parameters...")
param_grid = {
    'n_estimators': [100, 200, 300],  
    'max_depth': [10, 20, None],  
    'min_samples_split': [2, 5],  
    'min_samples_leaf': [1, 2],  
}

rf_model = RandomForestClassifier(random_state=42)
grid_search = GridSearchCV(rf_model, param_grid, cv=3, verbose=2, n_jobs=-1)
grid_search.fit(X_train, y_train)

# ✅ Get the Best Model
best_model = grid_search.best_estimator_
print(f"✅ Best Model: {grid_search.best_params_}")

# ✅ Train the Best Model
print("🚀 Training the best model on full dataset...")
best_model.fit(X_train, y_train)

# ✅ Evaluate the Model
y_pred = best_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n✅ Model Accuracy: {accuracy * 100:.2f}%")
print("\n📊 Confusion Matrix:\n", pd.crosstab(y_test, y_pred, rownames=['Actual'], colnames=['Predicted']))
print("\n📄 Classification Report:\n", classification_report(y_test, y_pred))

# ✅ Save the Model
joblib.dump(best_model, "models/random_forest_sqli_model.pkl")
print("\n✅ Model saved successfully as 'models/random_forest_sqli_model.pkl'")
