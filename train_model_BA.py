import pandas as pd
import re
import nltk
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score, classification_report
import joblib
from tqdm import tqdm

nltk.download('punkt')


SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "OR", "AND", "--", "#", "ALTER", "EXEC"]
SPECIAL_CHARACTERS = ["'", '"', ";", "--", "#", "(", ")", "="]
DANGEROUS_PATTERNS = ["OR 1=1", "UNION SELECT", "DROP TABLE", "INSERT INTO users", "UPDATE users SET"]


def preprocess_query(query):
    return re.sub(r"[^a-zA-Z0-9\s]", " ", query).lower()


def count_sql_keywords(query):
    return sum(query.upper().count(keyword) for keyword in SQL_KEYWORDS)

def count_special_characters(query):
    return sum(1 for char in query if char in SPECIAL_CHARACTERS)

def count_dangerous_patterns(query):
    return sum(1 for pattern in DANGEROUS_PATTERNS if pattern in query.upper())

def extract_features(df):
    tqdm.pandas()
    df["query_cleaned"] = df["query"].progress_apply(preprocess_query)
    df["length"] = df["query"].apply(len)
    df["keyword_count"] = df["query"].apply(count_sql_keywords)
    df["special_character_count"] = df["query"].apply(count_special_characters)
    df["dangerous_pattern_count"] = df["query"].apply(count_dangerous_patterns)
    return df[["length", "keyword_count", "special_character_count", "dangerous_pattern_count"]], df["label"]


def train_model():
    df = pd.read_csv("query_dataset_BA (1).csv")
    X, y = extract_features(df)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [None, 10, 20],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2]
    }

    rf_model = RandomForestClassifier(random_state=42)
    grid_search = GridSearchCV(rf_model, param_grid, cv=3, verbose=2, n_jobs=-1)
    grid_search.fit(X_train, y_train)

    best_model = grid_search.best_estimator_

    y_pred = best_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"✅ Best Model Accuracy: {accuracy * 100:.2f}%")
    print(classification_report(y_test, y_pred))

    joblib.dump(best_model, "models/random_forest_sqli_model.pkl")

if __name__ == "__main__":
    train_model()
