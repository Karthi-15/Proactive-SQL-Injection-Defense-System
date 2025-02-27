import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from imblearn.over_sampling import SMOTE
from tensorflow.keras.models import Sequential, save_model
from tensorflow.keras.layers import Dense, Dropout
import joblib


df = pd.read_csv("anomaly_detection_dataset.csv", encoding="utf-8")


expected_columns = ["Query_String", "Length", "Special_Chars", "Keyword_Count", "Mutation_Count", "Anomaly_Score", "Label"]
missing_columns = [col for col in expected_columns if col not in df.columns]
if missing_columns:
    raise ValueError(f"Missing columns in dataset: {missing_columns}. Please check the dataset.")


vectorizer = TfidfVectorizer(max_features=1000)
tfidf_features = vectorizer.fit_transform(df["Query_String"]).toarray()


df["Special_Char_Ratio"] = df["Special_Chars"] / (df["Mutation_Count"] + 1)
df["Keyword_Density"] = df["Keyword_Count"] / (df["Mutation_Count"] + 1)
df["Lexical_Diversity"] = df["Mutation_Count"] / (df["Special_Chars"] + 1)

features = ["Length", "Special_Chars", "Keyword_Count", "Mutation_Count", "Anomaly_Score", "Special_Char_Ratio", "Keyword_Density", "Lexical_Diversity"]
numeric_features = df[features].values
X = np.hstack((tfidf_features, numeric_features))
y = df["Label"]


label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)


scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)


smote = SMOTE(sampling_strategy="auto", random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_scaled, y)


X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.2, random_state=42)


xgb_model = xgb.XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.05, random_state=42)
xgb_model.fit(X_train, y_train)
y_pred_xgb = xgb_model.predict(X_test)


mlp_model = Sequential([
    Dense(512, activation="relu", input_shape=(X_train.shape[1],)),
    Dropout(0.2),
    Dense(256, activation="relu"),
    Dropout(0.2),
    Dense(1, activation="sigmoid")
])
mlp_model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
mlp_model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.2, verbose=1)


y_pred_mlp = (mlp_model.predict(X_test) > 0.5).astype(int).flatten()


final_pred = (y_pred_xgb + y_pred_mlp) / 2
final_pred = (final_pred > 0.5).astype(int)


accuracy_final = accuracy_score(y_test, final_pred)
classification_rep_final = classification_report(y_test, final_pred, target_names=["Safe", "Malicious"])

print(f"\n✅ Hybrid Model (XGBoost + MLP) Accuracy: {accuracy_final * 100:.2f}%")
print("\nClassification Report:\n", classification_rep_final)


joblib.dump(xgb_model, "models/xgboost_anomaly_model.pkl")
mlp_model.save("models/mlp_anomaly_model.h5")
joblib.dump(vectorizer, "models/tfidf_vectorizer.pkl")
joblib.dump(scaler, "models/scaler.pkl")

print("\n✅ Models and preprocessing tools saved successfully!")
