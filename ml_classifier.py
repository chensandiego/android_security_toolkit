
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

MODEL_PATH = "ml_model.joblib"

def get_placeholder_model():
    # Sample data with more features
    # Features: num_permissions, num_activities, num_hardcoded_secrets, num_identified_libraries,
    # num_insecure_communication, num_insecure_data_storage, num_webview_vulnerabilities
    X = [
        [10, 5, 0, 3, 0, 0, 0],  # Benign
        [20, 10, 2, 5, 1, 1, 0], # Potentially Malicious
        [30, 15, 5, 8, 2, 2, 1], # Intent Attack Suspected
        [25, 12, 3, 6, 1, 1, 0]  # Potentially Malicious
    ]
    y = [0, 1, 2, 1] # 0: Benign, 1: Potentially Malicious, 2: Intent Attack Suspected
    model = RandomForestClassifier(random_state=42)
    model.fit(X, y)
    joblib.dump(model, MODEL_PATH)
    return model

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    model = get_placeholder_model()

def classify_apk(features, similarity_score, similar_label):
    # High similarity to a known malicious APK should be flagged immediately
    if similar_label == "Malicious" and similarity_score > 0.8:
        return "High-Risk Malware (High Similarity)"
    
    if similar_label == "Intent Attack" and similarity_score > 0.8:
        return "High-Risk Intent Attack (High Similarity)"

    num_permissions = len(features.get("permissions", []))
    num_activities = len(features.get("activities", []))
    num_hardcoded_secrets = sum(len(v) for v in features.get("hardcoded_secrets", {}).values())
    num_identified_libraries = len(features.get("identified_libraries", []))
    num_insecure_communication = len(features.get("insecure_communication", []))
    num_insecure_data_storage = len(features.get("insecure_data_storage", []))
    num_webview_vulnerabilities = len(features.get("webview_vulnerabilities", []))

    # Create a feature vector with expanded features
    feature_vector = [[
        num_permissions,
        num_activities,
        num_hardcoded_secrets,
        num_identified_libraries,
        num_insecure_communication,
        num_insecure_data_storage,
        num_webview_vulnerabilities
    ]]

    # Predict
    prediction = model.predict(feature_vector)
    
    # Map prediction to a meaningful label
    labels = {0: "Benign", 1: "Potentially Malicious", 2: "Intent Attack Suspected"}
    return labels.get(prediction[0], "Unknown")
