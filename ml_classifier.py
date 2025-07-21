
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
import joblib
import os

MODEL_PATH = "ml_model.joblib"

def get_trained_model():
    # A more realistic, albeit still sample, dataset
    data = {
        'num_permissions': [10, 25, 30, 15, 12, 40, 5, 50],
        'num_activities': [5, 10, 15, 8, 6, 20, 3, 25],
        'num_hardcoded_secrets': [0, 2, 5, 1, 0, 7, 0, 10],
        'num_identified_libraries': [3, 5, 8, 4, 2, 12, 1, 15],
        'num_insecure_communication': [0, 1, 2, 1, 0, 3, 0, 4],
        'num_insecure_data_storage': [0, 1, 2, 0, 0, 3, 0, 5],
        'num_webview_vulnerabilities': [0, 0, 1, 0, 0, 2, 0, 3],
        'dangerous_permissions_ratio': [0.1, 0.4, 0.6, 0.2, 0.1, 0.7, 0.05, 0.8],
        'native_code_ratio': [0.0, 0.1, 0.2, 0.05, 0.0, 0.3, 0.0, 0.5],
        'num_suspicious_api_calls': [0, 5, 10, 2, 1, 15, 0, 20],
        'num_urls': [0, 3, 7, 1, 0, 10, 0, 12],
        'num_ips': [0, 1, 3, 0, 0, 5, 0, 6],
        'label': [0, 1, 2, 1, 0, 2, 0, 2]  # 0: Benign, 1: Potentially Malicious, 2: High-Risk
    }
    df = pd.DataFrame(data)
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Using a more advanced model like Gradient Boosting
    model = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42)
    model.fit(X, y)
    joblib.dump(model, MODEL_PATH)
    return model

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    model = get_trained_model()

def classify_apk(features, similarity_score, similar_label):
    if similar_label == "Malicious" and similarity_score > 0.8:
        return "High-Risk Malware (High Similarity)"
    if similar_label == "Intent Attack" and similarity_score > 0.8:
        return "High-Risk Intent Attack (High Similarity)"

    num_permissions = len(features.get("permissions", []))
    dangerous_permissions = [p for p in features.get("permissions", []) if 'DANGEROUS' in p]
    dangerous_permissions_ratio = len(dangerous_permissions) / num_permissions if num_permissions > 0 else 0
    
    # Placeholder for native code detection - this would require a more complex analysis
    native_code_ratio = 0.1 # Assuming a baseline

    feature_vector = pd.DataFrame([{
        'num_permissions': num_permissions,
        'num_activities': len(features.get("activities", [])),
        'num_hardcoded_secrets': sum(len(v) for v in features.get("hardcoded_secrets", {}).values()),
        'num_identified_libraries': len(features.get("identified_libraries", [])),
        'num_insecure_communication': len(features.get("insecure_communication", [])),
        'num_insecure_data_storage': len(features.get("insecure_data_storage", [])),
        'num_webview_vulnerabilities': len(features.get("webview_vulnerabilities", [])),
        'dangerous_permissions_ratio': dangerous_permissions_ratio,
        'native_code_ratio': native_code_ratio,
        'num_suspicious_api_calls': len(features.get("suspicious_api_calls", [])),
        'num_urls': len(features.get("network_indicators", {}).get("urls", [])),
        'num_ips': len(features.get("network_indicators", {}).get("ips", []))
    }])

    prediction = model.predict(feature_vector)
    labels = {0: "Benign", 1: "Potentially Malicious", 2: "High-Risk"}
    return labels.get(prediction[0], "Unknown")
