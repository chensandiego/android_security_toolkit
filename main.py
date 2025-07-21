import uvicorn
from fastapi import FastAPI, File, UploadFile, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import shutil
import os
from apk_analyzer import analyze_apk_features
from ml_classifier import classify_apk
from behavioral_fingerprint import fingerprint_model

# Create a directory for uploads if it doesn't exist
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze")
async def analyze_apk_endpoint(file: UploadFile = File(...)):
    # Save the uploaded file
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Analyze the APK
    features = analyze_apk_features(file_path)

    # Get behavioral similarity
    similarity_score, similar_label = fingerprint_model.get_similarity(features)

    # Classify the APK
    classification = classify_apk(features, similarity_score, similar_label)

    # Return the results
    return {
        "filename": file.filename,
        "classification": classification,
        "similarity": f"{similarity_score:.2f} to a known '{similar_label}' APK",
        "features": {
            "permissions": features["permissions"],
            "activities": features["activities"],
            "services": features["services"],
            "receivers": features["receivers"],
            "hardcoded_secrets": features["hardcoded_secrets"],
            "identified_libraries": features["identified_libraries"],
            "vulnerabilities": features["vulnerabilities"],
            "insecure_communication": features["insecure_communication"],
            "insecure_data_storage": features["insecure_data_storage"],
            "webview_vulnerabilities": features["webview_vulnerabilities"],
            "suspicious_api_calls": features["suspicious_api_calls"],
            "network_indicators": features["network_indicators"]
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
