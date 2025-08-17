import os
import json
import sys
import concurrent.futures
from apk_analyzer import analyze_apk_features
from tqdm import tqdm

# --- IMPORTANT ---
# EDIT THIS PATH to point to the directory where you extracted the APKs.
# Use the absolute path to avoid errors.
DATASET_BASE_DIR = "/Users/chen/Desktop/android_security_toolkit/apk_dataset" # <-- EDIT THIS

# Categories are based on the directory names from Step 3
CATEGORIES = {
    "Benign": "Benign",
    "Adware": "Malicious",
    "Riskware": "Malicious",
    "SMS": "Malicious"
}

def analyze_single_apk(apk_path):
    """Analyzes a single APK and returns its features."""
    try:
        return analyze_apk_features(apk_path)
    except Exception as e:
        print(f"
Error processing {apk_path}: {e}")
        return None

def process_apks_in_directory(dir_path, label, processed_apks):
    """Processes all APKs in a given directory in parallel and returns a list of fingerprints."""
    fingerprints = []
    
    if not os.path.isdir(dir_path):
        print(f"Warning: Directory not found: {dir_path}")
        return []

    apk_files_to_process = [
        os.path.join(dir_path, f) for f in os.listdir(dir_path) 
        if not f.startswith('.') and os.path.join(dir_path, f) not in processed_apks
    ]

    if not apk_files_to_process:
        print(f"
All APKs in {dir_path} already processed. Skipping.")
        return []

    print(f"
Processing {len(apk_files_to_process)} new APKs in {dir_path}...")

    with concurrent.futures.ProcessPoolExecutor() as executor:
        future_to_apk = {executor.submit(analyze_single_apk, apk_path): apk_path for apk_path in apk_files_to_process}
        
        for future in tqdm(concurrent.futures.as_completed(future_to_apk), total=len(apk_files_to_process), desc=f"Analyzing {label}"):
            apk_path = future_to_apk[future]
            try:
                features = future.result()
                if features:
                    fingerprints.append({
                        "file_path": apk_path,
                        "label": label,
                        "features": features
                    })
            except Exception as e:
                print(f"
Error processing {apk_path}: {e}")
                
    return fingerprints

def main():    """Main function to build the entire knowledge base."""    output_file = os.path.join(os.path.dirname(__file__), "known_apks_generated.json")    all_fingerprints = []    processed_apks = set()    # Load existing data if it exists    if os.path.exists(output_file):        with open(output_file, "r") as f:            try:                all_fingerprints = json.load(f)                processed_apks = {fp.get("file_path") for fp in all_fingerprints if "file_path" in fp}                print(f"Loaded {len(all_fingerprints)} existing fingerprints. {len(processed_apks)} APKs already processed.")            except json.JSONDecodeError:                print("Warning: Could not decode existing JSON file. Starting fresh.")                all_fingerprints = []                processed_apks = set()    with concurrent.futures.ThreadPoolExecutor() as executor:        future_to_label = {            executor.submit(process_apks_in_directory, os.path.join(DATASET_BASE_DIR, category_dir), label, processed_apks): label            for category_dir, label in CATEGORIES.items()        }                for future in concurrent.futures.as_completed(future_to_label):            label = future_to_label[future]            try:                category_fingerprints = future.result()                if category_fingerprints:                    all_fingerprints.extend(category_fingerprints)                    print(f"
Saving {len(all_fingerprints)} total fingerprints to {output_file} after processing '{label}'...")                    with open(output_file, "w") as f:                        json.dump(all_fingerprints, f, indent=4)            except Exception as e:                print(f"
Error processing category for label {label}: {e}")    print(f"
Final save of {len(all_fingerprints)} fingerprints to {output_file}...")    with open(output_file, "w") as f:        json.dump(all_fingerprints, f, indent=4)        print("
Knowledge base built successfully!")    print(f"File saved at: {output_file}")

if __name__ == "__main__":
    sys.path.append(os.path.dirname(__file__))
    main()
