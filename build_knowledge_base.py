import os
import json
import sys
from apk_analyzer import analyze_apk_features
from tqdm import tqdm

# --- IMPORTANT ---
# EDIT THIS PATH to point to the directory where you extracted the APKs.
# Use the absolute path to avoid errors.
DATASET_BASE_DIR = "/Users/chen/Desktop/apk_dataset" # <-- EDIT THIS

# Categories are based on the directory names from Step 3
CATEGORIES = {
    "Benign": "Benign",
    "Adware": "Malicious",
    "Banking": "Malicious",
    "Riskware": "Malicious",
    "SMS": "Malicious"
}

def process_apks_in_directory(dir_path, label):
    """Processes all APKs in a given directory and returns a list of fingerprints."""
    fingerprints = []
    print(f"\nProcessing {label} APKs in {dir_path}...")
    
    if not os.path.isdir(dir_path):
        print(f"Warning: Directory not found: {dir_path}")
        return []

    apk_files = [f for f in os.listdir(dir_path) if f.endswith(".apk")]
    
    for apk_file in tqdm(apk_files, desc=f"Analyzing {label}"):
        apk_path = os.path.join(dir_path, apk_file)
        try:
            # Analyze the APK to get its features
            features = analyze_apk_features(apk_path)
            
            # Create the fingerprint entry
            fingerprints.append({
                "label": label,
                "features": features
            })
        except Exception as e:
            # Log errors for specific files but continue the process
            print(f"\nError processing {apk_path}: {e}")
            
    return fingerprints

def main():
    """Main function to build the entire knowledge base."""
    all_fingerprints = []
    
    for category_dir, label in CATEGORIES.items():
        full_path = os.path.join(DATASET_BASE_DIR, category_dir)
        category_fingerprints = process_apks_in_directory(full_path, label)
        all_fingerprints.extend(category_fingerprints)

    # Define the output file path
    output_file = os.path.join(os.path.dirname(__file__), "known_apks_generated.json")

    print(f"\nSaving {len(all_fingerprints)} fingerprints to {output_file}...")
    
    # Save the combined list of fingerprints to the JSON file
    with open(output_file, "w") as f:
        json.dump(all_fingerprints, f, indent=4)
        
    print("\nKnowledge base built successfully!")
    print(f"File saved at: {output_file}")

if __name__ == "__main__":
    # Add the project directory to the path to allow importing apk_analyzer
    sys.path.append(os.path.dirname(__file__))
    main()
