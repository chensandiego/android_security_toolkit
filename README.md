# Android Security Toolkit

This toolkit analyzes Android APK files to identify potential security threats. It uses a combination of static feature analysis, machine learning classification, and a recommendation-based approach that compares an APK's "behavioral fingerprint" to a knowledge base of known malicious and benign applications.

## Features

-   **APK Feature Extraction:** Extracts permissions, activities, services, and receivers from APK files.
-   **Hardcoded Secret Detection:** Identifies hardcoded secrets like API keys, passwords, and sensitive URLs within the APK.
-   **Library Identification:** Detects common third-party libraries used in the APK.
-   **Vulnerability Scanning:** Checks identified libraries against a simplified local vulnerability database for known issues.
-   **Behavioral Fingerprinting:** Creates a unique fingerprint for each APK based on its features.
-   **Similarity Analysis:** Compares the fingerprint of an uploaded APK to a knowledge base of known APKs.
-   **Machine Learning Classification:** Uses a machine learning model to classify APKs as benign, malicious, or suspicious.

## Project Setup

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd android_security_toolkit
    ```

2.  **Create a virtual environment and install dependencies:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

## Building the Knowledge Base (Recommended)

To achieve accurate detection, you need to build a knowledge base of APK fingerprints from a dataset of known malicious and benign applications. The following steps use the **CIC-MalDroid-2020 dataset** as an example.

**Step 1: Download the APK Archives**

Go to the following URL and download the categorized archives:
`http://cicresearch.ca/CICDataset/MalDroid-2020/Dataset/APKs/`

Download the following files:
*   `Benign.tar.gz`
*   `Adware.tar.gz`
*   `Banking.tar.gz`
*   `Riskware.tar.gz`
*   `SMS2.tar.gz`

**Step 2: Organize and Extract the Archives**

Create a directory (e.g., `apk_dataset`) and move the downloaded files into it. Then, from within the `apk_dataset` directory, run the following commands:

```bash
# Create directories for each category
mkdir Benign Adware Banking Riskware SMS

# Extract each archive into its corresponding directory
tar -xzvf Benign.tar.gz -C Benign/
tar -xzvf Adware.tar.gz -C Adware/
tar -xzvf Banking.tar.gz -C Banking/
tar -xzvf Riskware.tar.gz -C Riskware/
tar -xzvf SMS2.tar.gz -C SMS/
```

**Step 3: Generate the Fingerprints**

A script named `build_knowledge_base.py` is provided to automate the analysis. Before running it, you **must** edit the script and update the `DATASET_BASE_DIR` variable to the **absolute path** of your `apk_dataset` directory.

Once you have edited the script, run it from the `android_security_toolkit` directory:

```bash
# Make sure your virtual environment is activated
source venv/bin/activate

# Run the script (this will take a very long time)
python build_knowledge_base.py
```

**Step 4: Activate the New Knowledge Base**

When the script is finished, it will create a file named `known_apks_generated.json`. To use it, rename this file to `known_apks.json`, which will replace the existing placeholder file.

```bash
# This replaces the old placeholder with your new, comprehensive knowledge base
mv known_apks_generated.json known_apks.json
```

## Running the Application

Once the setup is complete and you have built your knowledge base, you can run the web application:

```bash
# Make sure your virtual environment is activated
source venv/bin/activate

# Run the main application
python main.py
```

The application will be available at `http://127.0.0.1:8000`. You can upload an APK file through the web interface to have it analyzed.
