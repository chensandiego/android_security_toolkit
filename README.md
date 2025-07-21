# Android Security Toolkit

This toolkit analyzes Android APK files to identify potential security threats. It uses a combination of static feature analysis, machine learning classification, and a recommendation-based approach that compares an APK's "behavioral fingerprint" to a knowledge base of known malicious and benign applications.

## Features

-   **APK Feature Extraction:** Extracts permissions, activities, services, and receivers from APK files.
-   **Hardcoded Secret Detection:** Identifies hardcoded secrets like API keys, passwords, and sensitive URLs within the APK.
-   **Library Identification & Vulnerability Scanning:** Detects common third-party libraries and checks them against the National Vulnerability Database (NVD) for up-to-date threat information using the latest NVD API 2.0.
-   **Static Code Analysis for Vulnerabilities:** Performs static analysis to identify common Android vulnerabilities, including:
    -   Insecure communication (e.g., cleartext HTTP).
    -   Insecure data storage (e.g., `android:allowBackup="true"`, world-readable/writable files).
    -   WebView misconfigurations (e.g., `setJavaScriptEnabled(true)`, `addJavascriptInterface`).
    -   SSL/TLS Insecurity (e.g., custom hostname verifiers, custom trust managers, SSL error handling).
-   **Suspicious API Call Detection:** Scans for an expanded set of potentially dangerous API calls, including those related to SMS, runtime execution, reflection, dynamic code loading, root detection, and more.
-   **Network Indicators Extraction:** Identifies and extracts URLs and IP addresses embedded within the APK, which can serve as indicators of command-and-control servers or data exfiltration points.
-   **Behavioral Fingerprinting:** Creates a unique fingerprint for each APK based on its features, incorporating a rich set of features including permissions, activities, services, receivers, hardcoded secrets, identified libraries, detected vulnerabilities, and network indicators.
-   **Similarity Analysis:** Compares the fingerprint of an uploaded APK to a knowledge base of known APKs.
-   **Advanced Machine Learning Classification:** Uses a `GradientBoostingClassifier` to classify APKs as benign, potentially malicious, or high-risk. The model is trained on a more descriptive feature set, including:
    -   Counts of components (permissions, activities, etc.).
    -   Ratio of dangerous permissions.
    -   Ratio of native code.
    -   Number of suspicious API calls.
    -   Counts of network indicators (URLs and IPs).
-   **Enhanced Web Interface:** A redesigned, user-friendly web interface for uploading APKs and viewing detailed, organized analysis reports with visual aids.

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
