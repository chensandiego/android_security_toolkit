import re
import requests
from androguard.misc import AnalyzeAPK
from taint_analyzer import TaintAnalyzer

def find_hardcoded_secrets(apk_object):
    secrets_found = {}
    secret_patterns = {
        "API_KEY": r"(?i)(api_key|apikey|x-api-key|access_token|auth_token|client_secret|secret_key|bearer)[^a-zA-Z0-9]{0,20}([a-zA-Z0-9_-]{16,64})",
        "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
        "AWS_SECRET_KEY": r"([0-9a-zA-Z\/+]{40})",
        "GOOGLE_API_KEY": r"AIza[0-9A-Za-z-_]{35}",
        "FIREBASE_API_KEY": r"AIza[0-9A-Za-z-_]{35}",
        "PASSWORD": r"(?i)(password|pwd|pass)[^a-zA-Z0-9]{0,20}([a-zA-Z0-9!@#$%^&*()_+-={}\[\]:;\"'<>,.?/\\|]{8,64})",
        "URL_CREDENTIALS": r"(https?:\/\/[^\s\/$.?#].[^\s]*?[:][^\s]*?@)",
        "PRIVATE_KEY": r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----",
        "SSH_KEY": r"ssh-rsa AAAA[0-9A-Za-z+\/]{100,}",
        "GENERIC_TOKEN": r"(?i)(token|auth|secret)[^a-zA-Z0-9]{0,20}([a-zA-Z0-9_-]{20,128})"
    }
    try:
        manifest_xml = apk_object.get_android_manifest_xml()
        from lxml import etree
        manifest_content = etree.tostring(manifest_xml, encoding='utf-8').decode('utf-8')
        for secret_type, pattern in secret_patterns.items():
            found = re.findall(pattern, manifest_content)
            if found:
                if "AndroidManifest.xml" not in secrets_found:
                    secrets_found["AndroidManifest.xml"] = {}
                secrets_found["AndroidManifest.xml"][secret_type] = found
    except Exception as e:
        print(f"Error reading AndroidManifest.xml: {e}")
    for file_name in apk_object.get_files():
        if file_name.endswith('.xml') and file_name != 'AndroidManifest.xml':
            try:
                file_content = apk_object.get_file(file_name).decode('utf-8', errors='ignore')
                for secret_type, pattern in secret_patterns.items():
                    found = re.findall(pattern, file_content)
                    if found:
                        if file_name not in secrets_found:
                            secrets_found[file_name] = {}
                        secrets_found[file_name][secret_type] = found
            except Exception as e:
                print(f"Error reading file {file_name}: {e}")
    return secrets_found

def identify_libraries(dx_object):
    identified_libraries = set()
    common_library_prefixes = [
        "Lcom/google/android/gms/", "Lcom/google/firebase/", "Landroidx/", "Lcom/facebook/",
        "Lcom/squareup/", "Lio/reactivex/", "Lorg/apache/", "Lcom/unity3d/", "Lcom/adjust/",
        "Lcom/appsflyer/", "Lcom/crashlytics/", "Lcom/mixpanel/", "Lcom/segment/",
        "Lorg/greenrobot/eventbus/", "Lcom/bumptech/glide/", "Lcom/nostra13/universalimageloader/",
        "Lorg/json/", "Lcom/fasterxml/jackson/", "Lcom/google/gson/", "Lokhttp3/", "Lretrofit2/",
        "Lcom/android/volley/", "Lcom/loopj/android/http/", "Lorg/koin/", "Ldagger/",
        "Lkotlinx/coroutines/", "Lio/realm/", "Lcom/couchbase/lite/", "Lio/sentry/", "Lcom/bugsnag/",
        "Lcom/tencent/mm/opensdk/", "Lcom/alipay/sdk/", "Lcom/tencent/tauth/", "Lcom/weibo/sdk/",
        "Lcn/jpush/android/", "Lcom/baidu/mapapi/", "Lcom/amap/api/", "Lcom/tencent/map/",
        "Lcom/huawei/hms/", "Lcom/xiaomi/mipush/", "Lcom/meizu/cloud/pushsdk/", "Lcom/vivo/push/",
        "Lcom/oppo/push/", "Lcom/google/zxing/", "Lcom/journeyapps/barcodescanner/",
        "Lcom/github/chrisbanes/photoview/", "Lcom/github/PhilJay/MPAndroidChart/",
        "Lcom/github/bumptech/glide/", "Lcom/github/square/okhttp/", "Lcom/github/square/retrofit/",
        "Lcom/github/ReactiveX/RxJava/", "Lcom/github/JakeWharton/butterknife/",
        "Lcom/github/JakeWharton/timber/", "Lcom/github/CymChad/BaseRecyclerViewAdapterHelper/",
        "Lcom/github/alibaba/fastjson/", "Lcom/alibaba/fastjson/", "Lcom/google/code/gson/",
        "Lorg/slf4j/", "Lch/qos/logback/", "Lorg/apache/logging/log4j/", "Lcom/google/guava/",
        "Lorg/jetbrains/kotlin/", "Lorg/jetbrains/anko/", "Lio/netty/",
        "Lorg/eclipse/paho/client/mqttv3/", "Lorg/java_websocket/", "Lcom/rabbitmq/client/",

        "Lorg/zeromq/", "Lcom/google/protobuf/", "Lcom/google/flatbuffers/",
        "Lcom/google/auto/value/", "Lcom/google/auto/service/", "Lcom/google/dagger/",
        "Lcom/google/inject/"
    ]
    for d_class in dx_object.get_classes():
        class_name = d_class.name
        for prefix in common_library_prefixes:
            if class_name.startswith(prefix):
                parts = prefix[1:].split('/')
                library_name = '.'.join(parts[:3]) if len(parts) > 2 else '.'.join(parts)
                identified_libraries.add(library_name)
                break
    return list(identified_libraries)

def fetch_vulnerabilities_from_nvd(library_name):
    """
    Fetches vulnerability data from the National Vulnerability Database (NVD) using API 2.0.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    keyword = library_name.split('.')[-1]
    params = {'keywordSearch': keyword}
    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = []
        if 'vulnerabilities' in data:
            for item in data['vulnerabilities']:
                cve = item.get('cve', {})
                cve_id = cve.get('id', 'N/A')
                description = 'N/A'
                if cve.get('descriptions'):
                    for desc in cve['descriptions']:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', 'N/A')
                            break
                severity = "N/A"
                if 'metrics' in cve and 'cvssMetricV2' in cve['metrics'] and cve['metrics']['cvssMetricV2']:
                    severity = cve['metrics']['cvssMetricV2'][0].get('baseSeverity', "N/A")

                vulnerabilities.append({"cve": cve_id, "description": description, "severity": severity})
        return vulnerabilities
    except requests.exceptions.RequestException as e:
        print(f"Error fetching vulnerabilities for {library_name}: {e}")
        return []

def check_for_vulnerabilities(identified_libraries):
    found_vulnerabilities = []
    for lib in identified_libraries:
        # Fetch live data from NVD
        nvd_vulnerabilities = fetch_vulnerabilities_from_nvd(lib)
        if nvd_vulnerabilities:
            found_vulnerabilities.extend(nvd_vulnerabilities)
    return found_vulnerabilities

def check_insecure_communication(dx_object):
    insecure_urls = []
    for method in dx_object.get_methods():
        if method.is_external():
            continue
        for _, call, _ in method.get_xref_ins_and_outs():
            if call.get_name() == "Ljava/net/URL;-><init>(Ljava/lang/String;)V":
                # Look for string literals passed to URL constructor
                for _, ref in method.get_literals():
                    if isinstance(ref, str) and ref.startswith("http://"):
                        insecure_urls.append(ref)
            elif call.get_name() == "Lorg/apache/http/client/methods/HttpGet;-><init>(Ljava/lang/String;)V":
                for _, ref in method.get_literals():
                    if isinstance(ref, str) and ref.startswith("http://"):
                        insecure_urls.append(ref)
            # Add more checks for other networking libraries if needed (e.g., OkHttp, Volley)
    return list(set(insecure_urls))

def check_insecure_data_storage(a_object, dx_object):
    insecure_storage_findings = []

    # Check AndroidManifest.xml for android:allowBackup="true"
    try:
        manifest_xml = a_object.get_android_manifest_xml()
        allow_backup = manifest_xml.xpath("//application/@android:allowBackup")
        if allow_backup and allow_backup[0].lower() == "true":
            insecure_storage_findings.append("android:allowBackup=\"true\" found in AndroidManifest.xml. Data can be backed up via ADB.")
    except Exception as e:
        print(f"Error checking allowBackup in manifest: {e}")

    # Check for MODE_WORLD_READABLE/WRITEABLE in file operations
    for method in dx_object.get_methods():
        if method.is_external():
            continue
        for _, call, _ in method.get_xref_ins_and_outs():
            if call.get_name() == "Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;":
                # Check if MODE_WORLD_READABLE (0x2) or MODE_WORLD_WRITEABLE (0x4) is used
                for arg in call.get_args():
                    if isinstance(arg, int) and (arg & 0x2 or arg & 0x4):
                        insecure_storage_findings.append(f"Insecure file output mode detected in {method.get_class_name()}->{method.get_name()} (MODE_WORLD_READABLE/WRITEABLE).")
            elif call.get_name() == "Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;":
                for arg in call.get_args():
                    if isinstance(arg, int) and (arg & 0x2 or arg & 0x4):
                        insecure_storage_findings.append(f"Insecure shared preferences mode detected in {method.get_class_name()}->{method.get_name()} (MODE_WORLD_READABLE/WRITEABLE).")

    # Check for usage of Environment.getExternalStorageDirectory()
    for method in dx_object.get_methods():
        if method.is_external():
            continue
        for _, call, _ in method.get_xref_ins_and_outs():
            if call.get_name() == "Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;":
                insecure_storage_findings.append(f"Usage of Environment.getExternalStorageDirectory() detected in {method.get_class_name()}->{method.get_name()}. Data stored here is publicly accessible.")
    return list(set(insecure_storage_findings))

def check_webview_vulnerabilities(dx_object):
    webview_findings = []
    for method in dx_object.get_methods():
        if method.is_external():
            continue
        for _, call, _ in method.get_xref_ins_and_outs():
            # setJavaScriptEnabled(true)
            if call.get_name() == "Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V":
                # Check if the argument is 'true' (1)
                for arg in call.get_args():
                    if isinstance(arg, int) and arg == 1:
                        webview_findings.append(f"WebView.setJavaScriptEnabled(true) detected in {method.get_class_name()}->{method.get_name()}. This can lead to XSS if not handled carefully.")
            # addJavascriptInterface
            elif call.get_name() == "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V":
                webview_findings.append(f"WebView.addJavascriptInterface detected in {method.get_class_name()}->{method.get_name()}. Ensure methods exposed are properly annotated with @JavascriptInterface (API 17+) and sensitive operations are not exposed.")
            # setAllowFileAccessFromFileURLs(true) or setAllowUniversalAccessFromFileURLs(true)
            elif call.get_name() == "Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V":
                for arg in call.get_args():
                    if isinstance(arg, int) and arg == 1:
                        webview_findings.append(f"WebView.setAllowFileAccessFromFileURLs(true) detected in {method.get_class_name()}->{method.get_name()}. This can allow JavaScript in a local file to access other local files.")
            elif call.get_name() == "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V":
                for arg in call.get_args():
                    if isinstance(arg, int) and arg == 1:
                        webview_findings.append(f"WebView.setAllowUniversalAccessFromFileURLs(true) detected in {method.get_class_name()}->{method.get_name()}. This can allow JavaScript in a local file to access content from any origin.")
    return list(set(webview_findings))

def analyze_apk_features(file_path):
    a, d, dx = AnalyzeAPK(file_path)
    permissions = a.get_permissions()
    activities = a.get_activities()
    services = a.get_services()
    receivers = a.get_receivers()
    hardcoded_secrets = find_hardcoded_secrets(a)
    identified_libraries = identify_libraries(dx)
    vulnerabilities = check_for_vulnerabilities(identified_libraries)
    insecure_communication_findings = check_insecure_communication(dx)
    insecure_data_storage_findings = check_insecure_data_storage(a, dx)
    webview_vulnerabilities = check_webview_vulnerabilities(dx)
    suspicious_api_calls = detect_suspicious_api_calls(dx)
    ssl_tls_issues = check_ssl_tls_issues(dx)
    network_indicators = extract_network_indicators(dx)
    intent_filters = extract_intent_filters(a)

    taint_analyzer = TaintAnalyzer()
    taint_flows = taint_analyzer.analyze_apk(file_path)

    return {
        "permissions": permissions,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "hardcoded_secrets": hardcoded_secrets,
        "identified_libraries": identified_libraries,
        "vulnerabilities": vulnerabilities,
        "insecure_communication": insecure_communication_findings,
        "insecure_data_storage": insecure_data_storage_findings,
        "webview_vulnerabilities": webview_vulnerabilities,
        "suspicious_api_calls": suspicious_api_calls,
        "ssl_tls_issues": ssl_tls_issues,
        "network_indicators": network_indicators,
        "intent_filters": intent_filters,
        "taint_flows": taint_flows
    }

def detect_suspicious_api_calls(dx_object):
    suspicious_calls = []
    suspicious_api_patterns = {
        "SMS": ["Landroid/telephony/SmsManager;->sendTextMessage", "Landroid/telephony/SmsManager;->sendMultipartTextMessage"],
        "RuntimeExecution": ["Ljava/lang/Runtime;->exec", "Ljava/lang/ProcessBuilder;->start"],
        "Reflection": ["Ljava/lang/reflect/Method;->invoke", "Ljava/lang/Class;->forName"],
        "DexClassLoader": ["Ldalvik/system/DexClassLoader;-><init>", "Ldalvik/system/PathClassLoader;-><init>"],
        "Location": ["Landroid/location/LocationManager;->getLastKnownLocation", "Landroid/location/LocationManager;->requestLocationUpdates"],
        "Contacts": ["Landroid/provider/ContactsContract$CommonDataKinds$Phone;->query", "Landroid/content/ContentResolver;->query"],
        "Camera": ["Landroid/hardware/Camera;->open", "Landroid/hardware/camera2/CameraManager;->openCamera"],
        "Microphone": ["Landroid/media/AudioRecord;->startRecording", "Landroid/media/MediaRecorder;->start"],
        "FileSystem": ["Ljava/io/File;->delete", "Ljava/io/File;->mkdir", "Ljava/io/FileOutputStream;-><init>", "Ljava/io/FileInputStream;-><init>"],
        "Crypto": ["Ljavax/crypto/Cipher;->getInstance", "Ljava/security/MessageDigest;->getInstance"],
        "Network": ["Ljava/net/URL;->openConnection", "Ljava/net/HttpURLConnection;->connect", "Lorg/apache/http/client/HttpClient;->execute"],
        "RootDetection": ["Ljava/io/File;->exists", "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su"],
        "DataExfiltration": ["Landroid/util/Base64;->encodeToString", "Ljava/net/URLEncoder;->encode"],
        "Keylogging": ["Landroid/view/View;->setOnKeyListener", "Landroid/text/TextWatcher;->onTextChanged"],
        "Accessibility": ["Landroid/accessibilityservice/AccessibilityService;->onAccessibilityEvent"],
        "SMS_Read": ["Landroid/provider/Telephony$Sms;->CONTENT_URI"],
        "Call_Log": ["Landroid/provider/CallLog$Calls;->CONTENT_URI"],
        "Account_Info": ["Landroid/accounts/AccountManager;->getAccountsByType"],
        "Device_Admin": ["Landroid/app/admin/DevicePolicyManager;->isAdminActive"],
        "Install_Packages": ["Landroid/content/pm/PackageManager;->installPackage"],
        "Dynamic_Code_Loading": ["Ldalvik/system/DexClassLoader;->loadClass", "Ljava/lang/ClassLoader;->loadClass"],
        "Code_Reflection": ["Ljava/lang/Class;->getMethod", "Ljava/lang/Class;->getConstructor", "Ljava/lang/reflect/Method;->invoke", "Ljava/lang/reflect/Field;->get", "Ljava/lang/reflect/Field;->set"],
        "Reflection_Invoke": ["Ljava/lang/reflect/Method;->invoke"],
        "System_Properties": ["Landroid/os/SystemProperties;->get"],
        "Clipboard": ["Landroid/content/ClipboardManager;->getText"],
        "Screenshot": ["Landroid/view/View;->getDrawingCache"],
        "VPN": ["Landroid/net/VpnService;->prepare"],
        "Overlay": ["Landroid/view/WindowManager$LayoutParams;->TYPE_SYSTEM_ALERT"],
        "Battery_Optimization": ["Landroid/os/PowerManager;->isIgnoringBatteryOptimizations"]
    }

    for method in dx_object.get_methods():
        if method.is_external():
            continue
        for _, call, _ in method.get_xref_ins_and_outs():
            for category, apis in suspicious_api_patterns.items():
                for api in apis:
                    if api in call.get_class_name() + "->" + call.get_name():
                        suspicious_calls.append(f"{category}: {call.get_class_name()}->{call.get_name()}")
    
    return list(set(suspicious_calls))

def check_ssl_tls_issues(dx_object):
    ssl_tls_findings = []
    insecure_patterns = [
        "Ljavax/net/ssl/HostnameVerifier;->verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z", # Custom HostnameVerifier
        "Ljavax/net/ssl/X509TrustManager;->checkClientTrusted", # Custom TrustManager
        "Ljavax/net/ssl/X509TrustManager;->checkServerTrusted", # Custom TrustManager
        "Ljavax/net/ssl/TrustManager;->checkClientTrusted", # Custom TrustManager
        "Ljavax/net/ssl/TrustManager;->checkServerTrusted", # Custom TrustManager
        "Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER", # Apache HttpClient
        "Landroid/webkit/WebViewClient;->onReceivedSslError", # WebView SSL error handling
        "Landroid/net/http/SslError;->has  Error", # WebView SSL error handling
        "Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier", # Global HostnameVerifier
        "Ljavax/net/ssl/SSLContext;->init", # Custom SSLContext
    ]

    for method in dx_object.get_methods():
        if method.is_external():
            continue
        for _, call, _ in method.get_xref_ins_and_outs():
            for pattern in insecure_patterns:
                if pattern in call.get_class_name() + "->" + call.get_name():
                    ssl_tls_findings.append(f"Potential SSL/TLS issue: {pattern} detected in {method.get_class_name()}->{method.get_name()}.")
    return list(set(ssl_tls_findings))

def extract_network_indicators(dx_object):
    urls = []
    ips = []
    url_pattern = r"https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    for method in dx_object.get_methods():
        if method.is_external():
            continue
        for _, ref in method.get_literals():
            if isinstance(ref, str):
                found_urls = re.findall(url_pattern, ref)
                urls.extend(found_urls)
                found_ips = re.findall(ip_pattern, ref)
                ips.extend(found_ips)
    return {"urls": list(set(urls)), "ips": list(set(ips))}

def extract_intent_filters(a_object):
    intent_filters = []
    try:
        manifest_xml = a_object.get_android_manifest_xml()
        for component_type in ['activity', 'service', 'receiver']:
            for component in manifest_xml.xpath(f"//application/{component_type}"):
                component_name = component.get('{http://schemas.android.com/apk/res/android}name')
                for intent_filter in component.xpath("intent-filter"):
                    filter_details = {
                        "component": component_name,
                        "type": component_type,
                        "actions": [],
                        "categories": [],
                        "data": []
                    }
                    for action in intent_filter.xpath("action"):
                        filter_details["actions"].append(action.get('{http://schemas.android.com/apk/res/android}name'))
                    for category in intent_filter.xpath("category"):
                        filter_details["categories"].append(category.get('{http://schemas.android.com/apk/res/android}name'))
                    for data in intent_filter.xpath("data"):
                        data_attrs = {}
                        if data.get('{http://schemas.android.com/apk/res/android}scheme'):
                            data_attrs['scheme'] = data.get('{http://schemas.android.com/apk/res/android}scheme')
                        if data.get('{http://schemas.android.com/apk/res/android}host'):
                            data_attrs['host'] = data.get('{http://schemas.android.com/apk/res/android}host')
                        if data.get('{http://schemas.android.com/apk/res/android}port'):
                            data_attrs['port'] = data.get('{http://schemas.android.com/apk/res/android}port')
                        if data.get('{http://schemas.android.com/apk/res/android}path'):
                            data_attrs['path'] = data.get('{http://schemas.android.com/apk/res/android}path')
                        if data.get('{http://schemas.android.com/apk/res/android}pathPrefix'):
                            data_attrs['pathPrefix'] = data.get('{http://schemas.android.com/apk/res/android}pathPrefix')
                        if data.get('{http://schemas.android.com/apk/res/android}pathPattern'):
                            data_attrs['pathPattern'] = data.get('{http://schemas.android.com/apk/res/android}pathPattern')
                        if data.get('{http://schemas.android.com/apk/res/android}mimeType'):
                            data_attrs['mimeType'] = data.get('{http://schemas.android.com/apk/res/android}mimeType')
                        if data_attrs:
                            filter_details["data"].append(data_attrs)
                    intent_filters.append(filter_details)
    except Exception as e:
        print(f"Error extracting intent filters: {e}")
    return intent_filters
