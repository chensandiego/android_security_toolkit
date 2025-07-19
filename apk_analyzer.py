import re
import requests
from androguard.misc import AnalyzeAPK

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
    Fetches vulnerability data from the National Vulnerability Database (NVD).
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    # A more specific keyword search might be needed depending on library naming conventions
    keyword = library_name.split('.')[-1] # Example: com.squareup.okhttp -> okhttp
    params = {'keyword': keyword}
    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status() # Raise an exception for bad status codes
        data = response.json()
        vulnerabilities = []
        if 'result' in data and 'CVE_Items' in data['result']:
            for item in data['result']['CVE_Items']:
                cve_id = item['cve']['CVE_data_meta']['ID']
                description = item['cve']['description']['description_data'][0]['value']
                severity = item['impact']['baseMetricV2']['severity'] if 'baseMetricV2' in item['impact'] else "N/A"
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

def analyze_apk_features(file_path):
    a, d, dx = AnalyzeAPK(file_path)
    permissions = a.get_permissions()
    activities = a.get_activities()
    services = a.get_services()
    receivers = a.get_receivers()
    hardcoded_secrets = find_hardcoded_secrets(a)
    identified_libraries = identify_libraries(dx)
    vulnerabilities = check_for_vulnerabilities(identified_libraries)
    return {
        "permissions": permissions,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "hardcoded_secrets": hardcoded_secrets,
        "identified_libraries": identified_libraries,
        "vulnerabilities": vulnerabilities
    }