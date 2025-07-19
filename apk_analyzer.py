
import re
from androguard.misc import AnalyzeAPK

def find_hardcoded_secrets(apk_object):
    secrets_found = {}

    # Define regex patterns for common secrets
    # These are examples and can be expanded
    secret_patterns = {
        "API_KEY": r"(?i)(api_key|apikey|x-api-key|access_token|auth_token|client_secret|secret_key|bearer)[^a-zA-Z0-9]{0,20}([a-zA-Z0-9_-]{16,64})",
        "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
        "AWS_SECRET_KEY": r"([0-9a-zA-Z\/+]{40})",
        "GOOGLE_API_KEY": r"AIza[0-9A-Za-z-_]{35}",
        "FIREBASE_API_KEY": r"AIza[0-9A-Za-z-_]{35}", # Often similar to Google API Key
        "PASSWORD": r"(?i)(password|pwd|pass)[^a-zA-Z0-9]{0,20}([a-zA-Z0-9!@#$%^&*()_+-={}\[\]:;\"'<>,.?/\\|]{8,64})",
        "URL_CREDENTIALS": r"(https?:\/\/[^\s\/$.?#].[^\s]*?[:][^\s]*?@)", # URL with embedded credentials
        "PRIVATE_KEY": r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----",
        "SSH_KEY": r"ssh-rsa AAAA[0-9A-Za-z+\/]{100,}",
        "GENERIC_TOKEN": r"(?i)(token|auth|secret)[^a-zA-Z0-9]{0,20}([a-zA-Z0-9_-]{20,128})"
    }

    # Check AndroidManifest.xml
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

    # Check other XML files and general strings (simplified for now)
    # This part can be expanded to parse resources.arsc or other specific files
    # For now, let's just look at any XML files found in the APK
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

    # Note: Extracting strings from classes.dex requires more advanced androguard usage
    # and potentially string deobfuscation, which is beyond this initial scope.
    # For a more comprehensive scan, you'd iterate through dx.strings.

    return secrets_found

def analyze_apk_features(file_path):
    a, d, dx = AnalyzeAPK(file_path)

    permissions = a.get_permissions()
    activities = a.get_activities()
    services = a.get_services()
    receivers = a.get_receivers()
    hardcoded_secrets = find_hardcoded_secrets(a) # Call the new function

    return {
        "permissions": permissions,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "hardcoded_secrets": hardcoded_secrets # Add to the returned dictionary
    }

def identify_libraries(dx_object):
    identified_libraries = set()
    # Common library package prefixes (can be expanded)
    common_library_prefixes = [
        "Lcom/google/android/gms/", # Google Play Services
        "Lcom/google/firebase/",    # Firebase
        "Landroidx/",               # AndroidX
        "Lcom/facebook/",           # Facebook SDK
        "Lcom/squareup/",           # Square libraries (Retrofit, OkHttp)
        "Lio/reactivex/",           # RxJava
        "Lorg/apache/",             # Apache libraries
        "Lcom/unity3d/",            # Unity (if game)
        "Lcom/adjust/",             # Adjust SDK
        "Lcom/appsflyer/",          # AppsFlyer SDK
        "Lcom/crashlytics/",        # Crashlytics
        "Lcom/mixpanel/",           # Mixpanel
        "Lcom/segment/",            # Segment
        "Lorg/greenrobot/eventbus/",# EventBus
        "Lcom/bumptech/glide/",     # Glide
        "Lcom/nostra13/universalimageloader/", # Universal Image Loader
        "Lorg/json/",               # JSON library
        "Lcom/fasterxml/jackson/",  # Jackson
        "Lcom/google/gson/",        # Gson
        "Lokhttp3/",                # OkHttp
        "Lretrofit2/",              # Retrofit
        "Lcom/android/volley/",     # Volley
        "Lcom/loopj/android/http/", # Android-Async-Http
        "Lorg/koin/",               # Koin (Kotlin DI)
        "Ldagger/",                 # Dagger (Java DI)
        "Lkotlinx/coroutines/",     # Kotlin Coroutines
        "Lio/realm/",               # Realm Database
        "Lcom/couchbase/lite/",     # Couchbase Lite
        "Lio/sentry/",              # Sentry
        "Lcom/bugsnag/",            # Bugsnag
        "Lcom/tencent/mm/opensdk/", # WeChat SDK
        "Lcom/alipay/sdk/",         # Alipay SDK
        "Lcom/tencent/tauth/",      # Tencent QQ SDK
        "Lcom/weibo/sdk/",          # Weibo SDK
        "Lcn/jpush/android/",       # JPush
        "Lcom/baidu/mapapi/",       # Baidu Map SDK
        "Lcom/amap/api/",           # Amap SDK
        "Lcom/tencent/map/",        # Tencent Map SDK
        "Lcom/huawei/hms/",         # Huawei Mobile Services
        "Lcom/xiaomi/mipush/",      # Xiaomi Push
        "Lcom/meizu/cloud/pushsdk/",# Meizu Push
        "Lcom/vivo/push/",          # Vivo Push
        "Lcom/oppo/push/",          # Oppo Push
        "Lcom/google/zxing/",       # ZXing (Barcode Scanner)
        "Lcom/journeyapps/barcodescanner/", # JourneyApps Barcode Scanner
        "Lcom/github/chrisbanes/photoview/", # PhotoView
        "Lcom/github/PhilJay/MPAndroidChart/", # MPAndroidChart
        "Lcom/github/bumptech/glide/", # Glide (GitHub)
        "Lcom/github/square/okhttp/", # OkHttp (GitHub)
        "Lcom/github/square/retrofit/", # Retrofit (GitHub)
        "Lcom/github/ReactiveX/RxJava/", # RxJava (GitHub)
        "Lcom/github/JakeWharton/butterknife/", # ButterKnife
        "Lcom/github/JakeWharton/timber/", # Timber
        "Lcom/github/CymChad/BaseRecyclerViewAdapterHelper/", # BaseRecyclerViewAdapterHelper
        "Lcom/github/alibaba/fastjson/", # Fastjson
        "Lcom/alibaba/fastjson/",   # Fastjson (Alibaba)
        "Lcom/google/code/gson/",   # Gson (Google Code)
        "Lorg/slf4j/",              # SLF4J
        "Lch/qos/logback/",         # Logback
        "Lorg/apache/logging/log4j/", # Log4j
        "Lcom/google/guava/",       # Guava
        "Lorg/jetbrains/kotlin/",   # Kotlin
        "Lorg/jetbrains/anko/",     # Anko (Kotlin)
        "Lio/netty/",               # Netty
        "Lorg/eclipse/paho/client/mqttv3/", # Paho MQTT
        "Lorg/java_websocket/",     # Java-WebSocket
        "Lcom/rabbitmq/client/",    # RabbitMQ Java Client
        "Lorg/zeromq/",             # ZeroMQ
        "Lcom/google/protobuf/",    # Protobuf
        "Lcom/google/flatbuffers/", # FlatBuffers
        "Lcom/google/auto/value/",  # AutoValue
        "Lcom/google/auto/service/",# AutoService
        "Lcom/google/dagger/",      # Dagger 2
        "Lcom/google/inject/",      # Guice
    ]

    for d_class in dx_object.get_classes():
        class_name = d_class.name
        for prefix in common_library_prefixes:
            if class_name.startswith(prefix):
                # Extract a more readable library name
                # e.g., Lcom/google/android/gms/ads/AdView; -> com.google.android.gms
                parts = prefix[1:].split('/') # Remove 'L' and split
                if len(parts) > 2: # Take top 2-3 parts for a reasonable name
                    library_name = '.'.join(parts[:3])
                else:
                    library_name = '.'.join(parts)
                identified_libraries.add(library_name)
                break # Found a match, move to next class
    return list(identified_libraries)

def analyze_apk_features(file_path):
    a, d, dx = AnalyzeAPK(file_path)

    permissions = a.get_permissions()
    activities = a.get_activities()
    services = a.get_services()
    receivers = a.get_receivers()
    hardcoded_secrets = find_hardcoded_secrets(a) # Call the new function
    identified_libraries = identify_libraries(dx) # Call the new function

    return {
        "permissions": permissions,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "hardcoded_secrets": hardcoded_secrets,
        "identified_libraries": identified_libraries,
        "vulnerabilities": vulnerabilities # Add to the returned dictionary
    }

# Simplified local vulnerability database (for demonstration)
VULNERABILITY_DB = {
    "com.google.android.gms": [
        {"cve": "CVE-2023-XXXX", "description": "Example vulnerability in Google Play Services", "severity": "High"}
    ],
    "com.squareup.okhttp": [
        {"cve": "CVE-2022-YYYY", "description": "Example vulnerability in OkHttp", "severity": "Medium"}
    ],
    "Lorg/apache/": [
        {"cve": "CVE-2021-ZZZZ", "description": "Example vulnerability in Apache Commons", "severity": "Critical"}
    ]
}

def check_for_vulnerabilities(identified_libraries):
    found_vulnerabilities = []
    for lib in identified_libraries:
        # Check for exact matches first
        if lib in VULNERABILITY_DB:
            found_vulnerabilities.extend(VULNERABILITY_DB[lib])
        # Check for prefix matches (for broader categories like Lorg/apache/)
        else:
            for db_lib_prefix, cves in VULNERABILITY_DB.items():
                if db_lib_prefix.endswith('/') and lib.startswith(db_lib_prefix.replace('L', '').replace('/', '.')):
                    found_vulnerabilities.extend(cves)
    return found_vulnerabilities

def analyze_apk_features(file_path):
    a, d, dx = AnalyzeAPK(file_path)

    permissions = a.get_permissions()
    activities = a.get_activities()
    services = a.get_services()
    receivers = a.get_receivers()
    hardcoded_secrets = find_hardcoded_secrets(a) # Call the new function
    identified_libraries = identify_libraries(dx) # Call the new function
    vulnerabilities = check_for_vulnerabilities(identified_libraries) # Call the new function

    return {
        "permissions": permissions,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "hardcoded_secrets": hardcoded_secrets,
        "identified_libraries": identified_libraries,
        "vulnerabilities": vulnerabilities # Add to the returned dictionary
    }
