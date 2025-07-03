
from androguard.misc import AnalyzeAPK

def analyze_apk_features(file_path):
    a, d, dx = AnalyzeAPK(file_path)

    permissions = a.get_permissions()
    activities = a.get_activities()
    services = a.get_services()
    receivers = a.get_receivers()

    return {
        "permissions": permissions,
        "activities": activities,
        "services": services,
        "receivers": receivers
    }
