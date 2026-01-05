import time
from collections import defaultdict

# Suppress duplicate alerts for same IP + alert type
ALERT_SUPPRESSION_WINDOW = 60  # seconds

# (src_ip, alert_type) -> last_alert_time
last_alerts = defaultdict(float)


def should_suppress(alert):
    """
    Returns True if alert should be suppressed.
    """
    src_ip = alert.get("src_ip")
    alert_type = alert.get("alert_type")

    if not src_ip or not alert_type:
        return False  # never suppress malformed alerts

    key = (src_ip, alert_type)
    now = time.time()

    last_time = last_alerts[key]

    if (now - last_time) < ALERT_SUPPRESSION_WINDOW:
        return True  # suppress duplicate

    last_alerts[key] = now
    return False
