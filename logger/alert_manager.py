from collections import deque
from logger.loggers import logger
from ui.live_ui import add_alert

_alerts = deque(maxlen=200)

def send_alert(alert):
    if not isinstance(alert, dict):
        return

    _alerts.append(alert)

    # 🔥 SEND TO RICH UI
    add_alert(alert)

    # 🔥 SEND TO LOG FILE
    logger.warning(
        "ALERT=%s | SEVERITY=%s | SRC=%s | DST=%s | DESC=%s | INFO=%s",
        alert.get("alert_type", "Unknown"),
        alert.get("severity", "Medium"),
        alert.get("src_ip", "N/A"),
        alert.get("dst_ip", "N/A"),
        alert.get("description", "N/A"),
        alert.get("additional_info", {})
    )

def get_alerts_buffer():
    return list(_alerts)
