from logger.loggers import logger
import time
##logs are generalized but alerts will send specified alerts to a different file
#what shoult be there timestamp,alert type,severity,description,src_ip,dst_ip,additional_info

def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def send_alert(alert):
    """
    Sends structured IDS alerts to logging system
    """


    msg = (
        f"[{timestamp()}] "
        f"ALERT={alert.get('alert_type', 'Unknown')} | "
        f"SEVERITY={alert.get('severity', 'Medium')} | "
        f"SRC={alert.get('src_ip', 'N/A')} | "
        f"DST={alert.get('dst_ip', 'N/A')} | "
        f"DESC={alert.get('description', '')} | "
        f"INFO={alert.get('additional_info', '')}"
    )

    severity = alert.get("severity", "Medium")

    if severity == "High":
        logger.error(msg)
    elif severity == "Medium":
        logger.warning(msg)
    elif severity == "Low":
        logger.info(msg)
    else:
        logger.info(msg)