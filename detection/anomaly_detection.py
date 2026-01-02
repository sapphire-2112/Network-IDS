from detection.baseline import get_baseline

Z_THRESHOLD = 3.0

def detect_anomalies(src_ip, aggregated_features):
    alerts = []

    for window, features in aggregated_features.items():
        for feature_name, value in features.items():

            if not isinstance(value, (int, float)):
                continue

            baseline = get_baseline(src_ip, window, feature_name)
            if not baseline:
                continue

            mean = baseline["mean"]
            std = baseline["std"]

            if std == 0:
                continue

            z = abs((value - mean) / std)

            if z >= Z_THRESHOLD:
                alerts.append({
                    "alert_type": "ANOMALY_DETECTED",
                    "severity": "Medium",
                    "description": f"{feature_name} deviates from baseline",
                    "src_ip": src_ip,
                    "dst_ip": "N/A",
                    "additional_info": {
                        "window": window,
                        "feature": feature_name,
                        "observed": value,
                        "mean": mean,
                        "std": std,
                        "z_score": round(z, 2)
                    }
                })

    return alerts
