from detection.baseline import get_baseline

MIN_BASELINE_SAMPLES = 30
Z_THRESHOLD = 3.0

IGNORE_FEATURES = {"samples", "window_duration"}


def detect_anomalies(src_ip, aggregated_features):
    alerts = []

    for window, features in aggregated_features.items():
        for feature_name, value in features.items():

            if (
                not isinstance(value, (int, float))
                or feature_name in IGNORE_FEATURES
            ):
                continue

            baseline = get_baseline(src_ip, window, feature_name)
            if not baseline:
                continue

            # Baseline not ready
            if baseline.get("learning", True):
                continue

            if baseline["count"] < MIN_BASELINE_SAMPLES:
                continue

            mean = baseline["mean"]
            std = baseline["std"]

            if std < 1e-6:
                continue

            z = abs((value - mean) / std)

            if z >= Z_THRESHOLD:
                alerts.append({
                    "alert_type": "ANOMALY_DETECTED",
                    "severity": "Medium",
                    "src_ip": src_ip,
                    "dst_ip": "N/A",
                    "description": (
                        f"{feature_name} deviates from baseline "
                        f"(window={window})"
                    ),
                    "additional_info": {
                        "feature": feature_name,
                        "window": window,
                        "observed": round(value, 4),
                        "mean": round(mean, 4),
                        "std": round(std, 4),
                        "z_score": round(z, 2),
                    }
                })

    return alerts
