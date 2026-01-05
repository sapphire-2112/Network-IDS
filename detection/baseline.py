import math
from collections import defaultdict

MIN_BASELINE_SAMPLES = 30
STABILITY_EPSILON = 0.02
STABILITY_HITS = 5

baseline = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {
    "count": 0,
    "mean": 0.0,
    "m2": 0.0,
    "prev_mean": None,
    "prev_std": None,
    "stable_hits": 0,
    "confident": False
})))


def update_baseline(src_ip, aggregated_features):
    for window, features in aggregated_features.items():
        for feature_name, value in features.items():
            if not isinstance(value, (int, float)):
                continue

            stats = baseline[src_ip][window][feature_name]

            # --- Welford update ---
            stats["count"] += 1
            delta = value - stats["mean"]
            stats["mean"] += delta / stats["count"]
            delta2 = value - stats["mean"]
            stats["m2"] += delta * delta2

            # --- Confidence check ---
            if stats["count"] < MIN_BASELINE_SAMPLES:
                continue

            variance = stats["m2"] / (stats["count"] - 1)
            std = math.sqrt(variance)

            if stats["prev_mean"] is not None and stats["prev_std"] is not None:
                mean_change = abs(stats["mean"] - stats["prev_mean"]) / max(stats["prev_mean"], 1e-6)
                std_change = abs(std - stats["prev_std"]) / max(stats["prev_std"], 1e-6)

                if mean_change < STABILITY_EPSILON and std_change < STABILITY_EPSILON:
                    stats["stable_hits"] += 1
                else:
                    stats["stable_hits"] = 0

                if stats["stable_hits"] >= STABILITY_HITS:
                    stats["confident"] = True

            stats["prev_mean"] = stats["mean"]
            stats["prev_std"] = std


def get_baseline(src_ip, window, feature_name):
    stats = baseline[src_ip][window].get(feature_name)
    if not stats:
        return None

    if not stats["confident"]:
        return {
            "learning": True,
            "count": stats["count"]
        }

    variance = stats["m2"] / (stats["count"] - 1)
    std = math.sqrt(variance)

    return {
        "learning": False,
        "mean": stats["mean"],
        "std": std,
        "count": stats["count"]
    }
