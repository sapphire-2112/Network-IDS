import math
from collections import defaultdict

baseline = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {
    "count": 0,
    "mean": 0.0,
    "m2": 0.0  
})))


def update_baseline(src_ip, aggregated_features):
    """
    Update baseline statistics using aggregated features.
    """
    for window, features in aggregated_features.items():
        for feature_name, value in features.items():

            # Ignore non-numeric features
            if not isinstance(value, (int, float)):
                continue

            stats = baseline[src_ip][window][feature_name]

            stats["count"] += 1
            delta = value - stats["mean"]
            stats["mean"] += delta / stats["count"]
            delta2 = value - stats["mean"]
            stats["m2"] += delta * delta2


def get_baseline(src_ip, window, feature_name):
    """
    Return mean and std deviation for a feature.
    """
    stats = baseline[src_ip][window].get(feature_name)
    if not stats or stats["count"] < 2:
        return None

    variance = stats["m2"] / (stats["count"] - 1)
    std = math.sqrt(variance)

    return {
        "mean": stats["mean"],
        "std": std,
        "count": stats["count"]
    }
