import joblib
import pandas as pd
from pathlib import Path


# Project root
BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE_DIR / "models" / "random_forest.pkl"
FEATURE_PATH = BASE_DIR / "models" / "feature_names.pkl"


model = joblib.load(MODEL_PATH)
feature_names = joblib.load(FEATURE_PATH)


label_map = {
    0: "BENIGN",
    1: "DDoS",
    2: "PortScan"
}


def predict_flow(features):

    missing_features = [
        feature
        for feature in feature_names
        if feature not in features
    ]

    if missing_features:
        raise ValueError(
            f"Missing features: {missing_features}"
        )

    ordered_features = {
        feature: features[feature]
        for feature in feature_names
    }

    df = pd.DataFrame(
        [ordered_features],
        columns=feature_names
    )
    prediction = model.predict(df)[0]

    probabilities = model.predict_proba(df)[0]
    
    print("\n========== RANDOM FOREST ==========")
    print("Prediction:", label_map[int(prediction)])
    print("BENIGN:", probabilities[0])
    print("DDoS:", probabilities[1])
    print("PortScan:", probabilities[2])
    print("==================================")

    score = probabilities[int(prediction)]

    return {
        "prediction": label_map[int(prediction)],
        "score": float(score)
    }