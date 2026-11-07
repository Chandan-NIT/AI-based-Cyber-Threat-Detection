import joblib
from pathlib import Path


MODEL_PATH = (
    Path(__file__).resolve().parent.parent
    / "MLmodel"
    / "models"
    / "random_forest.pkl"
)

model = joblib.load(MODEL_PATH)


LABEL_MAP = {
    0: "BENIGN",
    1: "DDoS",
    2: "PortScan"
}


def predict(features):
    prediction = model.predict(features)

    return LABEL_MAP[prediction[0]]