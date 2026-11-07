import pandas as pd
import joblib


# Load trained model
model = joblib.load(
    "../MLmodel/models/random_forest.pkl"
)


# Load captured flow data
data = pd.read_csv(
    "captured_flows.csv"
)


# Clean column names
data.columns = data.columns.str.strip()


# Make sure the columns are in the
# exact order expected by the model
data = data[model.feature_names_in_]


# Make predictions
predictions = model.predict(data)


# Convert prediction numbers to attack names
label_map = {
    0: "BENIGN",
    1: "DDoS",
    2: "PortScan"
}


print("\nPredictions:")

for i, prediction in enumerate(predictions, start=1):

    result = label_map.get(
        prediction,
        "UNKNOWN"
    )

    print(
        f"Flow {i}: {result}"
    )