import pandas as pd

from services.prediction_services import predict_captured_flow


CSV_PATH = "../Datacapture/captured_flows.csv"


df = pd.read_csv(CSV_PATH)

print("Total flows:", len(df))
print("Total features:", len(df.columns))


for i, row in df.iterrows():

    features = row.to_dict()

    prediction = predict_captured_flow(features)

    print(
        f"Flow {i + 1}: {prediction}"
    )