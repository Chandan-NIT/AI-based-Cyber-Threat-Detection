import pandas as pd
import requests


CSV_PATH = "../Datacapture/captured_flows.csv"
API_URL = "http://127.0.0.1:8000/predict"


# Read captured flows
df = pd.read_csv(CSV_PATH)

print("Number of flows:", len(df))
print("Number of features:", len(df.columns))


# Take first flow
flow = df.iloc[0].to_dict()


# Send to FastAPI
response = requests.post(
    API_URL,
    json=flow
)


print("\nStatus code:", response.status_code)
print("Response:", response.json())