import pandas as pd
import joblib

# Load trained model
model = joblib.load("models/random_forest.pkl")

# Load one of our datasets
file = "Dataset/Raw/MachineLearningCSV/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

data = pd.read_csv(file)

# Clean column names
data.columns = data.columns.str.strip()

# Take one DDoS record
sample = data[data["Label"] == "DDoS"].iloc[[0]]

# Separate features from label
X = sample.drop("Label", axis=1)

# Make prediction
prediction = model.predict(X)

# Convert number back to attack name
label_map = {
    0: "BENIGN",
    1: "DDoS",
    2: "PortScan"
}

result = label_map[prediction[0]]

print("Prediction:", result)
