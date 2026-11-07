import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# Dataset paths
ddos_file = "Dataset/Raw/MachineLearningCSV/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
portscan_file = "Dataset/Raw/MachineLearningCSV/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
benign_file = "Dataset/Raw/MachineLearningCSV/Monday-WorkingHours.pcap_ISCX.csv"

# Load datasets
ddos = pd.read_csv(ddos_file)
portscan = pd.read_csv(portscan_file)
benign = pd.read_csv(benign_file)

# Clean column names
ddos.columns = ddos.columns.str.strip()
portscan.columns = portscan.columns.str.strip()
benign.columns = benign.columns.str.strip()

# Keep required classes
ddos = ddos[ddos["Label"] == "DDoS"]
portscan = portscan[portscan["Label"] == "PortScan"]
benign = benign.sample(n=150000, random_state=42)

# Combine
data = pd.concat([benign, ddos, portscan], ignore_index=True)

# Shuffle
data = data.sample(frac=1, random_state=42).reset_index(drop=True)

# Clean infinite and missing values
data.replace([np.inf, -np.inf], np.nan, inplace=True)
data.dropna(inplace=True)

# Remove duplicates
data.drop_duplicates(inplace=True)

# Separate features and target
X = data.drop("Label", axis=1)
y = data["Label"]

# Convert labels
label_map = {
    "BENIGN": 0,
    "DDoS": 1,
    "PortScan": 2
}

y = y.map(label_map)

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training Random Forest...")

# Create model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

# Train
model.fit(X_train, y_train)

print("Training complete!")

# Predict
y_pred = model.predict(X_test)

# Evaluation
print("\nClassification Report:")
print(classification_report(
    y_test,
    y_pred,
))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save model
joblib.dump(model, "models/random_forest.pkl")
joblib.dump(
    X.columns.tolist(),
    "models/feature_names.pkl"
)

print("\nModel saved to models/random_forest.pkl")