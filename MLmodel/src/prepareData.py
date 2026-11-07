import pandas as pd
import numpy as np

# Dataset paths
ddos_file = "../Dataset/Raw/MachineLearningCSV/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
portscan_file = "../Dataset/Raw/MachineLearningCSV/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
benign_file = "../Dataset/Raw/MachineLearningCSV/Monday-WorkingHours.pcap_ISCX.csv"

# Load datasets
ddos = pd.read_csv(ddos_file)
portscan = pd.read_csv(portscan_file)
benign = pd.read_csv(benign_file)

# Clean column names
ddos.columns = ddos.columns.str.strip()
portscan.columns = portscan.columns.str.strip()
benign.columns = benign.columns.str.strip()

# Keep only required attack classes
ddos = ddos[ddos["Label"] == "DDoS"]
portscan = portscan[portscan["Label"] == "PortScan"]

# Take 150,000 BENIGN samples
benign = benign.sample(n=150000, random_state=42)

# Combine datasets
data = pd.concat([benign, ddos, portscan], ignore_index=True)

# Shuffle
data = data.sample(frac=1, random_state=42).reset_index(drop=True)

print("Before cleaning:", data.shape)

# Replace infinity values with NaN
data.replace([np.inf, -np.inf], np.nan, inplace=True)

# Remove rows containing NaN
data.dropna(inplace=True)

# Remove duplicate rows
data.drop_duplicates(inplace=True)

# Shuffle again
data = data.sample(frac=1, random_state=42).reset_index(drop=True)

print("After cleaning:", data.shape)

print("\nFinal label distribution:")
print(data["Label"].value_counts())

print("\nMissing values:", data.isna().sum().sum())

print("Duplicate rows:", data.duplicated().sum())

# Separate features and target
X = data.drop("Label", axis=1)
y = data["Label"]

# Convert labels to numbers
label_map = {
    "BENIGN": 0,
    "DDoS": 1,
    "PortScan": 2
}

y = y.map(label_map)

print("\nFeatures shape:", X.shape)
print("Target shape:", y.shape)

print("\nTarget distribution:")
print(y.value_counts())

print("\nFeature data types:")
print(X.dtypes.value_counts())

from sklearn.model_selection import train_test_split

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining data:", X_train.shape)
print("Testing data:", X_test.shape)

print("\nTraining labels:")
print(y_train.value_counts())

print("\nTesting labels:")
print(y_test.value_counts())