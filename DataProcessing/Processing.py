import pandas as pd

# Load captured flow data
df = pd.read_csv("../Datacapture/captured_flows.csv")

# print("Original Data:")
# print(df)

# print("\nData Information:")
# print(df.info())

# print("\nMissing Values:")
# print(df.isnull().sum())

# Remove IP address columns
df = df.drop(columns=["source_ip", "destination_ip"])

print("\nAfter removing IP addresses:")
print(df.head())

print("\nProcessed columns:")
print(df.columns)

# Avoid division by zero
df["duration"] = df["duration"].replace(0, 0.001)

# Create packet rate
df["packet_rate"] = df["packet_count"] / df["duration"]

# Create average packet size
df["average_packet_size"] = df["total_bytes"] / df["packet_count"]

# Create bytes per second
df["bytes_per_second"] = df["total_bytes"] / df["duration"]

print("\nAfter creating new features:")
print(df.head())

# Save processed data
df.to_csv("processed_flows.csv", index=False)

print("\nProcessed data saved successfully.")