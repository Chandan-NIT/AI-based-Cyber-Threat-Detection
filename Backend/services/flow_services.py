import sys
from pathlib import Path
from datetime import datetime
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "Backend"))
from database import insert_detection
sys.path.append(str(PROJECT_ROOT / "Datacapture"))
from capture import calculate_all_features
from services.predictor import predict_flow


FLOW_TIMEOUT = 5


def check_completed_flows(flows):

    completed_flows = []

    current_time = datetime.now()

    for flow_key, flow in list(flows.items()):

        idle_time = (
            current_time - flow["last_time"]
        ).total_seconds()

        if idle_time >= FLOW_TIMEOUT:

            completed_flows.append(
                (flow_key, flow)
            )

    return completed_flows


def process_completed_flow(flow):

    # Calculate ML features
    features = calculate_all_features(flow)

    # Get ML prediction and prediction score
    result = predict_flow(features)

    prediction = result["prediction"]
    score = result["score"]

    # Calculate basic information for database
    timestamp = datetime.now().isoformat()

    packet_count = len(flow["packets"])

    total_bytes = sum(
        packet["length"]
        for packet in flow["packets"]
    )

    duration = (
        flow["last_time"] - flow["start_time"]
    ).total_seconds()

    # Store detection in SQLite
    insert_detection(
        timestamp,
        flow["source_ip"],
        flow["destination_ip"],
        flow["source_port"],
        flow["destination_port"],
        flow["protocol"],
        packet_count,
        total_bytes,
        duration,
        prediction,
        score
    )

    return {
        "prediction": prediction,
        "score": score
    }