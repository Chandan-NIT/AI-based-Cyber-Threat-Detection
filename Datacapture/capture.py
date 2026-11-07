from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import csv
import numpy as np


# ============================================================
# FLOW STORAGE
# ============================================================

flows = {}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def calculate_mean(values):

    if len(values) == 0:
        return 0.0

    return float(np.mean(values))


def calculate_std(values):

    if len(values) <= 1:
        return 0.0

    return float(np.std(values))


def calculate_iat(times):

    if len(times) <= 1:
        return []

    times = sorted(times)

    return [
        (times[i] - times[i - 1]).total_seconds() * 1_000_000
        for i in range(1, len(times))
    ]


# ============================================================
# PROCESS PACKET
# ============================================================

def process_packet(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol = packet[IP].proto

    source_port = 0
    destination_port = 0

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if TCP in packet:

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    elif UDP in packet:

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    # --------------------------------------------------------
    # Ignore other protocols
    # --------------------------------------------------------

    else:

        return

    # ========================================================
    # FLOW KEYS
    # ========================================================

    flow_key = (
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol
    )

    reverse_key = (
        destination_ip,
        source_ip,
        destination_port,
        source_port,
        protocol
    )

    current_time = datetime.now()

    # ========================================================
    # NEW FLOW
    # ========================================================

    if flow_key not in flows and reverse_key not in flows:

        flows[flow_key] = {

            "source_ip": source_ip,
            "destination_ip": destination_ip,

            "source_port": source_port,
            "destination_port": destination_port,

            "protocol": protocol,

            "start_time": current_time,
            "last_time": current_time,

            # ------------------------------------------------
            # Packet information
            # ------------------------------------------------

            "packets": [],

            "fwd_packets": [],
            "bwd_packets": [],

            "fwd_times": [],
            "bwd_times": [],

            # ------------------------------------------------
            # TCP information
            # ------------------------------------------------

            "tcp_flags": [],

            "fwd_tcp_windows": [],
            "bwd_tcp_windows": [],

            # ------------------------------------------------
            # Header lengths
            # ------------------------------------------------

            "fwd_header_lengths": [],
            "bwd_header_lengths": [],

            # ------------------------------------------------
            # TCP segment information
            # ------------------------------------------------

            "fwd_segment_sizes": [],
            "bwd_segment_sizes": [],

            "fwd_data_packets": 0
        }

        flow = flows[flow_key]

        direction = "fwd"

    # ========================================================
    # EXISTING FORWARD FLOW
    # ========================================================

    elif flow_key in flows:

        flow = flows[flow_key]

        direction = "fwd"

    # ========================================================
    # EXISTING REVERSE FLOW
    # ========================================================

    else:

        flow = flows[reverse_key]

        direction = "bwd"

    # ========================================================
    # PACKET LENGTH
    # ========================================================
    #
    # Use IP packet length rather than len(packet), so that
    # Ethernet/L2 information is not included.
    #

    packet_length = len(packet[IP])

    flow["last_time"] = current_time

    # ========================================================
    # STORE PACKET
    # ========================================================

    flow["packets"].append({

        "time": current_time,

        "length": packet_length,

        "direction": direction
    })

    # ========================================================
    # FORWARD / BACKWARD PACKETS
    # ========================================================

    if direction == "fwd":

        flow["fwd_packets"].append(
            packet_length
        )

        flow["fwd_times"].append(
            current_time
        )

    else:

        flow["bwd_packets"].append(
            packet_length
        )

        flow["bwd_times"].append(
            current_time
        )

    # ========================================================
    # TCP FEATURES
    # ========================================================

    if TCP in packet:

        tcp = packet[TCP]

        flags = int(tcp.flags)

        # ----------------------------------------------------
        # Store TCP flags with direction
        # ----------------------------------------------------

        flow["tcp_flags"].append({

            "flags": flags,

            "direction": direction
        })

        # ----------------------------------------------------
        # TCP window
        # ----------------------------------------------------

        if direction == "fwd":

            flow["fwd_tcp_windows"].append(
                int(tcp.window)
            )

        else:

            flow["bwd_tcp_windows"].append(
                int(tcp.window)
            )

        # ----------------------------------------------------
        # IP header length
        # ----------------------------------------------------

        ip_header_length = (
            int(packet[IP].ihl) * 4
        )

        # ----------------------------------------------------
        # TCP header length
        # ----------------------------------------------------

        tcp_header_length = (
            int(tcp.dataofs) * 4
        )

        total_header_length = (
            ip_header_length +
            tcp_header_length
        )

        if direction == "fwd":

            flow["fwd_header_lengths"].append(
                total_header_length
            )

        else:

            flow["bwd_header_lengths"].append(
                total_header_length
            )

        # ----------------------------------------------------
        # TCP payload / segment size
        # ----------------------------------------------------

        payload_size = len(
            bytes(tcp.payload)
        )

        if direction == "fwd":

            flow["fwd_segment_sizes"].append(
                payload_size
            )

            # Count only packets containing actual data
            if payload_size > 0:

                flow["fwd_data_packets"] += 1

        else:

            flow["bwd_segment_sizes"].append(
                payload_size
            )


# ============================================================
# BASIC FEATURES
# ============================================================

def calculate_basic_features(flow):

    fwd = flow["fwd_packets"]
    bwd = flow["bwd_packets"]

    all_packets = fwd + bwd

    # --------------------------------------------------------
    # Flow duration
    # --------------------------------------------------------

    duration = (
        flow["last_time"] -
        flow["start_time"]
    ).total_seconds() * 1_000_000

    if duration < 0:

        duration = 0

    duration_seconds = duration / 1_000_000

    # --------------------------------------------------------
    # Avoid division by zero
    # --------------------------------------------------------

    if duration_seconds == 0:

        duration_seconds = 0.000001

    # --------------------------------------------------------
    # Packet lengths
    # --------------------------------------------------------

    total_fwd_length = sum(fwd)

    total_bwd_length = sum(bwd)

    # --------------------------------------------------------
    # Features
    # --------------------------------------------------------

    features = {}

    features["Destination Port"] = (
        flow["destination_port"]
    )

    features["Flow Duration"] = duration

    features["Total Fwd Packets"] = len(fwd)

    features["Total Backward Packets"] = len(bwd)

    features["Total Length of Fwd Packets"] = (
        total_fwd_length
    )

    features["Total Length of Bwd Packets"] = (
        total_bwd_length
    )

    # --------------------------------------------------------
    # Forward packet statistics
    # --------------------------------------------------------

    if fwd:

        features["Fwd Packet Length Max"] = max(fwd)

        features["Fwd Packet Length Min"] = min(fwd)

        features["Fwd Packet Length Mean"] = (
            np.mean(fwd)
        )

        features["Fwd Packet Length Std"] = (
            np.std(fwd)
            if len(fwd) > 1
            else 0
        )

    else:

        features["Fwd Packet Length Max"] = 0

        features["Fwd Packet Length Min"] = 0

        features["Fwd Packet Length Mean"] = 0

        features["Fwd Packet Length Std"] = 0

    # --------------------------------------------------------
    # Backward packet statistics
    # --------------------------------------------------------

    if bwd:

        features["Bwd Packet Length Max"] = max(bwd)

        features["Bwd Packet Length Min"] = min(bwd)

        features["Bwd Packet Length Mean"] = (
            np.mean(bwd)
        )

        features["Bwd Packet Length Std"] = (
            np.std(bwd)
            if len(bwd) > 1
            else 0
        )

    else:

        features["Bwd Packet Length Max"] = 0

        features["Bwd Packet Length Min"] = 0

        features["Bwd Packet Length Mean"] = 0

        features["Bwd Packet Length Std"] = 0

    # --------------------------------------------------------
    # Flow rates
    # --------------------------------------------------------

    total_bytes = (
        total_fwd_length +
        total_bwd_length
    )

    total_packets = len(all_packets)

    features["Flow Bytes/s"] = (
        total_bytes /
        duration_seconds
    )

    features["Flow Packets/s"] = (
        total_packets /
        duration_seconds
    )

    return features


# ============================================================
# TIMING FEATURES
# ============================================================

def calculate_timing_features(flow):

    all_times = (
        flow["fwd_times"] +
        flow["bwd_times"]
    )

    all_times.sort()

    fwd_times = flow["fwd_times"]

    bwd_times = flow["bwd_times"]

    # --------------------------------------------------------
    # IAT
    # --------------------------------------------------------

    flow_iat = calculate_iat(
        all_times
    )

    fwd_iat = calculate_iat(
        fwd_times
    )

    bwd_iat = calculate_iat(
        bwd_times
    )

    features = {}

    # --------------------------------------------------------
    # Flow IAT
    # --------------------------------------------------------

    features["Flow IAT Mean"] = (
        calculate_mean(flow_iat)
    )

    features["Flow IAT Std"] = (
        calculate_std(flow_iat)
    )

    features["Flow IAT Max"] = (
        max(flow_iat)
        if flow_iat
        else 0
    )

    features["Flow IAT Min"] = (
        min(flow_iat)
        if flow_iat
        else 0
    )

    # --------------------------------------------------------
    # Forward IAT
    # --------------------------------------------------------

    features["Fwd IAT Total"] = (
        sum(fwd_iat)
    )

    features["Fwd IAT Mean"] = (
        calculate_mean(fwd_iat)
    )

    features["Fwd IAT Std"] = (
        calculate_std(fwd_iat)
    )

    features["Fwd IAT Max"] = (
        max(fwd_iat)
        if fwd_iat
        else 0
    )

    features["Fwd IAT Min"] = (
        min(fwd_iat)
        if fwd_iat
        else 0
    )

    # --------------------------------------------------------
    # Backward IAT
    # --------------------------------------------------------

    features["Bwd IAT Total"] = (
        sum(bwd_iat)
    )

    features["Bwd IAT Mean"] = (
        calculate_mean(bwd_iat)
    )

    features["Bwd IAT Std"] = (
        calculate_std(bwd_iat)
    )

    features["Bwd IAT Max"] = (
        max(bwd_iat)
        if bwd_iat
        else 0
    )

    features["Bwd IAT Min"] = (
        min(bwd_iat)
        if bwd_iat
        else 0
    )

    return features


# ============================================================
# TCP FLAG FEATURES
# ============================================================

def calculate_flag_features(flow):

    features = {}

    fwd_psh = 0
    bwd_psh = 0

    fwd_urg = 0
    bwd_urg = 0

    fin_count = 0
    syn_count = 0
    rst_count = 0
    psh_count = 0
    ack_count = 0
    urg_count = 0
    cwe_count = 0
    ece_count = 0

    # --------------------------------------------------------
    # TCP flags
    # --------------------------------------------------------

    for item in flow["tcp_flags"]:

        flags = item["flags"]

        direction = item["direction"]

        # FIN
        if flags & 0x01:

            fin_count += 1

        # SYN
        if flags & 0x02:

            syn_count += 1

        # RST
        if flags & 0x04:

            rst_count += 1

        # PSH
        if flags & 0x08:

            psh_count += 1

            if direction == "fwd":

                fwd_psh += 1

            else:

                bwd_psh += 1

        # ACK
        if flags & 0x10:

            ack_count += 1

        # URG
        if flags & 0x20:

            urg_count += 1

            if direction == "fwd":

                fwd_urg += 1

            else:

                bwd_urg += 1

        # ECE
        if flags & 0x40:

            ece_count += 1

        # CWR
        if flags & 0x80:

            cwe_count += 1

    features["Fwd PSH Flags"] = fwd_psh

    features["Bwd PSH Flags"] = bwd_psh

    features["Fwd URG Flags"] = fwd_urg

    features["Bwd URG Flags"] = bwd_urg

    features["FIN Flag Count"] = fin_count

    features["SYN Flag Count"] = syn_count

    features["RST Flag Count"] = rst_count

    features["PSH Flag Count"] = psh_count

    features["ACK Flag Count"] = ack_count

    features["URG Flag Count"] = urg_count

    features["CWE Flag Count"] = cwe_count

    features["ECE Flag Count"] = ece_count

    return features


# ============================================================
# PACKET FEATURES
# ============================================================

def calculate_packet_features(flow):

    fwd = flow["fwd_packets"]

    bwd = flow["bwd_packets"]

    all_packets = fwd + bwd

    # --------------------------------------------------------
    # Header lengths
    # --------------------------------------------------------

    fwd_header_length = sum(
        flow["fwd_header_lengths"]
    )

    bwd_header_length = sum(
        flow["bwd_header_lengths"]
    )

    # --------------------------------------------------------
    # Duration
    # --------------------------------------------------------

    duration = (
        flow["last_time"] -
        flow["start_time"]
    ).total_seconds()

    if duration == 0:

        duration = 0.000001

    # --------------------------------------------------------
    # Packet rates
    # --------------------------------------------------------

    fwd_packets_per_second = (
        len(fwd) / duration
    )

    bwd_packets_per_second = (
        len(bwd) / duration
    )

    # --------------------------------------------------------
    # Packet statistics
    # --------------------------------------------------------

    if all_packets:

        min_packet_length = min(
            all_packets
        )

        max_packet_length = max(
            all_packets
        )

        packet_length_mean = np.mean(
            all_packets
        )

        packet_length_std = (
            np.std(all_packets)
            if len(all_packets) > 1
            else 0
        )

        packet_length_variance = (
            np.var(all_packets)
            if len(all_packets) > 1
            else 0
        )

    else:

        min_packet_length = 0
        max_packet_length = 0
        packet_length_mean = 0
        packet_length_std = 0
        packet_length_variance = 0

    # --------------------------------------------------------
    # Down / Up ratio
    # --------------------------------------------------------

    if len(fwd) == 0:

        down_up_ratio = 0

    else:

        down_up_ratio = (
            len(bwd) /
            len(fwd)
        )

    # --------------------------------------------------------
    # Average packet size
    # --------------------------------------------------------

    if all_packets:

        average_packet_size = (
            sum(all_packets) /
            len(all_packets)
        )

    else:

        average_packet_size = 0

    # --------------------------------------------------------
    # Average forward segment size
    # --------------------------------------------------------

    if fwd:

        avg_fwd_segment_size = (
            sum(fwd) /
            len(fwd)
        )

    else:

        avg_fwd_segment_size = 0

    # --------------------------------------------------------
    # Average backward segment size
    # --------------------------------------------------------

    if bwd:

        avg_bwd_segment_size = (
            sum(bwd) /
            len(bwd)
        )

    else:

        avg_bwd_segment_size = 0

    return {

        "Fwd Header Length":
            fwd_header_length,

        "Bwd Header Length":
            bwd_header_length,

        "Fwd Packets/s":
            fwd_packets_per_second,

        "Bwd Packets/s":
            bwd_packets_per_second,

        "Min Packet Length":
            min_packet_length,

        "Max Packet Length":
            max_packet_length,

        "Packet Length Mean":
            packet_length_mean,

        "Packet Length Std":
            packet_length_std,

        "Packet Length Variance":
            packet_length_variance,

        "Down/Up Ratio":
            down_up_ratio,

        "Average Packet Size":
            average_packet_size,

        "Avg Fwd Segment Size":
            avg_fwd_segment_size,

        "Avg Bwd Segment Size":
            avg_bwd_segment_size,

        "Fwd Header Length.1":
            fwd_header_length
    }


# ============================================================
# BULK / SUBFLOW FEATURES
# ============================================================

def calculate_bulk_subflow_features(flow):

    fwd = flow["fwd_packets"]

    bwd = flow["bwd_packets"]

    # --------------------------------------------------------
    # Bulk features
    #
    # We currently don't track CICIDS bulk-transfer state.
    # Therefore these remain zero.
    # --------------------------------------------------------

    fwd_avg_bytes_bulk = 0
    fwd_avg_packets_bulk = 0
    fwd_avg_bulk_rate = 0

    bwd_avg_bytes_bulk = 0
    bwd_avg_packets_bulk = 0
    bwd_avg_bulk_rate = 0

    # --------------------------------------------------------
    # Subflow
    # --------------------------------------------------------

    subflow_fwd_packets = len(fwd)

    subflow_fwd_bytes = sum(fwd)

    subflow_bwd_packets = len(bwd)

    subflow_bwd_bytes = sum(bwd)

    # --------------------------------------------------------
    # Initial TCP windows
    # --------------------------------------------------------

    if flow["fwd_tcp_windows"]:

        init_win_forward = (
            flow["fwd_tcp_windows"][0]
        )

    else:

        init_win_forward = 0

    if flow["bwd_tcp_windows"]:

        init_win_backward = (
            flow["bwd_tcp_windows"][0]
        )

    else:

        init_win_backward = 0

    # --------------------------------------------------------
    # Forward data packets
    # --------------------------------------------------------

    act_data_pkt_fwd = (
        flow["fwd_data_packets"]
    )

    # --------------------------------------------------------
    # Minimum forward segment size
    #
    # Use TCP payload sizes.
    # --------------------------------------------------------

    forward_segments = (
        flow["fwd_segment_sizes"]
    )

    if forward_segments:

        min_seg_size_forward = min(
            forward_segments
        )

    else:

        min_seg_size_forward = 0

    return {

        "Fwd Avg Bytes/Bulk":
            fwd_avg_bytes_bulk,

        "Fwd Avg Packets/Bulk":
            fwd_avg_packets_bulk,

        "Fwd Avg Bulk Rate":
            fwd_avg_bulk_rate,

        "Bwd Avg Bytes/Bulk":
            bwd_avg_bytes_bulk,

        "Bwd Avg Packets/Bulk":
            bwd_avg_packets_bulk,

        "Bwd Avg Bulk Rate":
            bwd_avg_bulk_rate,

        "Subflow Fwd Packets":
            subflow_fwd_packets,

        "Subflow Fwd Bytes":
            subflow_fwd_bytes,

        "Subflow Bwd Packets":
            subflow_bwd_packets,

        "Subflow Bwd Bytes":
            subflow_bwd_bytes,

        "Init_Win_bytes_forward":
            init_win_forward,

        "Init_Win_bytes_backward":
            init_win_backward,

        "act_data_pkt_fwd":
            act_data_pkt_fwd,

        "min_seg_size_forward":
            min_seg_size_forward
    }


# ============================================================
# ACTIVE / IDLE FEATURES
# ============================================================

def calculate_active_idle_features(flow):

    all_times = (
        flow["fwd_times"] +
        flow["bwd_times"]
    )

    all_times.sort()

    active_periods = []

    idle_periods = []

    if len(all_times) >= 2:

        gaps = [

            (
                all_times[i] -
                all_times[i - 1]
            ).total_seconds()
            * 1_000_000

            for i in range(
                1,
                len(all_times)
            )
        ]

        current_active = []

        for gap in gaps:

            # ------------------------------------------------
            # Active period
            # ------------------------------------------------

            if gap <= 1_000_000:

                current_active.append(
                    gap
                )

            # ------------------------------------------------
            # Idle period
            # ------------------------------------------------

            else:

                if current_active:

                    active_periods.append(
                        sum(current_active)
                    )

                idle_periods.append(
                    gap
                )

                current_active = []

        if current_active:

            active_periods.append(
                sum(current_active)
            )

    # ========================================================
    # ACTIVE
    # ========================================================

    if active_periods:

        active_mean = np.mean(
            active_periods
        )

        active_std = (
            np.std(active_periods)
            if len(active_periods) > 1
            else 0
        )

        active_max = max(
            active_periods
        )

        active_min = min(
            active_periods
        )

    else:

        active_mean = 0
        active_std = 0
        active_max = 0
        active_min = 0

    # ========================================================
    # IDLE
    # ========================================================

    if idle_periods:

        idle_mean = np.mean(
            idle_periods
        )

        idle_std = (
            np.std(idle_periods)
            if len(idle_periods) > 1
            else 0
        )

        idle_max = max(
            idle_periods
        )

        idle_min = min(
            idle_periods
        )

    else:

        idle_mean = 0
        idle_std = 0
        idle_max = 0
        idle_min = 0

    return {

        "Active Mean":
            active_mean,

        "Active Std":
            active_std,

        "Active Max":
            active_max,

        "Active Min":
            active_min,

        "Idle Mean":
            idle_mean,

        "Idle Std":
            idle_std,

        "Idle Max":
            idle_max,

        "Idle Min":
            idle_min
    }


# ============================================================
# CALCULATE ALL FEATURES
# ============================================================

def calculate_all_features(flow):

    features = {}

    features.update(
        calculate_basic_features(flow)
    )

    features.update(
        calculate_timing_features(flow)
    )

    features.update(
        calculate_flag_features(flow)
    )

    features.update(
        calculate_packet_features(flow)
    )

    features.update(
        calculate_bulk_subflow_features(flow)
    )

    features.update(
        calculate_active_idle_features(flow)
    )

    return features


# ============================================================
# FEATURE NAMES
# ============================================================

feature_names = [

    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",

    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",

    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",

    "Flow Bytes/s",
    "Flow Packets/s",

    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",

    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",

    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",

    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",

    "Fwd Header Length",
    "Bwd Header Length",

    "Fwd Packets/s",
    "Bwd Packets/s",

    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",

    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",

    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",

    "Fwd Header Length.1",

    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",

    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",

    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",

    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",

    "act_data_pkt_fwd",
    "min_seg_size_forward",

    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",

    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min"
]


# ============================================================
# CHECK FEATURE COUNT
# ============================================================

if len(feature_names) != 78:

    raise RuntimeError(
        f"Expected 78 feature names, "
        f"but found {len(feature_names)}"
    )


# ============================================================
# CSV CAPTURE MODE
# ============================================================

if __name__ == "__main__":

    print("Starting packet capture...")

    sniff(
        prn=process_packet,
        count=100
    )

    print(
        "\nCapture finished."
    )

    print(
        "Total flows:",
        len(flows)
    )

    captured_features = []

    # ========================================================
    # CALCULATE FEATURES
    # ========================================================

    for i, flow in enumerate(
        flows.values(),
        start=1
    ):

        print(
            f"\nFlow {i}"
        )

        print(
            "Source:",
            flow["source_ip"],
            ":",
            flow["source_port"]
        )

        print(
            "Destination:",
            flow["destination_ip"],
            ":",
            flow["destination_port"]
        )

        print(
            "Protocol:",
            flow["protocol"]
        )

        print(
            "Total packets:",
            len(flow["packets"])
        )

        print(
            "Forward packets:",
            len(flow["fwd_packets"])
        )

        print(
            "Backward packets:",
            len(flow["bwd_packets"])
        )

        features = calculate_all_features(
            flow
        )

        captured_features.append(
            features
        )

        print(
            "Number of features:",
            len(features)
        )

    # ========================================================
    # VALIDATE FEATURES
    # ========================================================

    print(
        "\nChecking feature count..."
    )

    for features in captured_features:

        missing = [
            feature
            for feature in feature_names
            if feature not in features
        ]

        extra = [
            feature
            for feature in features
            if feature not in feature_names
        ]

        print(
            "Calculated features:",
            len(features)
        )

        print(
            "Expected features:",
            len(feature_names)
        )

        print(
            "Missing features:",
            missing
        )

        print(
            "Extra features:",
            extra
        )

    # ========================================================
    # WRITE CSV
    # ========================================================

    with open(
        "captured_flows.csv",
        "w",
        newline=""
    ) as file:

        writer = csv.writer(file)

        writer.writerow(
            feature_names
        )

        for features in captured_features:

            row = [
                features.get(
                    feature,
                    0
                )
                for feature in feature_names
            ]

            writer.writerow(row)

    print(
        "\n78-feature CSV created."
    )