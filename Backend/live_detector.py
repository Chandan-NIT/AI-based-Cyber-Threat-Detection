from scapy.all import sniff
import sys
from pathlib import Path
from datetime import datetime, timedelta
import socket


# =========================================================
# PROJECT PATH
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

sys.path.append(
    str(PROJECT_ROOT / "Datacapture")
)


# =========================================================
# IMPORT PACKET CAPTURE
# =========================================================

from capture import (
    process_packet,
    flows
)


# =========================================================
# IMPORT FLOW PROCESSING
# =========================================================

from services.flow_services import (
    check_completed_flows,
    process_completed_flow
)


# =========================================================
# IMPORT DATABASE
# =========================================================

sys.path.append(
    str(PROJECT_ROOT / "Backend")
)

from database import insert_detection


# =========================================================
# GET LOCAL IP
# =========================================================

def get_local_ip():

    try:

        socket_connection = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        socket_connection.connect(
            ("8.8.8.8", 80)
        )

        local_ip = socket_connection.getsockname()[0]

        socket_connection.close()

        return local_ip

    except Exception:

        return None


LOCAL_IP = get_local_ip()


print(
    f"Local machine IP: {LOCAL_IP}"
)


# =========================================================
# PORT SCAN SETTINGS
# =========================================================

PORT_SCAN_WINDOW = 5

PORT_SCAN_THRESHOLD = 10


# =========================================================
# PORT SCAN TRACKER
# =========================================================

port_scan_tracker = {}


# =========================================================
# DDOS SETTINGS
# =========================================================

DDOS_WINDOW = 5

DDOS_PACKET_THRESHOLD = 100

DDOS_FLOW_THRESHOLD = 20

DDOS_BYTE_THRESHOLD = 50000


# =========================================================
# DDOS TRACKER
# =========================================================

ddos_tracker = {}


# =========================================================
# CHECK FOR PORT SCAN
# =========================================================

def check_port_scan(flow):

    source_ip = flow["source_ip"]

    destination_ip = flow["destination_ip"]

    destination_port = flow["destination_port"]

    current_time = flow["last_time"]


    tracker_key = (
        source_ip,
        destination_ip
    )


    # -----------------------------------------------------
    # Create tracker
    # -----------------------------------------------------

    if tracker_key not in port_scan_tracker:

        port_scan_tracker[tracker_key] = {

            "ports": [],

            "alerted": False
        }


    tracker = port_scan_tracker[tracker_key]


    # -----------------------------------------------------
    # Add destination port
    # -----------------------------------------------------

    tracker["ports"].append(

        (
            destination_port,
            current_time
        )
    )


    # -----------------------------------------------------
    # Remove old ports
    # -----------------------------------------------------

    cutoff_time = (

        current_time
        - timedelta(
            seconds=PORT_SCAN_WINDOW
        )
    )


    tracker["ports"] = [

        (port, timestamp)

        for port, timestamp in tracker["ports"]

        if timestamp >= cutoff_time
    ]


    # -----------------------------------------------------
    # Count unique ports
    # -----------------------------------------------------

    unique_ports = set(

        port

        for port, timestamp
        in tracker["ports"]
    )


    port_count = len(unique_ports)


    print(

        f"Port scan tracker: "
        f"{source_ip} -> {destination_ip} "
        f"| Unique ports: {port_count}"
    )


    # -----------------------------------------------------
    # Detect port scan
    # -----------------------------------------------------

    if (

        port_count >= PORT_SCAN_THRESHOLD

        and not tracker["alerted"]
    ):

        tracker["alerted"] = True

        return True, port_count


    return False, port_count


# =========================================================
# CHECK FOR DDOS
# =========================================================

def check_ddos(flow):

    source_ip = flow["source_ip"]

    destination_ip = flow["destination_ip"]

    current_time = flow["last_time"]


    # =====================================================
    # IMPORTANT
    #
    # Only monitor traffic coming INTO this machine.
    #
    # Example:
    #
    # 192.168.0.105 -> 192.168.0.190
    #
    # is monitored.
    #
    # But:
    #
    # 192.168.0.190 -> Google
    #
    # is ignored.
    # =====================================================

    if destination_ip != LOCAL_IP:

        return (
            False,
            0,
            0,
            0
        )


    tracker_key = (

        source_ip,
        destination_ip
    )


    # -----------------------------------------------------
    # Create tracker
    # -----------------------------------------------------

    if tracker_key not in ddos_tracker:

        ddos_tracker[tracker_key] = {

            "flows": [],

            "alerted": False
        }


    tracker = ddos_tracker[tracker_key]


    # -----------------------------------------------------
    # Flow information
    # -----------------------------------------------------

    packet_count = len(
        flow["packets"]
    )


    total_bytes = sum(

        packet["length"]

        for packet in flow["packets"]
    )


    # -----------------------------------------------------
    # Add flow
    # -----------------------------------------------------

    tracker["flows"].append(

        (
            current_time,
            packet_count,
            total_bytes
        )
    )


    # -----------------------------------------------------
    # Remove flows older than 5 seconds
    # -----------------------------------------------------

    cutoff_time = (

        current_time
        - timedelta(
            seconds=DDOS_WINDOW
        )
    )


    active_flows = []

    total_packets = 0

    total_bytes_in_window = 0


    for (

        timestamp,
        packets,
        bytes_count

    ) in tracker["flows"]:


        if timestamp >= cutoff_time:

            active_flows.append(

                (
                    timestamp,
                    packets,
                    bytes_count
                )
            )


            total_packets += packets

            total_bytes_in_window += bytes_count


    tracker["flows"] = active_flows


    # -----------------------------------------------------
    # Calculate statistics
    # -----------------------------------------------------

    flow_count = len(
        active_flows
    )


    packet_rate = (

        total_packets
        / DDOS_WINDOW
    )


    byte_rate = (

        total_bytes_in_window
        / DDOS_WINDOW
    )


    print(

        f"DDoS tracker: "
        f"{source_ip} -> {destination_ip} "
        f"| Flows: {flow_count} "
        f"| Packets: {total_packets} "
        f"| Bytes: {total_bytes_in_window} "
        f"| Packets/s: {packet_rate:.2f} "
        f"| Bytes/s: {byte_rate:.2f}"
    )


    # =====================================================
    # DDOS DETECTION
    # =====================================================
    threshold_reached = (

        total_packets >= DDOS_PACKET_THRESHOLD

        or

        total_bytes_in_window >= DDOS_BYTE_THRESHOLD
    )


    if (

        threshold_reached

        and not tracker["alerted"]
    ):

        tracker["alerted"] = True


        return (

            True,

            flow_count,

            total_packets,

            total_bytes_in_window
        )


    return (

        False,

        flow_count,

        total_packets,

        total_bytes_in_window
    )


# =========================================================
# CLEAN PORT SCAN TRACKER
# =========================================================

def cleanup_port_scan_tracker():

    current_time = datetime.now()

    keys_to_remove = []


    for key, tracker in port_scan_tracker.items():


        if not tracker["ports"]:

            keys_to_remove.append(key)

            continue


        latest_time = max(

            timestamp

            for port, timestamp
            in tracker["ports"]
        )


        idle_time = (

            current_time
            - latest_time
        ).total_seconds()


        if idle_time > PORT_SCAN_WINDOW:

            keys_to_remove.append(key)


    for key in keys_to_remove:

        del port_scan_tracker[key]


# =========================================================
# CLEAN DDOS TRACKER
# =========================================================

def cleanup_ddos_tracker():

    current_time = datetime.now()

    keys_to_remove = []


    for key, tracker in ddos_tracker.items():


        if not tracker["flows"]:

            keys_to_remove.append(key)

            continue


        latest_time = max(

            timestamp

            for timestamp, packets, bytes_count

            in tracker["flows"]
        )


        idle_time = (

            current_time
            - latest_time
        ).total_seconds()


        if idle_time > DDOS_WINDOW:

            keys_to_remove.append(key)


    for key in keys_to_remove:

        del ddos_tracker[key]


# =========================================================
# PROCESS COMPLETED FLOWS
# =========================================================

def process_finished_flows():

    completed_flows = check_completed_flows(
        flows
    )


    for flow_key, flow in completed_flows:


        # =================================================
        # RANDOM FOREST
        # =================================================

        prediction = process_completed_flow(
            flow
        )


        print(

            f"\nFlow detected: {prediction}"
        )


        # =================================================
        # PORT SCAN
        # =================================================

        is_port_scan, unique_port_count = (

            check_port_scan(flow)
        )


        if is_port_scan:

            print("\n")

            print(
                "========================================"
            )

            print(
                "        PORT SCAN DETECTED"
            )

            print(
                "========================================"
            )

            print(
                f"Source IP      : "
                f"{flow['source_ip']}"
            )

            print(
                f"Destination IP : "
                f"{flow['destination_ip']}"
            )

            print(
                f"Unique Ports   : "
                f"{unique_port_count}"
            )

            print(
                "Detection Type : "
                "Behavioral Analysis"
            )

            print(
                "========================================"
            )


            # -------------------------------------------------
            # Save PortScan event
            # -------------------------------------------------

            timestamp = datetime.now().isoformat()


            packet_count = len(
                flow["packets"]
            )


            total_bytes = sum(

                packet["length"]

                for packet in flow["packets"]
            )


            duration = (

                flow["last_time"]
                - flow["start_time"]
            ).total_seconds()


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

                "PortScan",

                1.0
            )


        # =================================================
        # DDOS
        # =================================================

        (

            is_ddos,

            flow_count,

            total_packets,

            total_bytes

        ) = check_ddos(flow)


        if is_ddos:

            print("\n")

            print(
                "========================================"
            )

            print(
                "           DDOS DETECTED"
            )

            print(
                "========================================"
            )

            print(
                f"Source IP      : "
                f"{flow['source_ip']}"
            )

            print(
                f"Destination IP : "
                f"{flow['destination_ip']}"
            )

            print(
                f"Flows          : "
                f"{flow_count}"
            )

            print(
                f"Packets        : "
                f"{total_packets}"
            )

            print(
                f"Total Bytes    : "
                f"{total_bytes}"
            )

            print(
                "Detection Type : "
                "Behavioral Analysis"
            )

            print(
                "========================================"
            )


            # -------------------------------------------------
            # Save ONE behavioral DDoS event
            # -------------------------------------------------

            timestamp = datetime.now().isoformat()


            packet_count = len(
                flow["packets"]
            )


            duration = (

                flow["last_time"]
                - flow["start_time"]
            ).total_seconds()


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

                "DDoS",

                1.0
            )


        # =================================================
        # REMOVE COMPLETED FLOW
        # =================================================

        if flow_key in flows:

            del flows[flow_key]


    # =====================================================
    # CLEAN TRACKERS
    # =====================================================

    cleanup_port_scan_tracker()

    cleanup_ddos_tracker()


# =========================================================
# START LIVE DETECTION
# =========================================================

print(
    "Starting live detection..."
)


while True:

    sniff(

        prn=process_packet,

        timeout=1
    )


    process_finished_flows()