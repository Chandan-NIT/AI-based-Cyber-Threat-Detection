import sqlite3
import os


# Find the main project folder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Database will be stored inside Database/
DB_PATH = os.path.join(BASE_DIR, "Database", "cyber_threats.db")


# Create a database connection
def get_connection():
    return sqlite3.connect(DB_PATH)


def create_database():

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,

            source_ip TEXT,
            destination_ip TEXT,

            source_port INTEGER,
            destination_port INTEGER,
            protocol INTEGER,

            packet_count INTEGER,
            total_bytes REAL,
            duration REAL,

            prediction TEXT,
            prediction_score REAL
        )
    """)

    conn.commit()
    conn.close()


def insert_detection(
    timestamp,
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol,
    packet_count,
    total_bytes,
    duration,
    prediction,
    prediction_score
):

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO detections (
            timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            packet_count,
            total_bytes,
            duration,
            prediction,
            prediction_score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol,
        packet_count,
        total_bytes,
        duration,
        prediction,
        prediction_score
    ))

    conn.commit()
    conn.close()


def get_attacks(limit: int = 50):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            packet_count,
            total_bytes,
            duration,
            prediction,
            prediction_score
        FROM detections
        WHERE prediction != 'BENIGN'
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()

    conn.close()

    attacks = []

    for row in rows:

        attacks.append({
            "id": row[0],
            "timestamp": row[1],
            "source_ip": row[2],
            "destination_ip": row[3],
            "source_port": row[4],
            "destination_port": row[5],
            "protocol": row[6],
            "packet_count": row[7],
            "total_bytes": row[8],
            "duration": row[9],
            "prediction": row[10],
            "prediction_score": row[11]
        })

    return attacks


def get_recent_detections(limit=200):

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            packet_count,
            total_bytes,
            duration,
            prediction,
            prediction_score
        FROM detections
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return rows


def get_statistics():

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM detections
    """)

    total_flows = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM detections
        WHERE prediction = 'BENIGN'
    """)

    benign = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM detections
        WHERE prediction = 'DDoS'
    """)

    ddos = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM detections
        WHERE prediction = 'PortScan'
    """)

    portscan = cursor.fetchone()[0]

    conn.close()

    return {
        "total_flows": total_flows,
        "benign": benign,
        "ddos": ddos,
        "portscan": portscan
    }


def get_detection_activity():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            substr(timestamp, 12, 5) AS time,
            COUNT(*) AS total,
            SUM(CASE WHEN prediction = 'DDoS' THEN 1 ELSE 0 END) AS ddos,
            SUM(CASE WHEN prediction = 'PortScan' THEN 1 ELSE 0 END) AS portscan
        FROM detections
        GROUP BY time
        ORDER BY time
    """)

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "time": row[0],
            "total": row[1],
            "ddos": row[2],
            "portscan": row[3]
        }
        for row in rows
    ]


# Create the database and table first
create_database()