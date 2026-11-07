from fastapi import FastAPI
import sqlite3
import os


app = FastAPI()


# Database path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "Database", "cyber_threats.db")


def get_connection():
    return sqlite3.connect(DB_PATH)


@app.get("/")
def home():
    return {
        "message": "SIH26145 Cyber Threat Detection API is running"
    }


@app.get("/detections")
def get_detections():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM detections
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    detections = []

    for row in rows:

        detections.append({
            "id": row[0],
            "timestamp": row[1],
            "source_port": row[2],
            "destination_port": row[3],
            "protocol": row[4],
            "packet_count": row[5],
            "total_bytes": row[6],
            "duration": row[7],
            "prediction": row[8]
        })

    return detections

@app.get("/stats")
def get_stats():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM detections")
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
        WHERE prediction != 'BENIGN'
    """)
    attacks = cursor.fetchone()[0]

    conn.close()

    return {
        "total_flows": total_flows,
        "benign": benign,
        "attacks": attacks
    }
    
@app.get("/detections/recent")
def get_recent_detections():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM detections
        ORDER BY id DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()

    conn.close()

    detections = []

    for row in rows:

        detections.append({
            "id": row[0],
            "timestamp": row[1],
            "source_port": row[2],
            "destination_port": row[3],
            "protocol": row[4],
            "packet_count": row[5],
            "total_bytes": row[6],
            "duration": row[7],
            "prediction": row[8]
        })

    return detections

@app.get("/attacks")
def get_attacks():

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
    """)

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