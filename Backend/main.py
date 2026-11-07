from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from services.predictor import predict_flow
from database import (
    get_recent_detections,
    get_statistics,
    get_detection_activity,
    get_attacks
)
import subprocess
import sys
from pathlib import Path

app = FastAPI(
    title="SIH26145 Cyber Threat Detection API",
    description="AI-based detection of threats in unidirectional IP traffic",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
detector_process = None

@app.get("/detection-activity")
def detection_activity():
    return get_detection_activity()

@app.get("/statistics")
def statistics():
    return get_statistics()

@app.post("/start-scan")
def start_scan():

    global detector_process

    if detector_process is not None and detector_process.poll() is None:
        return {
            "status": "already_running"
        }

    project_root = Path(__file__).resolve().parent.parent

    detector_path = project_root / "Backend" / "live_detector.py"

    detector_process = subprocess.Popen(
        [sys.executable, str(detector_path)],
        cwd=str(project_root)
    )

    return {
        "status": "started"
    }


@app.post("/stop-scan")
def stop_scan():

    global detector_process

    if detector_process is None or detector_process.poll() is not None:

        detector_process = None

        return {
            "status": "not_running"
        }

    detector_process.terminate()
    detector_process.wait()

    detector_process = None

    return {
        "status": "stopped"
    }


@app.get("/scan-status")
def scan_status():

    global detector_process

    if detector_process is not None and detector_process.poll() is None:

        return {
            "running": True
        }

    return {
        "running": False
    }

@app.get("/")
def root():

    return {
        "message": "SIH26145 Backend is running"
    }


@app.get("/health")
def health():

    return {
        "status": "healthy"
    }

@app.get("/recent-scans")
def recent_scans(limit: int = 20):

    scans = get_recent_detections(limit)

    return {
        "scans": scans
    }
    
@app.get("/attacks")
def attacks(limit: int = 20):

    return get_attacks(limit)

@app.post("/predict")
def predict(features: dict):

    try:

        prediction = predict_flow(features)

        return {
            "prediction": prediction
        }

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )