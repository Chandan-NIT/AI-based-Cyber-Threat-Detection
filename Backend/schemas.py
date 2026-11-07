from pydantic import BaseModel
from typing import Dict


class PredictionRequest(BaseModel):
    features: Dict[str, float]