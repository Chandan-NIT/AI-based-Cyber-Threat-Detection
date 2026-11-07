from services.predictor import predict_flow


def predict_captured_flow(features):
    """
    Send a completed 78-feature flow to the ML model.
    """

    prediction = predict_flow(features)

    print("ML Prediction:", prediction)

    return prediction