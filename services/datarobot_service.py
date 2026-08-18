import os
from typing import Any, Dict

import datarobot as dr
import pandas as pd
from datarobot_predict.deployment import predict
from dotenv import load_dotenv


load_dotenv()

DATAROBOT_API_TOKEN = os.getenv("DATAROBOT_API_TOKEN")
DATAROBOT_ENDPOINT = os.getenv(
    "DATAROBOT_ENDPOINT",
    "https://app.datarobot.com/api/v2",
)
DATAROBOT_DEPLOYMENT_ID = os.getenv("DATAROBOT_DEPLOYMENT_ID")

ANOMALY_THRESHOLD = float(
    os.getenv("DATAROBOT_ANOMALY_THRESHOLD", "0.1167")
)


if not DATAROBOT_API_TOKEN:
    raise RuntimeError("DATAROBOT_API_TOKEN is missing.")

if not DATAROBOT_DEPLOYMENT_ID:
    raise RuntimeError("DATAROBOT_DEPLOYMENT_ID is missing.")


def get_datarobot_client():
    return dr.Client(
        endpoint=DATAROBOT_ENDPOINT,
        token=DATAROBOT_API_TOKEN,
    )


def get_deployment():
    get_datarobot_client()
    return dr.Deployment.get(DATAROBOT_DEPLOYMENT_ID)


def predict_anomaly(flow_features: Dict[str, Any]) -> Dict[str, Any]:

    if not flow_features:
        raise ValueError("flow_features are required.")

    input_df = pd.DataFrame([flow_features])

    deployment = get_deployment()

    result_df, response = predict(
        deployment=deployment,
        data_frame=input_df,
    )

    if result_df.empty:
        raise RuntimeError("DataRobot returned an empty prediction.")

    if "ANOMALY_SCORE" not in result_df.columns:
        raise RuntimeError(
            f"ANOMALY_SCORE not found. Columns: {list(result_df.columns)}"
        )

    anomaly_score = float(result_df.iloc[0]["ANOMALY_SCORE"])

    if not 0.0 <= anomaly_score <= 1.0:
        raise RuntimeError(
            f"Invalid anomaly score: {anomaly_score}"
        )

    is_anomaly = anomaly_score > ANOMALY_THRESHOLD

    headers = dict(response)

    return {
        "anomaly_score": anomaly_score,
        "is_anomaly": is_anomaly,
        "model_name": "Isolation Forest",
        "model_version": headers.get("x-datarobot-model-id"),
        "prediction_metadata": {
            "deployment_id": DATAROBOT_DEPLOYMENT_ID,
            "deployment_name": getattr(deployment, "label", None),
            "threshold": ANOMALY_THRESHOLD,
            "threshold_rule": "anomaly_score > threshold",
            "prediction_columns": list(result_df.columns),
        },
    }