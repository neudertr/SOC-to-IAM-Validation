import datetime
import hashlib
import json
import os
from typing import Any

TIIR_PROCESS_LOG_PATH = os.path.join(
    os.getcwd(),
    globals().get("TIIR_PROCESS_LOG_NAME", "tiir_proces_log.jsonl"),
)


def _json_safe(value: Any):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    try:
        import pandas as pd  # type: ignore
        if isinstance(value, pd.DataFrame):
            return value.to_dict(orient="records")
        if isinstance(value, pd.Series):
            return value.to_dict()
    except Exception:
        pass
    return str(value)


def file_sha256(path: str):
    if not path or not os.path.exists(path) or not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class TIIRProcessLogger:
    def __init__(self, path: str = TIIR_PROCESS_LOG_PATH):
        self.path = path

    def reset(self, session_meta=None):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            event = {
                "ts_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "stage": "SESSION",
                "event": "session_start",
                "status": "INFO",
                "data": _json_safe(session_meta or {}),
            }
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    def log(self, stage: str, event: str, data=None, status: str = "INFO"):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        payload = {
            "ts_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "stage": stage,
            "event": event,
            "status": status,
            "data": _json_safe(data or {}),
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")


if "tiir_logger" not in globals():
    tiir_logger = TIIRProcessLogger()
