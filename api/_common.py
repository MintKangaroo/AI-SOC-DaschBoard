import os

from flask import Blueprint, request, jsonify, current_app

api_bp = Blueprint("api", __name__)


def _hash_scan_allowed(path):
    """해시 스캔 허용 디렉터리 검사 (경로 탈출 방지)"""
    allowed = os.getenv("HASH_SCAN_ALLOWED_DIRS")
    if allowed:
        dirs = [d.strip() for d in allowed.split(",") if d.strip()]
    else:
        dirs = [os.path.expanduser("~"), os.getcwd()]
    real = os.path.realpath(path)
    for d in dirs:
        base = os.path.realpath(d)
        if real == base or real.startswith(base + os.sep):
            return True
    return False


def get_services():
    app = current_app._get_current_object()
    return (
        app.packet_analyzer,
        app.threat_detector,
        app.sysmon_parser,
        app.hash_checker,
        app.ai_analyst,
        app.ml_analyst,
    )


def _mitre():
    return current_app._get_current_object().mitre_tracker
