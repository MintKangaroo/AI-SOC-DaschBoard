"""위협 분석: AI · ML · MITRE · 위협 인텔리전스
   (api_bp 공유 — api/routes.py 가 임포트해 라우트를 등록한다)"""
from flask import request, jsonify, current_app
from api._common import api_bp, get_services, _mitre, _hash_scan_allowed


# ------------------------------------------------------------------ #
#  AI 분석
# ------------------------------------------------------------------ #

@api_bp.route("/ai/status", methods=["GET"])
def ai_status():
    _, _, _, _, ai, _ = get_services()
    return jsonify(ai.get_status())


@api_bp.route("/ai/chat", methods=["POST"])
def ai_chat():
    _, _, _, _, ai, _ = get_services()
    data    = request.get_json()
    message = data.get("message", "").strip()
    context = data.get("context", {})
    if not message:
        return jsonify({"error": "메시지가 필요합니다"}), 400
    response = ai.chat(message, context)
    return jsonify({"response": response})


@api_bp.route("/ai/analyze/alert/<int:alert_id>", methods=["POST"])
def analyze_alert(alert_id):
    _, td, _, _, ai, _ = get_services()
    alerts = td.get_alerts(limit=500)
    target = next((a for a in alerts if a["id"] == alert_id), None)
    if not target:
        return jsonify({"error": "알림을 찾을 수 없습니다"}), 404
    result = ai.analyze_alert(target, async_mode=False)
    return jsonify(result)


@api_bp.route("/ai/analyze/traffic", methods=["POST"])
def analyze_traffic():
    pa, _, _, _, ai, _ = get_services()
    summary = {
        "stats": pa.get_stats(),
        "top_talkers": pa.get_top_talkers(),
        "protocol_dist": pa.get_protocol_distribution(),
        "traffic_history": pa.get_traffic_history()[-10:],
    }
    result = ai.analyze_packet_summary(summary, async_mode=False)
    return jsonify(result)


@api_bp.route("/ai/history", methods=["GET"])
def ai_history():
    _, _, _, _, ai, _ = get_services()
    return jsonify({"history": ai.get_history()})


# ------------------------------------------------------------------ #
#  ML 자체 모델 분석
# ------------------------------------------------------------------ #

@api_bp.route("/ml/status", methods=["GET"])
def ml_status():
    _, _, _, _, _, ml = get_services()
    return jsonify({
        "stats":  ml.get_stats(),
        "rl":     ml.get_rl_status(),
    })


@api_bp.route("/ml/analyze", methods=["POST"])
def ml_analyze():
    pa, _, _, _, _, ml = get_services()
    result = ml.analyze_now(pa.get_stats())
    return jsonify(result)


@api_bp.route("/ml/log", methods=["GET"])
def ml_log():
    _, _, _, _, _, ml = get_services()
    limit = int(request.args.get("limit", 20))
    return jsonify({"log": ml.get_log(limit)})


@api_bp.route("/ml/decision", methods=["GET"])
def ml_decision():
    """ML 의사결정 지원 — 유사 위협 그룹핑 + 정오탐 분석 + 대응 권고"""
    ds = current_app._get_current_object().decision_support
    return jsonify(ds.get_summary())


@api_bp.route("/ml/feedback", methods=["POST"])
def ml_feedback():
    _, _, _, _, _, ml = get_services()
    data = request.get_json()
    is_fp = data.get("is_false_positive", False)
    ml.mark_alert(is_fp=is_fp)
    return jsonify({"ok": True})


# ------------------------------------------------------------------ #
#  MITRE ATT&CK
# ------------------------------------------------------------------ #

@api_bp.route("/mitre/matrix", methods=["GET"])
def mitre_matrix():
    return jsonify(_mitre().get_matrix())


@api_bp.route("/mitre/recent", methods=["GET"])
def mitre_recent():
    limit = int(request.args.get("limit", 50))
    return jsonify({"events": _mitre().get_recent(limit)})


@api_bp.route("/mitre/top", methods=["GET"])
def mitre_top():
    top = int(request.args.get("top", 10))
    return jsonify({"top": _mitre().get_top_techniques(top)})


@api_bp.route("/mitre/technique/<technique_id>", methods=["GET"])
def mitre_technique_detail(technique_id):
    """특정 Technique의 상세(발생 이력, 관련 알림, 방어권고)를 반환."""
    return jsonify(_mitre().get_technique_detail(technique_id))


# ------------------------------------------------------------------ #
#  위협 인텔리전스 (악성 IP / URL 피드)
# ------------------------------------------------------------------ #

@api_bp.route("/threat-intel/status", methods=["GET"])
def ti_status():
    ti = current_app._get_current_object().threat_intel
    return jsonify(ti.get_status())


@api_bp.route("/threat-intel/refresh", methods=["POST"])
def ti_refresh():
    ti = current_app._get_current_object().threat_intel
    import threading as _t
    _t.Thread(target=ti._refresh_feeds, daemon=True).start()
    return jsonify({"ok": True, "message": "피드 갱신 요청됨"})
