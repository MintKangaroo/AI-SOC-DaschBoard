"""탐지·수집: 패킷 · 위협알림(이력/CSV) · Sysmon · 해시
   (api_bp 공유 — api/routes.py 가 임포트해 라우트를 등록한다)"""
from flask import request, jsonify, current_app
from api._common import api_bp, get_services, _mitre, _hash_scan_allowed, audit_record


# ------------------------------------------------------------------ #
#  패킷 분석
# ------------------------------------------------------------------ #

@api_bp.route("/packets", methods=["GET"])
def get_packets():
    pa, *_ = get_services()
    limit = int(request.args.get("limit", 50))
    return jsonify({"packets": pa.get_recent_packets(limit), "stats": pa.get_stats()})


@api_bp.route("/packets/stats", methods=["GET"])
def packet_stats():
    pa, *_ = get_services()
    return jsonify({
        "stats": pa.get_stats(),
        "top_talkers": pa.get_top_talkers(),
        "protocol_dist": pa.get_protocol_distribution(),
        "traffic_history": pa.get_traffic_history(),
    })


# ------------------------------------------------------------------ #
#  위협 탐지
# ------------------------------------------------------------------ #

@api_bp.route("/alerts", methods=["GET"])
def get_alerts():
    _, td, *_ = get_services()
    limit    = int(request.args.get("limit", 100))
    severity = request.args.get("severity")
    status   = request.args.get("status")
    return jsonify({
        "alerts": td.get_alerts(limit=limit, severity=severity, status=status),
        "stats":  td.get_stats(),
    })


@api_bp.route("/alerts/history", methods=["GET"])
def alerts_history():
    """전체 알림 이력 검색 (기간·심각도·상태·유형·IP·본문). 페이지네이션."""
    _, td, *_ = get_services()
    a = request.args
    page  = max(1, a.get("page", 1, type=int))
    limit = min(200, max(1, a.get("limit", 50, type=int)))
    rows, total = td.search_alerts(
        severity=a.get("severity") or None,
        status=a.get("status") or None,
        threat_type=a.get("threat_type") or None,
        ip=(a.get("ip") or "").strip() or None,
        text=(a.get("text") or "").strip() or None,
        date_from=a.get("from") or None,
        date_to=a.get("to") or None,
        limit=limit, offset=(page - 1) * limit,
    )
    return jsonify({
        "alerts": rows, "total": total, "page": page, "limit": limit,
        "pages": (total + limit - 1) // limit,
        "labels": td.threat_type_labels(),
    })


@api_bp.route("/alerts/history/export.csv", methods=["GET"])
def alerts_history_export():
    """현재 검색 조건의 알림 이력을 CSV로 내보내기 (최대 10000건)."""
    import csv, io
    from flask import Response
    _, td, *_ = get_services()
    a = request.args
    rows, _total = td.search_alerts(
        severity=a.get("severity") or None,
        status=a.get("status") or None,
        threat_type=a.get("threat_type") or None,
        ip=(a.get("ip") or "").strip() or None,
        text=(a.get("text") or "").strip() or None,
        date_from=a.get("from") or None,
        date_to=a.get("to") or None,
        limit=10000, offset=0,
    )
    buf = io.StringIO()
    buf.write("﻿")  # Excel 한글 깨짐 방지 BOM
    w = csv.writer(buf)
    w.writerow(["id", "timestamp", "severity", "threat_type", "threat_label",
                "src_ip", "dst_ip", "status", "description"])
    for r in rows:
        w.writerow([r["id"], r["timestamp"], r["severity"], r["threat_type"],
                    r.get("threat_label", ""), r["src_ip"], r["dst_ip"],
                    r["status"], r["description"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=alert_history.csv"})


@api_bp.route("/alerts/<int:alert_id>/status", methods=["PUT"])
def update_alert_status(alert_id):
    _, td, *_ = get_services()
    data = request.get_json()
    status = data.get("status")
    if status not in ("OPEN", "ACK", "CLOSED"):
        return jsonify({"error": "유효하지 않은 상태"}), 400
    ok = td.update_alert_status(alert_id, status,
                                note=data.get("note"),
                                assignee=data.get("assignee"))
    if ok:
        act = {"ACK": "ALERT_ACK", "CLOSED": "ALERT_CLOSE",
               "OPEN": "ALERT_REOPEN"}.get(status, "ALERT_ACK")
        audit_record(act, target=f"알림 #{alert_id}", detail=data.get("note") or "")
    return jsonify({"success": ok})


# ------------------------------------------------------------------ #
#  Sysmon
# ------------------------------------------------------------------ #

@api_bp.route("/sysmon/events", methods=["GET"])
def sysmon_events():
    _, _, sp, *_ = get_services()
    limit    = int(request.args.get("limit", 100))
    event_id = request.args.get("event_id", type=int)
    severity = request.args.get("severity")
    return jsonify({
        "events": sp.get_events(limit=limit, event_id=event_id, severity=severity),
        "stats":  sp.get_stats(),
    })


# ------------------------------------------------------------------ #
#  해시 검사
# ------------------------------------------------------------------ #

@api_bp.route("/hash/check", methods=["POST"])
def check_hash():
    _, _, _, hc, _, _ = get_services()
    data = request.get_json()
    hash_val = data.get("hash", "").strip()
    algo     = data.get("algorithm", "sha256")
    if not hash_val:
        return jsonify({"error": "hash 값이 필요합니다"}), 400
    return jsonify(hc.check_hash(hash_val, algo))


@api_bp.route("/hash/file", methods=["POST"])
def hash_file():
    _, _, _, hc, _, _ = get_services()
    data = request.get_json()
    path = data.get("path", "")
    if not path:
        return jsonify({"error": "파일 경로가 필요합니다"}), 400
    if not _hash_scan_allowed(path):
        return jsonify({"error": "허용되지 않은 경로입니다 (HASH_SCAN_ALLOWED_DIRS 참고)"}), 403
    return jsonify(hc.scan_file(path))


@api_bp.route("/hash/history", methods=["GET"])
def hash_history():
    _, _, _, hc, _, _ = get_services()
    return jsonify({"history": hc.get_scan_history()})
