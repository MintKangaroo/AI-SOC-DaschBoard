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


# ------------------------------------------------------------------ #
#  내 정보 (시스템/네트워크)
# ------------------------------------------------------------------ #

@api_bp.route("/system/info", methods=["GET"])
def system_info():
    from modules import system_info as _si
    return jsonify(_si.get_all())


@api_bp.route("/system/public-ip", methods=["GET"])
def system_public_ip():
    from modules import system_info as _si
    force = request.args.get("force") in ("1", "true", "yes")
    ip = _si.get_public_ip(force=force)
    geo = _si.get_geo_info(ip) if ip else None
    return jsonify({"public_ip": ip, "geo": geo})


@api_bp.route("/threat-intel/check", methods=["POST"])
def ti_check():
    ti = current_app._get_current_object().threat_intel
    data = request.get_json() or {}
    ip = data.get("ip")
    url = data.get("url")
    return jsonify({
        "ip":  ip,  "ip_malicious":  ti.check_ip(ip) if ip else None,
        "url": url, "url_malicious": ti.check_url(url) if url else None,
    })


# ------------------------------------------------------------------ #
#  외부 시스템 연동 — SIEM (접근 로그 수집)
# ------------------------------------------------------------------ #

@api_bp.route("/integrations/siem", methods=["GET"])
def siem_status():
    siem = current_app._get_current_object().siem_collector
    return jsonify(siem.get_status())


@api_bp.route("/integrations/siem/events", methods=["GET"])
def siem_events():
    siem = current_app._get_current_object().siem_collector
    limit = int(request.args.get("limit", 100))
    source = request.args.get("source")
    suspicious = request.args.get("suspicious") in ("1", "true", "yes")
    return jsonify({"events": siem.get_events(limit=limit, source=source,
                                              suspicious_only=suspicious)})


@api_bp.route("/authlog", methods=["GET"])
def authlog_status():
    return jsonify(current_app._get_current_object().authlog.get_status())


# ------------------------------------------------------------------ #
#  IP 평판 조회 (AbuseIPDB)
# ------------------------------------------------------------------ #

@api_bp.route("/integrations/abuseipdb", methods=["GET"])
def ip_reputation_status():
    return jsonify(current_app._get_current_object().ip_reputation.get_status())


@api_bp.route("/reputation/check", methods=["POST"])
def ip_reputation_check():
    rep = current_app._get_current_object().ip_reputation
    ip = (request.get_json() or {}).get("ip")
    if not ip:
        return jsonify({"error": "ip 필요"}), 400
    return jsonify(rep.check(ip, force=True))


# ------------------------------------------------------------------ #
#  EDR (엔드포인트 탐지·대응)
# ------------------------------------------------------------------ #

@api_bp.route("/integrations/edr", methods=["GET"])
def edr_status():
    return jsonify(current_app._get_current_object().edr.get_status())


@api_bp.route("/edr/kill", methods=["POST"])
def edr_kill():
    edr = current_app._get_current_object().edr
    pid = (request.get_json() or {}).get("pid")
    if pid is None:
        return jsonify({"error": "pid 필요"}), 400
    ok, detail = edr.kill_process(pid, reason="분석가 수동 격리")
    return jsonify({"ok": ok, "detail": detail})


# ------------------------------------------------------------------ #
#  네트워크 모니터링 관제
# ------------------------------------------------------------------ #

@api_bp.route("/integrations/network", methods=["GET"])
def network_status():
    return jsonify(current_app._get_current_object().net_monitor.get_status())


# ------------------------------------------------------------------ #
#  자동화 취약점 패치 (Ansible)
# ------------------------------------------------------------------ #

@api_bp.route("/patch/status", methods=["GET"])
def patch_status():
    return jsonify(current_app._get_current_object().patch_manager.get_status())


@api_bp.route("/patch/scan", methods=["POST"])
def patch_scan():
    pm = current_app._get_current_object().patch_manager
    pm.scan()
    return jsonify(pm.get_status())


@api_bp.route("/patch/playbook", methods=["POST"])
def patch_playbook():
    pm = current_app._get_current_object().patch_manager
    security_only = (request.get_json() or {}).get("security_only", True)
    path, content = pm.generate_playbook(security_only=security_only)
    return jsonify({"path": path, "content": content})


@api_bp.route("/patch/run", methods=["POST"])
def patch_run():
    pm = current_app._get_current_object().patch_manager
    data = request.get_json() or {}
    mode = data.get("mode", "check")            # check(dry-run) | apply
    security_only = data.get("security_only", True)
    host_ids = data.get("hosts")                # 대상 호스트 id 목록(없으면 localhost)
    job = pm.run_job(mode=mode, security_only=security_only, host_ids=host_ids)
    return jsonify({k: job.get(k) for k in
                    ("id", "kind", "mode", "status", "playbook", "hosts", "started")})


@api_bp.route("/patch/command", methods=["POST"])
def patch_command():
    pm = current_app._get_current_object().patch_manager
    data = request.get_json() or {}
    command = data.get("command", "")
    mode = data.get("mode", "check")            # check(미리보기) | apply(실제 실행)
    host_ids = data.get("hosts")
    job = pm.run_command(command=command, host_ids=host_ids, mode=mode)
    return jsonify({k: job.get(k) for k in
                    ("id", "kind", "mode", "status", "result", "hosts", "started")})


# ------------------------------------------------------------------ #
#  취약점 스캐너 (포트/서비스/CVE)
# ------------------------------------------------------------------ #

@api_bp.route("/vulnscan/status", methods=["GET"])
def vulnscan_status():
    return jsonify(current_app._get_current_object().vuln_scanner.get_status())


@api_bp.route("/vulnscan/scan", methods=["POST"])
def vulnscan_scan():
    vs = current_app._get_current_object().vuln_scanner
    host_ids = (request.get_json() or {}).get("hosts")   # 대상(없으면 전체)
    result = vs.scan(host_ids=host_ids)
    return jsonify(result)


# ------------------------------------------------------------------ #
#  웹 엔드포인트 퍼저 (견고성 점검)
# ------------------------------------------------------------------ #

@api_bp.route("/fuzz/status", methods=["GET"])
def fuzz_status():
    return jsonify(current_app._get_current_object().web_fuzzer.get_status())


@api_bp.route("/fuzz/run", methods=["POST"])
def fuzz_run():
    wf = current_app._get_current_object().web_fuzzer
    data = request.get_json() or {}
    result = wf.run(
        target_id=data.get("target", "self"),
        paths=data.get("paths"),
        params=data.get("params"),
        method=data.get("method", "GET"),
    )
    return jsonify(result)


@api_bp.route("/fuzz/stop", methods=["POST"])
def fuzz_stop():
    current_app._get_current_object().web_fuzzer.stop_run()
    return jsonify({"status": "stopping"})


# ------------------------------------------------------------------ #
#  푸시 알림 (ntfy)
# ------------------------------------------------------------------ #

@api_bp.route("/notify/status", methods=["GET"])
def notify_status():
    return jsonify(current_app._get_current_object().notifier.get_status())


@api_bp.route("/notify/test", methods=["POST"])
def notify_test():
    n = current_app._get_current_object().notifier
    ok, detail = n.notify("✅ SOC 대시보드 테스트",
                          "푸시 알림이 정상 동작합니다. 이제 정탐/차단 시 이 폰으로 알림이 옵니다.",
                          severity="CRITICAL", dedup_key="test", force=True)
    return jsonify({"ok": ok, "detail": detail, "active": n.active})


# ------------------------------------------------------------------ #
#  Sigma 룰 엔진
# ------------------------------------------------------------------ #

@api_bp.route("/integrations/sigma", methods=["GET"])
def sigma_status():
    return jsonify(current_app._get_current_object().sigma.get_status())


@api_bp.route("/sigma/reload", methods=["POST"])
def sigma_reload():
    sig = current_app._get_current_object().sigma
    sig.load_rules()
    return jsonify(sig.get_status())


@api_bp.route("/sigma/toggle", methods=["POST"])
def sigma_toggle():
    sig = current_app._get_current_object().sigma
    rid = (request.get_json() or {}).get("rule_id")
    state = sig.toggle_rule(rid)
    return jsonify({"rule_id": rid, "enabled": state})


@api_bp.route("/sigma/test", methods=["POST"])
def sigma_test():
    sig = current_app._get_current_object().sigma
    fields = (request.get_json() or {}).get("fields") or {}
    return jsonify({"matches": sig.test_event(fields)})


# ------------------------------------------------------------------ #
#  일일 AI 리포트
# ------------------------------------------------------------------ #

@api_bp.route("/report/status", methods=["GET"])
def report_status():
    return jsonify(current_app._get_current_object().daily_report.get_status())


@api_bp.route("/report/generate", methods=["POST"])
def report_generate():
    r = current_app._get_current_object().daily_report.generate(trigger="manual")
    return jsonify({"id": r["id"], "generated": r["generated"],
                    "briefing": r["briefing"], "highlights": r["highlights"]})


@api_bp.route("/report/<rid>", methods=["GET"])
def report_get(rid):
    r = current_app._get_current_object().daily_report.get_report(rid)
    if not r:
        return jsonify({"error": "리포트 없음"}), 404
    return jsonify(r)


# ------------------------------------------------------------------ #
#  퍼플팀 공격 시뮬레이션 (탐지 검증)
# ------------------------------------------------------------------ #

@api_bp.route("/purple/status", methods=["GET"])
def purple_status():
    return jsonify(current_app._get_current_object().purple.get_status())


@api_bp.route("/purple/run", methods=["POST"])
def purple_run():
    p = current_app._get_current_object().purple
    sid = (request.get_json() or {}).get("scenario")
    if sid and sid != "all":
        return jsonify({"result": p.run_scenario(sid)})
    return jsonify(p.run_all())


# ------------------------------------------------------------------ #
#  SOAR 자동 대응
# ------------------------------------------------------------------ #

def _soar():
    return current_app._get_current_object().soar


@api_bp.route("/soar/status", methods=["GET"])
def soar_status():
    return jsonify(_soar().get_status())


@api_bp.route("/soar/playbooks/<pb_id>/toggle", methods=["POST"])
def soar_toggle_playbook(pb_id):
    enabled = _soar().toggle_playbook(pb_id)
    if enabled is None:
        return jsonify({"error": "플레이북 없음"}), 404
    return jsonify({"id": pb_id, "enabled": enabled})


@api_bp.route("/soar/block", methods=["POST"])
def soar_block():
    data = request.get_json() or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip 가 필요합니다"}), 400
    ok = _soar().manual_block(ip, data.get("reason", "분석가 수동 차단"))
    return jsonify({"success": ok, "message": "차단됨" if ok else "이미 차단된 IP"})


@api_bp.route("/soar/unblock", methods=["POST"])
def soar_unblock():
    data = request.get_json() or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip 가 필요합니다"}), 400
    ok = _soar().manual_unblock(ip)
    return jsonify({"success": ok})


# ------------------------------------------------------------------ #
#  인시던트 (케이스) 관리
# ------------------------------------------------------------------ #

def _incidents():
    return current_app._get_current_object().incidents


@api_bp.route("/incidents", methods=["GET"])
def incidents_list():
    status = request.args.get("status")
    limit = int(request.args.get("limit", 100))
    return jsonify({
        "stats": _incidents().get_stats(),
        "incidents": _incidents().get_all(limit=limit, status=status),
    })


@api_bp.route("/incidents/<int:inc_id>", methods=["GET"])
def incident_detail(inc_id):
    inc = _incidents().get(inc_id)
    if not inc:
        return jsonify({"error": "인시던트 없음"}), 404
    return jsonify(inc)


@api_bp.route("/incidents/<int:inc_id>", methods=["PUT"])
def incident_update(inc_id):
    data = request.get_json() or {}
    status = data.get("status")
    if status and status not in ("OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"):
        return jsonify({"error": "유효하지 않은 상태"}), 400
    ok = _incidents().update(inc_id, status=status,
                             assignee=data.get("assignee"),
                             note=data.get("note"))
    return jsonify({"success": ok})


# ------------------------------------------------------------------ #
#  통합 대시보드 요약
# ------------------------------------------------------------------ #

@api_bp.route("/dashboard/summary", methods=["GET"])
def dashboard_summary():
    pa, td, sp, hc, ai, ml = get_services()
    mitre = _mitre()
    matrix = mitre.get_matrix()
    return jsonify({
        "packets":  pa.get_stats(),
        "threats":  td.get_stats(),
        "sysmon":   sp.get_stats(),
        "ai":       ai.get_status(),
        "ml":       ml.get_stats(),
        "mitre":    {"total_mapped": matrix["total_mapped"],
                     "unique_techniques": matrix["unique_techniques"]},
        "timestamp": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
