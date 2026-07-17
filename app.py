"""
SOC 대시보드 메인 앱
"""
import os
import secrets
import logging
from datetime import timedelta
from flask import (Flask, render_template, request, session,
                   redirect, jsonify)
from flask_socketio import SocketIO
from flask_cors import CORS

# Werkzeug / Flask / SocketIO 요청 로그 억제
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("engineio").setLevel(logging.ERROR)
logging.getLogger("socketio").setLevel(logging.ERROR)
# 시작 배너 로그 제거
import flask.cli
flask.cli.show_server_banner = lambda *args, **kwargs: None

import config
from api.routes import api_bp
from modules.packet_analyzer import PacketAnalyzer
from modules.threat_detector import ThreatDetector
from modules.sysmon_parser import SysmonParser
from modules.hash_checker import HashChecker
from modules.ai_analyst import AIAnalyst
from modules.ml_analyst import MLAnalyst
from modules.geoip import AttackMapTracker
from modules.mitre_attack import MitreTracker
from modules.threat_intel import ThreatIntel
from modules.ip_reputation import IPReputation
from modules.edr import EDRSensor
from modules.net_monitor import NetworkMonitor
from modules.patch_manager import PatchManager
from modules.vuln_scanner import VulnScanner
from modules.web_fuzzer import WebFuzzer
from modules.notifier import Notifier
from modules.sigma_engine import SigmaEngine
from modules.daily_report import DailyReport
from modules.purple_team import PurpleTeam
from modules.access_log_parser import AccessLogCollector
from modules.soar import SOAREngine
from modules.decision_support import DecisionSupport
from modules.incidents import IncidentManager
from modules.auth import AuthManager
from modules.authlog_parser import AuthLogMonitor


def create_app():
    app = Flask(__name__)
    app.config.from_object(config.Config)

    # ── SECRET_KEY 강화: 기본값이면 세션 서명용 랜덤 키 생성 ──
    if app.config.get("SECRET_KEY") in ("soc-dashboard-secret-2024",
                                        "soc-dashboard-secret-change-me", None, ""):
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        print("[SOC] 경고: 기본 SECRET_KEY — 랜덤 키 생성(재시작 시 세션 초기화). "
              ".env의 SECRET_KEY를 설정하면 유지됩니다.")

    # ── 세션 유지 시간 ──
    app.permanent_session_lifetime = timedelta(
        hours=float(app.config.get("SESSION_HOURS", 12)))

    # ── 인증 매니저 ──
    auth = AuthManager(
        username=app.config.get("DASH_USERNAME", "admin"),
        password=app.config.get("DASH_PASSWORD") or None,
        password_hash=app.config.get("DASH_PASSWORD_HASH") or None,
    )
    app.auth = auth
    auth_on = app.config.get("AUTH_ENABLED", True)
    if auth_on and not auth.configured:
        # 비밀번호 미설정 → 랜덤 발급(콘솔 1회 표시). .env에 DASH_PASSWORD 설정 권장.
        gen = secrets.token_urlsafe(9)
        auth.password_hash = AuthManager(auth.username, password=gen).password_hash
        print("=" * 56)
        print(f"[SOC] 대시보드 로그인 비밀번호 미설정 — 임시 발급")
        print(f"[SOC]   사용자명: {auth.username}")
        print(f"[SOC]   비밀번호: {gen}")
        print(f"[SOC]   (.env의 DASH_PASSWORD 로 고정 설정 권장)")
        print("=" * 56)
    elif not auth_on:
        print("[SOC] 경고: AUTH_ENABLED=False — 인증 없이 노출됩니다.")

    CORS(app, supports_credentials=True)
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode="threading",
        logger=False,
        engineio_logger=False,
    )

    # 서비스 초기화
    demo = app.config.get("DEMO_MODE", True)
    iface = app.config.get("CAPTURE_INTERFACE")

    mitre_tracker   = MitreTracker(socketio)
    attack_map      = AttackMapTracker(socketio)
    threat_detector = ThreatDetector(socketio, app.config,
                                     mitre_tracker=mitre_tracker,
                                     attack_map=attack_map)
    packet_analyzer = PacketAnalyzer(socketio, app.config,
                                     threat_detector=threat_detector)
    sysmon_parser   = SysmonParser(socketio, app.config, mitre_tracker=mitre_tracker)
    hash_checker    = HashChecker(app.config.get("MALICIOUS_HASH_DB"))
    ml_analyst      = MLAnalyst(socketio)
    ai_analyst      = AIAnalyst(socketio, ml_analyst=ml_analyst)
    threat_intel    = ThreatIntel(socketio, packet_analyzer=packet_analyzer,
                                  mitre_tracker=mitre_tracker)
    threat_detector.threat_intel = threat_intel   # IoC 기반 정탐 신뢰도 가중

    ip_reputation = IPReputation(socketio, app.config)
    threat_detector.ip_reputation = ip_reputation  # AbuseIPDB 평판 → 정탐/오탐 근거

    siem_sources = None
    if app.config.get("SIEM_ACCESS_LOGS"):
        siem_sources = [{"name": n.strip(), "path": p.strip()}
                        for n, _, p in (item.partition("=")
                                        for item in app.config["SIEM_ACCESS_LOGS"].split(";"))
                        if n.strip() and p.strip()]
    siem_collector  = AccessLogCollector(socketio, sources=siem_sources,
                                         mitre_tracker=mitre_tracker,
                                         attack_map=attack_map)

    soar = SOAREngine(socketio, app.config, ai_analyst=ai_analyst,
                      ml_analyst=ml_analyst, threat_detector=threat_detector)
    threat_detector.soar = soar
    siem_collector.soar  = soar
    threat_intel.soar    = soar

    decision = DecisionSupport(socketio)
    threat_detector.decision = decision   # 클러스터 prior → 알림 신뢰도 반영
    soar.decision            = decision   # AI/규칙 판정 → 클러스터 학습

    incidents = IncidentManager(socketio)
    soar.incidents = incidents            # 정탐 알림 → 인시던트 자동 승격

    # 실제 SSH 인증 로그 감시 (auth.log) → BRUTE_FORCE 를 파이프라인에 주입
    authlog = AuthLogMonitor(socketio, app.config, threat_detector=threat_detector)

    # Sigma 룰 엔진 (업계 표준 탐지룰) → EDR 프로세스 이벤트를 표준룰로 평가
    sigma = SigmaEngine(socketio, app.config, threat_detector=threat_detector,
                        mitre_tracker=mitre_tracker)

    # AI 기반 EDR (프로세스 행위 관제) → HIGH/CRITICAL 은 AI 트리아지 파이프라인에 투입
    edr = EDRSensor(socketio, app.config, threat_detector=threat_detector,
                    mitre_tracker=mitre_tracker, ai_analyst=ai_analyst,
                    ip_reputation=ip_reputation)
    edr.sigma = sigma   # EDR 스캔 프로세스를 Sigma 룰로도 평가

    # 네트워크 모니터링 관제 (연결·포트·대역폭·타깃 헬스체크)
    net_monitor = NetworkMonitor(socketio, app.config, ip_reputation=ip_reputation,
                                 threat_detector=threat_detector)

    # 푸시 알림 (ntfy) — 정탐/차단만 폰으로
    notifier = Notifier(socketio, app.config)
    soar.notifier = notifier

    # 자동화 취약점 패치 (Ansible)
    patch_manager = PatchManager(socketio, app.config)

    # 취약점 스캐너 (포트/서비스/CVE)
    vuln_scanner = VulnScanner(socketio, app.config)

    # 웹 엔드포인트 퍼저 (견고성 점검)
    web_fuzzer = WebFuzzer(socketio, app.config)

    # 퍼플팀 공격 시뮬레이션 하네스 (탐지 파이프라인 검증)
    purple = PurpleTeam(socketio, app.config, sigma=sigma, edr=edr, authlog=authlog,
                        ip_reputation=ip_reputation, net_monitor=net_monitor,
                        threat_detector=threat_detector)

    # 일일 AI 리포트 (전 모듈 지표 집계 → Claude 브리핑)
    daily_report = DailyReport(socketio, app.config, ai_analyst=ai_analyst, services={
        "threat_detector": threat_detector, "soar": soar, "edr": edr,
        "sigma": sigma, "net_monitor": net_monitor, "authlog": authlog,
        "ip_reputation": ip_reputation, "mitre": mitre_tracker, "incidents": incidents,
    })

    # app 컨텍스트에 서비스 등록
    app.packet_analyzer = packet_analyzer
    app.threat_detector = threat_detector
    app.sysmon_parser   = sysmon_parser
    app.hash_checker    = hash_checker
    app.ai_analyst      = ai_analyst
    app.ml_analyst      = ml_analyst
    app.attack_map      = attack_map
    app.mitre_tracker   = mitre_tracker
    app.threat_intel    = threat_intel
    app.ip_reputation   = ip_reputation
    app.siem_collector  = siem_collector
    app.soar            = soar
    app.decision_support = decision
    app.incidents        = incidents
    app.authlog          = authlog
    app.edr              = edr
    app.net_monitor      = net_monitor
    app.patch_manager    = patch_manager
    app.vuln_scanner     = vuln_scanner
    app.web_fuzzer       = web_fuzzer
    app.notifier         = notifier
    app.sigma            = sigma
    app.daily_report     = daily_report
    app.purple           = purple

    # Blueprint 등록
    app.register_blueprint(api_bp, url_prefix="/api")

    # ------------------------------------------------------------------ #
    #  인증 가드
    # ------------------------------------------------------------------ #

    def _is_public(path):
        return (path == "/login" or path == "/logout"
                or path.startswith("/static/"))

    @app.before_request
    def _require_login():
        if not auth_on or _is_public(request.path):
            return
        if session.get("user"):
            return
        # 미인증: API는 401 JSON, 그 외는 로그인 페이지로
        if request.path.startswith("/api/"):
            return jsonify({"error": "인증이 필요합니다", "auth_required": True}), 401
        return redirect("/login")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not auth_on:
            return redirect("/")
        error = None
        if request.method == "POST":
            ip = request.remote_addr or "?"
            ok, reason = auth.verify(request.form.get("username", ""),
                                     request.form.get("password", ""), ip)
            if ok:
                session.permanent = True
                session["user"] = auth.username
                print(f"[SOC] 로그인 성공: {auth.username} ({ip})")
                return redirect("/")
            if reason == "locked":
                error = f"로그인 시도 과다 — {auth.lock_remaining(ip)}초 후 다시 시도하세요"
            else:
                error = "사용자명 또는 비밀번호가 올바르지 않습니다"
            print(f"[SOC] 로그인 실패({reason}): {ip}")
        elif session.get("user"):
            return redirect("/")
        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect("/login")

    # ------------------------------------------------------------------ #
    #  라우트
    # ------------------------------------------------------------------ #

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/whoami")
    def whoami():
        return jsonify({"user": session.get("user"), "auth_enabled": auth_on,
                        "demo": app.config.get("DEMO_MODE", True)})

    # ------------------------------------------------------------------ #
    #  SocketIO 이벤트
    # ------------------------------------------------------------------ #

    @socketio.on("connect")
    def on_connect():
        # 미인증 소켓 연결 거부 (세션 쿠키로 검증)
        if auth_on and not session.get("user"):
            return False
        print(f"[SOC] 클라이언트 연결됨")

    @socketio.on("disconnect")
    def on_disconnect():
        print(f"[SOC] 클라이언트 연결 해제")

    @socketio.on("chat_message")
    def on_chat(data):
        message = data.get("message", "")
        context = data.get("context", {})
        response = ai_analyst.chat(message, context)
        socketio.emit("chat_response", {
            "message": message,
            "response": response,
            "timestamp": __import__("datetime").datetime.now().strftime("%H:%M:%S"),
        }, to=request.sid)

    @socketio.on("request_ai_analysis")
    def on_ai_analysis(data):
        alert = data.get("alert")
        if alert:
            result = ai_analyst.analyze_alert(alert, async_mode=False)
            socketio.emit("ai_analysis", result, to=request.sid)

    # ------------------------------------------------------------------ #
    #  백그라운드 서비스 시작
    # ------------------------------------------------------------------ #

    packet_analyzer.start(interface=iface, demo=demo)
    threat_detector.start(demo=demo)
    sysmon_parser.start(demo=demo)
    ai_analyst.start()
    ml_analyst.start()
    attack_map.start(demo=demo)
    threat_intel.start(demo=demo)
    ip_reputation.set_own_ips(getattr(soar, "_own_ips", set()))
    ip_reputation.start(demo=demo)
    siem_collector.start(demo=demo)
    soar.start(demo=demo)
    authlog.start(demo=demo)   # auth.log 있으면 실모드, 없으면 데모
    sigma.start(demo=demo)     # Sigma 룰 로드 (EDR 보다 먼저)
    edr.start(demo=demo)       # psutil 있으면 실센서, 없으면 데모
    net_monitor.start(demo=demo)
    patch_manager.start(demo=demo)   # apt 스캔은 읽기전용, 실제 패치는 수동
    vuln_scanner.start(demo=demo)    # 포트/서비스/CVE 스캔 (연결 스캔, 온디맨드)
    web_fuzzer.start(demo=demo)      # 웹 견고성 퍼징 (본인 서버만, 온디맨드)
    daily_report.start(demo=demo)    # 매일 정해진 시각 브리핑 + 시작 시 1회
    purple.start(demo=demo)          # 온디맨드 탐지 검증 (자동 실행 없음)
    print(f"[Notify] ntfy 푸시 {'활성' if notifier.active else '비활성(NTFY_ENABLED/NTFY_TOPIC 설정 시 폰 알림)'}")

    # ML 분석기에 패킷 통계 주기적 공급
    import threading as _t
    def _ml_feed_loop():
        import time as _time
        while True:
            _time.sleep(3)
            try:
                ml_analyst.feed_traffic(packet_analyzer.get_stats())
            except Exception:
                pass
    _t.Thread(target=_ml_feed_loop, daemon=True).start()

    return app, socketio


app, socketio = create_app()

if __name__ == "__main__":
    cfg = config.Config()
    print(f"[SOC] 보안관제 대시보드 v1.0 시작")
    print(f"[SOC] http://{cfg.HOST}:{cfg.PORT}")
    print(f"[SOC] 데모 모드: {cfg.DEMO_MODE}")
    socketio.run(
        app,
        host=cfg.HOST,
        port=cfg.PORT,
        debug=cfg.DEBUG,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
        log_output=False,
    )
