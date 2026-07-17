"""
SOC 대시보드 메인 앱
"""
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
from modules.auth import AuthManager
from wiring import build_services, start_services


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

    # 서비스 계층 생성·상호 배선·app 등록 (배선 상세는 wiring.py)
    build_services(app, socketio)

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
        response = app.ai_analyst.chat(message, context)
        socketio.emit("chat_response", {
            "message": message,
            "response": response,
            "timestamp": __import__("datetime").datetime.now().strftime("%H:%M:%S"),
        }, to=request.sid)

    @socketio.on("request_ai_analysis")
    def on_ai_analysis(data):
        alert = data.get("alert")
        if alert:
            result = app.ai_analyst.analyze_alert(alert, async_mode=False)
            socketio.emit("ai_analysis", result, to=request.sid)

    # 백그라운드 서비스 시작 + ML 피드 루프 (상세는 wiring.py)
    start_services(app, socketio)

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
