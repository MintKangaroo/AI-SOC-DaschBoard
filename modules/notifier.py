"""
푸시 알림 (ntfy) — CRITICAL/정탐만 폰으로

ntfy(https://ntfy.sh 또는 셀프호스트)로 모바일 푸시 알림을 보낸다.
Slack/Discord 대신 사용자가 선택한 경량 오픈소스 푸시.

핵심 설계 (오탐 스팸 방지 — 프로젝트 목표인 '정탐/오탐 구분'과 일치):
  - 모든 알림을 보내지 않는다. SOAR가 AI/규칙으로 '정탐' 판정한 건과
    자동 차단(auto-block) 같은 확정 대응만 폰으로 보낸다.
  - 심각도 임계값(NTFY_MIN_PRIORITY_SEVERITY, 기본 CRITICAL) 이상만.
  - 동일 키 중복 알림은 쿨다운(기본 300초)으로 억제.

설정(.env):
  NTFY_ENABLED, NTFY_SERVER(기본 https://ntfy.sh), NTFY_TOPIC,
  NTFY_TOKEN(선택, 인증 서버), NTFY_MIN_SEVERITY(기본 CRITICAL)

topic 미설정이거나 비활성이면 실제 전송하지 않고 기록만(안전).
"""
import time
import threading
from datetime import datetime
from collections import deque

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
# ntfy priority: 1(min)~5(max)
_SEV_PRIORITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
_SEV_TAGS = {"CRITICAL": "rotating_light", "HIGH": "warning",
             "MEDIUM": "eyes", "LOW": "information_source"}


class Notifier:
    def __init__(self, socketio, config=None):
        self.socketio = socketio
        self.config = config or {}
        self._lock = threading.Lock()

        self.enabled = str(self.config.get("NTFY_ENABLED", "False")) == "True"
        self.server = (self.config.get("NTFY_SERVER") or "https://ntfy.sh").rstrip("/")
        self.topic = (self.config.get("NTFY_TOPIC") or "").strip()
        self.token = (self.config.get("NTFY_TOKEN") or "").strip()
        self.min_sev = str(self.config.get("NTFY_MIN_SEVERITY", "CRITICAL")).upper()
        try:
            self.cooldown = float(self.config.get("NTFY_COOLDOWN", 300))
        except (TypeError, ValueError):
            self.cooldown = 300.0

        self._last_sent = {}          # dedup key -> ts
        self.history = deque(maxlen=100)
        self.stats = {"enabled": self.enabled and bool(self.topic),
                      "sent": 0, "suppressed": 0, "failed": 0, "last": None,
                      "server": self.server, "min_severity": self.min_sev}

    # ------------------------------------------------------------------ #

    @property
    def active(self):
        return self.enabled and bool(self.topic) and REQUESTS_OK

    def get_status(self):
        with self._lock:
            return {
                "stats": dict(self.stats),
                "topic_set": bool(self.topic),
                "active": self.active,
                "server": self.server,
                "min_severity": self.min_sev,
                "history": list(reversed(list(self.history)))[:30],
            }

    # ------------------------------------------------------------------ #
    #  전송 진입점
    # ------------------------------------------------------------------ #

    def notify(self, title, message, severity="CRITICAL", tags=None,
               dedup_key=None, click=None, force=False):
        """푸시 전송. 임계값 미만/쿨다운/미설정이면 억제(기록만)."""
        severity = (severity or "INFO").upper()
        if not force and _SEV_ORDER.get(severity, 0) < _SEV_ORDER.get(self.min_sev, 4):
            return False, "below_threshold"

        # 쿨다운 중복 억제
        key = dedup_key or f"{title}:{severity}"
        now = time.time()
        with self._lock:
            last = self._last_sent.get(key)
            if not force and last and now - last < self.cooldown:
                self.stats["suppressed"] += 1
                return False, "cooldown"
            self._last_sent[key] = now

        entry = {"title": title, "message": message, "severity": severity,
                 "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 "delivered": False, "detail": ""}

        if not self.active:
            entry["detail"] = ("미설정/비활성 — 전송 안 함 (NTFY_ENABLED=True + NTFY_TOPIC 설정 필요)"
                               if not self.active else "")
            self._record(entry, delivered=False, failed=False)
            return False, "inactive"

        ok, detail = self._send_ntfy(title, message, severity, tags, click)
        entry["delivered"] = ok
        entry["detail"] = detail
        self._record(entry, delivered=ok, failed=not ok)
        return ok, detail

    def _send_ntfy(self, title, message, severity, tags, click):
        # ntfy JSON 발행 형식 — 헤더 대신 JSON 본문이라 UTF-8(한글/이모지) 안전
        payload = {
            "topic": self.topic,
            "title": title,
            "message": message,
            "priority": _SEV_PRIORITY.get(severity, 4),
            "tags": tags or [_SEV_TAGS.get(severity, "warning")],
        }
        if click:
            payload["click"] = click
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            r = requests.post(self.server, json=payload, headers=headers, timeout=8)
            if r.status_code < 300:
                return True, f"전송 성공 ({self.server}/{self.topic})"
            return False, f"HTTP {r.status_code}"
        except Exception as e:
            return False, f"오류: {type(e).__name__}"

    def _record(self, entry, delivered, failed):
        with self._lock:
            self.history.append(entry)
            if delivered:
                self.stats["sent"] += 1
                self.stats["last"] = entry["timestamp"]
            elif failed:
                self.stats["failed"] += 1
        try:
            self.socketio.emit("notify_event", entry)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  고수준 헬퍼 (SOAR/EDR 등에서 호출)
    # ------------------------------------------------------------------ #

    def notify_true_positive(self, alert, confidence, who="AI"):
        """SOAR가 정탐 판정한 알림 → 폰 푸시."""
        threat = alert.get("threat_label") or alert.get("threat_type", "위협")
        src = alert.get("src_ip", "?")
        title = f"🚨 정탐 확정: {threat}"
        msg = (f"{who} 정탐 판정({confidence}%)\n출발지: {src}\n"
               f"{alert.get('description', '')}")
        return self.notify(title, msg, severity=alert.get("severity", "CRITICAL"),
                           dedup_key=f"tp:{alert.get('id')}")

    def notify_block(self, ip, reason):
        """SOAR 자동 차단 → 폰 푸시."""
        return self.notify(f"⛔ 자동 차단: {ip}", f"{reason}",
                           severity="CRITICAL", dedup_key=f"block:{ip}")
