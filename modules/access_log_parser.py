"""
SIEM 접근 로그 수집 모듈
외부 프로젝트(자동매매 KR/USA 등)의 웹서버 access log를 tail 방식으로 수집·파싱하고,
의심 요청(스캔/프로브)을 분류해 SocketIO로 스트리밍한다.

지원 형식: werkzeug / http.server 공통 로그
  1.2.3.4 - - [02/Jun/2026 09:04:27] "GET / HTTP/1.1" 200 -
  1.2.3.4 - - [02/Jun/2026 09:04:14] code 400, message Bad request version (...)

로그 파일이 없으면 데모 이벤트 생성으로 fallback.
"""
import os
import re
import time
import random
import threading
from datetime import datetime
from collections import deque, Counter

# 기본 수집 대상 (자동매매 프로젝트 대시보드 서버 로그)
DEFAULT_SOURCES = [
    {"name": "자동매매 KR",
     "path": "/home/mintkangaroo/Project/Invest_KOREA_Stock_Project/ls_kr_rl_trader/storage/logs/server.log"},
    {"name": "자동매매 USA",
     "path": "/home/mintkangaroo/Project/Invest_USA_Stock_Project/ls_us_rl_trader/logs/run.log"},
]

# werkzeug/http.server 접근 라인: IP - - [date] 나머지
_ACCESS_RE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}) - - \[([^\]]+)\] (.*)$')
# "REQUEST" STATUS -
_REQ_RE = re.compile(r'^"(.*)" (\d{3}) -?\s*$')

_PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.",
                     "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                     "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")


def classify_request(request, status):
    """요청 문자열/상태코드 → (suspicious, severity, category)"""
    if request.startswith("\\x16\\x03"):
        return True, "HIGH", "TLS 프로브 (HTTPS 스캔)"
    if "\\x" in request:
        return True, "HIGH", "바이너리 프로브 (프로토콜 스캔)"
    if request.startswith("PRI * HTTP/2"):
        return True, "HIGH", "HTTP/2 프로브"
    low = request.lower()
    for kw, cat in (("/.env", "환경파일 탈취 시도"),
                    ("/wp-", "WordPress 스캔"),
                    ("/admin", "관리자 페이지 스캔"),
                    ("/phpmyadmin", "phpMyAdmin 스캔"),
                    ("/.git", "Git 저장소 노출 스캔"),
                    ("/cgi-bin", "CGI 취약점 스캔"),
                    ("/boaform", "IoT 취약점 스캔"),
                    ("/shell", "웹쉘 접근 시도")):
        if kw in low:
            return True, "CRITICAL", cat
    # 일반 4xx/5xx 는 오탐이 많아 '의심'으로 올리지 않음 (프로브/스캔 패턴만 의심)
    if status >= 400:
        return False, "LOW", f"클라이언트 오류 (HTTP {status})"
    return False, "INFO", "정상 요청"


class AccessLogCollector:
    """외부 access log 수집기 — start()/stop()/get_events() 인터페이스"""

    POLL_INTERVAL = 5.0

    def __init__(self, socketio, sources=None, mitre_tracker=None, attack_map=None):
        self.socketio = socketio
        self.mitre = mitre_tracker
        self.attack_map = attack_map
        self.soar = None   # app.py 에서 주입
        self.running = False
        self._lock = threading.Lock()

        self.events = deque(maxlen=1000)
        self.ip_counter = Counter()
        self.stats = {
            "total_events": 0,
            "suspicious_events": 0,
            "unique_ips": 0,
            "sources_ok": 0,
            "last_event": None,
        }

        self.sources = []
        for src in (sources or DEFAULT_SOURCES):
            self.sources.append({
                "name": src["name"],
                "path": src["path"],
                "exists": os.path.exists(src["path"]),
                "offset": 0,
                "events": 0,
                "suspicious": 0,
                "last_read": None,
            })

    # ------------------------------------------------------------------ #

    def start(self, demo=True):
        if self.running:
            return
        self.running = True
        if any(s["exists"] for s in self.sources):
            threading.Thread(target=self._collect_loop, daemon=True).start()
        elif demo:
            print("[SIEM] 접근 로그 파일 없음 — 데모 이벤트 생성")
            threading.Thread(target=self._demo_loop, daemon=True).start()

    def stop(self):
        self.running = False

    def get_events(self, limit=100, source=None, suspicious_only=False):
        with self._lock:
            result = list(self.events)
        if source:
            result = [e for e in result if e["source"] == source]
        if suspicious_only:
            result = [e for e in result if e["suspicious"]]
        return list(reversed(result))[:limit]

    def get_stats(self):
        with self._lock:
            stats = dict(self.stats)
            stats["unique_ips"] = len(self.ip_counter)
            stats["top_ips"] = self.ip_counter.most_common(10)
        return stats

    def get_status(self):
        with self._lock:
            sources = [{k: s[k] for k in
                        ("name", "path", "exists", "events", "suspicious", "last_read")}
                       for s in self.sources]
        return {
            "stats": self.get_stats(),
            "sources": sources,
            "events": self.get_events(100),
        }

    # ------------------------------------------------------------------ #

    def _collect_loop(self):
        first_pass = True
        while self.running:
            for src in self.sources:
                try:
                    self._read_source(src, emit=not first_pass)
                except Exception as e:
                    print(f"[SIEM] {src['name']} 읽기 오류: {e}")
            if first_pass:
                first_pass = False
                # 초기 적재 완료 상태를 한 번 브로드캐스트
                self.socketio.emit("siem_status", self.get_status())
            for _ in range(int(self.POLL_INTERVAL * 10)):
                if not self.running:
                    return
                time.sleep(0.1)

    def _read_source(self, src, emit=True):
        if not os.path.exists(src["path"]):
            src["exists"] = False
            return
        src["exists"] = True
        size = os.path.getsize(src["path"])
        if size < src["offset"]:            # 로그 로테이션 감지
            src["offset"] = 0
        if size == src["offset"]:
            return

        with open(src["path"], "r", encoding="utf-8", errors="replace") as f:
            f.seek(src["offset"])
            chunk = f.read()
            src["offset"] = f.tell()
        src["last_read"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for line in chunk.splitlines():
            event = self._parse_line(line, src["name"])
            if event:
                src["events"] += 1
                if event["suspicious"]:
                    src["suspicious"] += 1
                self._record_event(event, emit=emit)

    def _parse_line(self, line, source_name):
        m = _ACCESS_RE.match(line.strip())
        if not m:
            return None
        ip, ts, rest = m.groups()
        # "code NNN, message ..." 라인은 뒤따르는 요청 라인과 중복 — 건너뜀
        if rest.startswith("code "):
            return None
        rm = _REQ_RE.match(rest)
        if not rm:
            return None
        request, status = rm.group(1), int(rm.group(2))
        suspicious, severity, category = classify_request(request, status)
        return {
            "source": source_name,
            "ip": ip,
            "timestamp": ts,
            "request": request[:200],
            "status": status,
            "suspicious": suspicious,
            "severity": severity,
            "category": category,
        }

    def _record_event(self, event, emit=True):
        with self._lock:
            self.events.append(event)
            self.ip_counter[event["ip"]] += 1
            self.stats["total_events"] += 1
            if event["suspicious"]:
                self.stats["suspicious_events"] += 1
            self.stats["last_event"] = event["timestamp"]
            self.stats["sources_ok"] = sum(1 for s in self.sources if s["exists"])

        if not emit:
            return
        self.socketio.emit("siem_event", event)
        # HIGH/CRITICAL 프로브만 지도·MITRE 반영 (MEDIUM 이하 노이즈 차단)
        if (event["suspicious"] and event["severity"] in ("HIGH", "CRITICAL")
                and self._is_external(event["ip"])):
            if self.attack_map:
                try:
                    self.attack_map.add_attack_ip(event["ip"], "PORT_SCAN",
                                                  event["severity"])
                except Exception:
                    pass
            if self.mitre:
                try:
                    self.mitre.map_threat(
                        "ANOMALY", src_ip=event["ip"],
                        description=f"[SIEM/{event['source']}] {event['category']}")
                except Exception:
                    pass
            if self.soar:
                try:
                    self.soar.handle_siem_event(event)
                except Exception:
                    pass

    @staticmethod
    def _is_external(ip):
        return bool(ip) and not ip.startswith(_PRIVATE_PREFIXES)

    # ------------------------------------------------------------------ #
    #  데모 fallback
    # ------------------------------------------------------------------ #

    _DEMO_REQUESTS = [
        ('GET / HTTP/1.1', 200), ('GET /api/status HTTP/1.1', 200),
        ('GET /.env HTTP/1.1', 404), ('PRI * HTTP/2.0', 505),
        ('GET /wp-login.php HTTP/1.1', 404),
        ('\\x16\\x03\\x01\\x00\\xee', 400),
        ('GET /admin HTTP/1.1', 403), ('POST /api/login HTTP/1.1', 401),
    ]

    def _demo_loop(self):
        names = [s["name"] for s in self.sources] or ["데모 소스"]
        time.sleep(2)
        while self.running:
            req, status = random.choice(self._DEMO_REQUESTS)
            suspicious, severity, category = classify_request(req, status)
            self._record_event({
                "source": random.choice(names),
                "ip": f"{random.randint(1,223)}.{random.randint(0,254)}."
                      f"{random.randint(0,254)}.{random.randint(1,254)}",
                "timestamp": datetime.now().strftime("%d/%b/%Y %H:%M:%S"),
                "request": req,
                "status": status,
                "suspicious": suspicious,
                "severity": severity,
                "category": category,
            })
            time.sleep(random.uniform(3.0, 8.0))
