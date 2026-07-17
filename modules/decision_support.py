"""
ML 의사결정 지원 (Decision Support) 모듈

목표: 관리자가 보안에 대한 정확한 의사결정을 내릴 수 있도록,
  1) 유사 위협 그룹핑 — (위협유형 × 출발지 /24 대역) 단위 온라인 클러스터링
  2) 정오탐 분석 자동화 — AI 트리아지/분석가 판정을 클러스터별로 학습
  3) 자동화된 추론 — 클러스터 통계 기반 대응 권고 생성
  4) 탐지 피드백 — 클러스터 정탐률 prior 를 threat_detector 신뢰도에 반영
     (같은 그룹에서 오탐이 반복되면 신규 알림의 신뢰도가 자동으로 내려감)
"""
import threading
from datetime import datetime
from collections import Counter, deque


def _src_net(ip):
    """출발지 /24 대역 (그룹핑 키)"""
    if not ip:
        return "unknown"
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".0/24"
    return ip


class DecisionSupport:
    def __init__(self, socketio=None):
        self.socketio = socketio
        self._lock = threading.Lock()
        self.clusters = {}          # (threat_type, src_net) → cluster dict
        self._alert_cluster = {}    # alert_id → cluster key (판정 역추적용)
        self._order = deque(maxlen=200)   # 최근 갱신 순서

    # ------------------------------------------------------------------ #
    #  수집
    # ------------------------------------------------------------------ #

    def observe_alert(self, alert):
        """모든 신규 알림을 클러스터에 반영 (오탐 의심 포함)"""
        key = (alert.get("threat_type", "UNKNOWN"), _src_net(alert.get("src_ip")))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            c = self.clusters.get(key)
            if c is None:
                c = self.clusters[key] = {
                    "threat_type": key[0],
                    "src_net": key[1],
                    "count": 0,
                    "severities": Counter(),
                    "src_ips": set(),
                    "first_seen": now,
                    "last_seen": now,
                    "tp": 0,        # 정탐 판정 수
                    "fp": 0,        # 오탐 판정 수
                    "verdict_sources": Counter(),   # AI / 규칙 / 분석가
                }
            c["count"] += 1
            c["last_seen"] = now
            c["severities"][alert.get("severity", "?")] += 1
            if len(c["src_ips"]) < 50:
                c["src_ips"].add(alert.get("src_ip"))
            if alert.get("id") is not None:
                self._alert_cluster[alert["id"]] = key
                if len(self._alert_cluster) > 2000:
                    for k in list(self._alert_cluster)[:500]:
                        del self._alert_cluster[k]
            if key in self._order:
                self._order.remove(key)
            self._order.append(key)

        if self.socketio:
            try:
                self.socketio.emit("decision_update", self.get_summary())
            except Exception:
                pass

    def record_verdict(self, alert_id, is_tp, source="AI"):
        """정탐/오탐 판정을 클러스터에 학습"""
        with self._lock:
            key = self._alert_cluster.get(alert_id)
            if not key or key not in self.clusters:
                return False
            c = self.clusters[key]
            if is_tp:
                c["tp"] += 1
            else:
                c["fp"] += 1
            c["verdict_sources"][source] += 1
        if self.socketio:
            try:
                self.socketio.emit("decision_update", self.get_summary())
            except Exception:
                pass
        return True

    # ------------------------------------------------------------------ #
    #  추론 / 조회
    # ------------------------------------------------------------------ #

    def cluster_prior(self, threat_type, src_ip):
        """클러스터 정탐률 prior — (rate, n) / 판정 3건 미만이면 None"""
        key = (threat_type, _src_net(src_ip))
        with self._lock:
            c = self.clusters.get(key)
            if not c:
                return None
            n = c["tp"] + c["fp"]
            if n < 3:
                return None
            # Laplace smoothing
            return (c["tp"] + 1) / (n + 2), n

    @staticmethod
    def _recommend(c):
        """클러스터 통계 → 대응 권고 (자동화된 추론)"""
        n = c["tp"] + c["fp"]
        rate = (c["tp"] + 1) / (n + 2) if n else None
        dominant = c["severities"].most_common(1)[0][0] if c["severities"] else "?"
        external = not c["src_net"].startswith(("10.", "127.", "192.168.", "172."))

        if n >= 3 and rate <= 0.3:
            return ("FP_TUNE", f"오탐 {c['fp']}/{n}건 — 탐지 임계값 상향 또는 "
                               f"{c['src_net']} 화이트리스트 검토 권고")
        if n >= 3 and rate >= 0.7 and external:
            return ("BLOCK", f"정탐 {c['tp']}/{n}건 + 외부 대역 — "
                             f"{c['src_net']} 차단 권고")
        if c["count"] >= 10 and len(c["src_ips"]) >= 5:
            return ("CAMPAIGN", f"다수 IP({len(c['src_ips'])}개)에서 동일 유형 반복 — "
                                f"조직적 캠페인 의심, 상관 분석 권고")
        if dominant == "CRITICAL" and n == 0:
            return ("REVIEW", "CRITICAL 다수이나 판정 이력 없음 — 우선 수동 검토 권고")
        return ("MONITOR", "관찰 지속 — 판정 데이터 축적 중")

    def get_clusters(self, limit=30):
        with self._lock:
            keys = list(reversed(self._order))[:limit]
            result = []
            for key in keys:
                c = self.clusters.get(key)
                if not c:
                    continue
                n = c["tp"] + c["fp"]
                action, reason = self._recommend(c)
                result.append({
                    "threat_type": c["threat_type"],
                    "src_net": c["src_net"],
                    "count": c["count"],
                    "unique_ips": len(c["src_ips"]),
                    "dominant_severity": (c["severities"].most_common(1)[0][0]
                                          if c["severities"] else "?"),
                    "tp": c["tp"], "fp": c["fp"],
                    "tp_rate": round((c["tp"] + 1) / (n + 2), 2) if n else None,
                    "first_seen": c["first_seen"],
                    "last_seen": c["last_seen"],
                    "recommendation": action,
                    "reason": reason,
                })
            return result

    def get_summary(self):
        with self._lock:
            total_verdicts = sum(c["tp"] + c["fp"] for c in self.clusters.values())
            total_fp = sum(c["fp"] for c in self.clusters.values())
        return {
            "cluster_count": len(self.clusters),
            "total_verdicts": total_verdicts,
            "total_fp": total_fp,
            "clusters": self.get_clusters(20),
        }
