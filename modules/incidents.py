"""
인시던트(케이스) 관리 모듈

SOC 실무의 케이스 관리 워크플로:
  알림(Alert)은 개별 이벤트, 인시던트(Incident)는 대응 단위.
  SOAR가 정탐으로 판정한 알림은 (위협유형 × 출발지 /24) 단위 인시던트로
  자동 승격·병합되고, 차단 등 대응 조치가 타임라인에 기록된다.

상태 흐름: OPEN → INVESTIGATING → CONTAINED → RESOLVED
data/incidents.json 에 영속화.
"""
import os
import json
import threading
from datetime import datetime


VALID_STATUS = ("OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED")
_SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _src_net(ip):
    if not ip:
        return "unknown"
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ip


class IncidentManager:
    def __init__(self, socketio=None, store_path="data/incidents.json"):
        self.socketio = socketio
        self.store_path = store_path
        self._lock = threading.Lock()
        self.incidents = {}     # id → incident dict
        self._next_id = 1
        self._load()

    # ------------------------------------------------------------------ #
    #  자동 승격 (SOAR 에서 호출)
    # ------------------------------------------------------------------ #

    def promote_alert(self, alert, reason="정탐 판정"):
        """정탐 알림 → 인시던트 생성 또는 기존 활성 인시던트에 병합"""
        threat_type = alert.get("threat_type", "UNKNOWN")
        net = _src_net(alert.get("src_ip"))
        severity = alert.get("severity", "MEDIUM")

        with self._lock:
            inc = self._find_active(threat_type, net)
            if inc is None:
                inc_id = self._next_id
                self._next_id += 1
                inc = {
                    "id": inc_id,
                    "title": f"{alert.get('threat_label', threat_type)} — {net}",
                    "threat_type": threat_type,
                    "src_net": net,
                    "severity": severity,
                    "status": "OPEN",
                    "assignee": "",
                    "alert_ids": [],
                    "created": _now(),
                    "updated": _now(),
                    "timeline": [{"ts": _now(), "kind": "open",
                                  "text": f"인시던트 생성 — {reason}"}],
                }
                self.incidents[inc_id] = inc

            aid = alert.get("id")
            if aid is not None and aid not in inc["alert_ids"]:
                inc["alert_ids"].append(aid)
            # 심각도 상향만 허용
            if _SEV_ORDER.get(severity, 0) > _SEV_ORDER.get(inc["severity"], 0):
                inc["severity"] = severity
            inc["timeline"].append({
                "ts": _now(), "kind": "alert",
                "text": f"알림 #{aid} 연결 ({severity}, {alert.get('src_ip')}) — {reason}",
            })
            inc["updated"] = _now()
            inc_id = inc["id"]
            self._save()

        self._emit()
        return inc_id

    def attach_block(self, ip, reason):
        """차단 조치를 해당 대역의 활성 인시던트 타임라인에 기록"""
        net = _src_net(ip)
        changed = False
        with self._lock:
            for inc in self.incidents.values():
                if inc["src_net"] == net and inc["status"] in ("OPEN", "INVESTIGATING"):
                    inc["timeline"].append({
                        "ts": _now(), "kind": "block",
                        "text": f"IP {ip} 차단 — {reason}",
                    })
                    if inc["status"] == "OPEN":
                        inc["status"] = "INVESTIGATING"
                    inc["updated"] = _now()
                    changed = True
            if changed:
                self._save()
        if changed:
            self._emit()
        return changed

    # ------------------------------------------------------------------ #
    #  분석가 조치
    # ------------------------------------------------------------------ #

    def update(self, inc_id, status=None, assignee=None, note=None):
        with self._lock:
            inc = self.incidents.get(inc_id)
            if not inc:
                return False
            if status:
                if status not in VALID_STATUS:
                    return False
                if status != inc["status"]:
                    inc["timeline"].append({
                        "ts": _now(), "kind": "status",
                        "text": f"상태 변경: {inc['status']} → {status}",
                    })
                    inc["status"] = status
            if assignee is not None:
                inc["assignee"] = assignee
                inc["timeline"].append({
                    "ts": _now(), "kind": "assign",
                    "text": f"담당자 지정: {assignee or '(해제)'}",
                })
            if note:
                inc["timeline"].append({"ts": _now(), "kind": "note", "text": note})
            inc["updated"] = _now()
            self._save()
        self._emit()
        return True

    # ------------------------------------------------------------------ #
    #  조회
    # ------------------------------------------------------------------ #

    def get_all(self, limit=100, status=None):
        with self._lock:
            items = sorted(self.incidents.values(),
                           key=lambda i: i["updated"], reverse=True)
        if status:
            items = [i for i in items if i["status"] == status]
        return [self._summary(i) for i in items[:limit]]

    def get(self, inc_id):
        with self._lock:
            inc = self.incidents.get(inc_id)
            return dict(inc) if inc else None

    def get_stats(self):
        with self._lock:
            counts = {"total": len(self.incidents)}
            for st in VALID_STATUS:
                counts[st.lower()] = sum(
                    1 for i in self.incidents.values() if i["status"] == st)
        counts["active"] = counts["open"] + counts["investigating"]
        return counts

    @staticmethod
    def _summary(inc):
        d = {k: inc[k] for k in ("id", "title", "threat_type", "src_net",
                                 "severity", "status", "assignee",
                                 "created", "updated")}
        d["alert_count"] = len(inc["alert_ids"])
        d["timeline_count"] = len(inc["timeline"])
        return d

    # ------------------------------------------------------------------ #
    #  내부
    # ------------------------------------------------------------------ #

    def _find_active(self, threat_type, net):
        for inc in self.incidents.values():
            if (inc["threat_type"] == threat_type and inc["src_net"] == net
                    and inc["status"] in ("OPEN", "INVESTIGATING")):
                return inc
        return None

    def _emit(self):
        if self.socketio:
            try:
                self.socketio.emit("incident_update", {
                    "stats": self.get_stats(),
                    "incidents": self.get_all(30),
                })
            except Exception:
                pass

    def _load(self):
        try:
            if os.path.exists(self.store_path):
                with open(self.store_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.incidents = {int(k): v for k, v in
                                  data.get("incidents", {}).items()}
                self._next_id = data.get("next_id", len(self.incidents) + 1)
        except Exception as e:
            print(f"[Incidents] 로드 실패: {e}")

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.store_path) or ".", exist_ok=True)
            with open(self.store_path, "w", encoding="utf-8") as f:
                json.dump({"next_id": self._next_id,
                           "incidents": {str(k): v for k, v in self.incidents.items()}},
                          f, ensure_ascii=False)
        except Exception as e:
            print(f"[Incidents] 저장 실패: {e}")
