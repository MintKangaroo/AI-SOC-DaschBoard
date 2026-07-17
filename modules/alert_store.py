"""
알림 영속화 모듈 - SQLite 기반
재시작 후에도 알림 이력이 유지되도록 저장/복원한다.
"""
import os
import json
import sqlite3
import threading


class AlertStore:
    def __init__(self, db_path="data/alerts.db"):
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id          INTEGER PRIMARY KEY,
                    threat_type TEXT,
                    severity    TEXT,
                    src_ip      TEXT,
                    dst_ip      TEXT,
                    description TEXT,
                    details     TEXT,
                    timestamp   TEXT,
                    status      TEXT DEFAULT 'OPEN',
                    note        TEXT DEFAULT '',
                    assignee    TEXT DEFAULT ''
                )
            """)
            self._conn.commit()

    def save(self, alert):
        """Alert 객체 저장 (id 충돌 시 갱신)"""
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO alerts
                   (id, threat_type, severity, src_ip, dst_ip, description,
                    details, timestamp, status, note, assignee)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (alert.id, alert.threat_type, alert.severity, alert.src_ip,
                 alert.dst_ip, alert.description,
                 json.dumps(alert.details, ensure_ascii=False),
                 alert.timestamp, alert.status, alert.note, alert.assignee),
            )
            self._conn.commit()

    def update_status(self, alert_id, status, note=None, assignee=None):
        sets, params = ["status = ?"], [status]
        if note is not None:
            sets.append("note = ?")
            params.append(note)
        if assignee is not None:
            sets.append("assignee = ?")
            params.append(assignee)
        params.append(alert_id)
        with self._lock:
            self._conn.execute(
                f"UPDATE alerts SET {', '.join(sets)} WHERE id = ?", params
            )
            self._conn.commit()

    def load_recent(self, limit=500):
        """최근 알림을 오래된 순으로 반환 (deque 복원용)"""
        with self._lock:
            rows = self._conn.execute(
                """SELECT id, threat_type, severity, src_ip, dst_ip, description,
                          details, timestamp, status, note, assignee
                   FROM alerts ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        result = []
        for row in reversed(rows):
            try:
                details = json.loads(row[6]) if row[6] else {}
            except json.JSONDecodeError:
                details = {}
            result.append({
                "id": row[0], "threat_type": row[1], "severity": row[2],
                "src_ip": row[3], "dst_ip": row[4], "description": row[5],
                "details": details, "timestamp": row[7], "status": row[8],
                "note": row[9], "assignee": row[10],
            })
        return result

    def search(self, severity=None, status=None, threat_type=None,
               ip=None, text=None, date_from=None, date_to=None,
               limit=100, offset=0):
        """조건별 알림 이력 검색 (전체 DB 대상). (rows, total) 반환.

        - ip: src_ip/dst_ip 부분일치
        - text: description 부분일치
        - date_from/date_to: 'YYYY-MM-DD' (해당 일 포함)
        """
        where, params = [], []
        if severity:
            where.append("severity = ?"); params.append(severity)
        if status:
            where.append("status = ?"); params.append(status)
        if threat_type:
            where.append("threat_type = ?"); params.append(threat_type)
        if ip:
            where.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
            params += [f"%{ip}%", f"%{ip}%"]
        if text:
            where.append("description LIKE ?"); params.append(f"%{text}%")
        if date_from:
            where.append("timestamp >= ?"); params.append(f"{date_from} 00:00:00")
        if date_to:
            where.append("timestamp <= ?"); params.append(f"{date_to} 23:59:59")
        clause = ("WHERE " + " AND ".join(where)) if where else ""

        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM alerts {clause}", params
            ).fetchone()[0]
            rows = self._conn.execute(
                f"""SELECT id, threat_type, severity, src_ip, dst_ip, description,
                           details, timestamp, status, note, assignee
                    FROM alerts {clause}
                    ORDER BY id DESC LIMIT ? OFFSET ?""",
                params + [int(limit), int(offset)],
            ).fetchall()

        result = []
        for row in rows:
            try:
                details = json.loads(row[6]) if row[6] else {}
            except json.JSONDecodeError:
                details = {}
            result.append({
                "id": row[0], "threat_type": row[1], "severity": row[2],
                "src_ip": row[3], "dst_ip": row[4], "description": row[5],
                "details": details, "timestamp": row[7], "status": row[8],
                "note": row[9], "assignee": row[10],
            })
        return result, total

    def max_id(self):
        with self._lock:
            row = self._conn.execute("SELECT MAX(id) FROM alerts").fetchone()
        return row[0] or 0

    def close(self):
        with self._lock:
            self._conn.close()
