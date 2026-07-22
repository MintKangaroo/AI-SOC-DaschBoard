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
            self._migrate_alert_columns("alerts")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_verdict ON alerts(verdict)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_threat ON alerts(threat_type)")
            self._conn.commit()

    def _migrate_alert_columns(self, table):
        existing = {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")}
        additions = {
            "origin": "TEXT DEFAULT 'unknown'",
            "verdict": "TEXT DEFAULT 'UNREVIEWED'",
            "verdict_actor": "TEXT DEFAULT ''",
            "verdict_reason": "TEXT DEFAULT ''",
            "verdict_at": "TEXT DEFAULT ''",
        }
        for name, ddl in additions.items():
            if name not in existing:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    def save(self, alert):
        """Alert 객체 저장 (id 충돌 시 갱신)"""
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO alerts
                   (id, threat_type, severity, src_ip, dst_ip, description,
                    details, timestamp, status, note, assignee, origin,
                    verdict, verdict_actor, verdict_reason, verdict_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (alert.id, alert.threat_type, alert.severity, alert.src_ip,
                 alert.dst_ip, alert.description,
                 json.dumps(alert.details, ensure_ascii=False),
                 alert.timestamp, alert.status, alert.note, alert.assignee,
                 getattr(alert, "origin", "unknown"),
                 getattr(alert, "verdict", "UNREVIEWED"),
                 getattr(alert, "verdict_actor", ""),
                 getattr(alert, "verdict_reason", ""),
                 getattr(alert, "verdict_at", "")),
            )
            self._conn.commit()

    def set_verdict(self, alert_id, verdict, actor, reason, decided_at):
        if verdict not in ("UNREVIEWED", "INVESTIGATING", "TRUE_POSITIVE", "FALSE_POSITIVE"):
            return False
        with self._lock:
            cur = self._conn.execute(
                """UPDATE alerts SET verdict=?, verdict_actor=?, verdict_reason=?, verdict_at=?
                   WHERE id=?""", (verdict, actor, reason, decided_at, alert_id))
            self._conn.commit()
        return cur.rowcount == 1

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

    def update_details(self, alert_id, details):
        """외부 평판 등 사후 강화 결과를 기존 알림에 병합 저장한다."""
        with self._lock:
            row = self._conn.execute("SELECT details FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if not row:
                return False
            try:
                current = json.loads(row[0]) if row[0] else {}
            except json.JSONDecodeError:
                current = {}
            current.update(details or {})
            self._conn.execute("UPDATE alerts SET details=? WHERE id=?",
                               (json.dumps(current, ensure_ascii=False), alert_id))
            self._conn.commit()
        return True

    def load_recent(self, limit=500):
        """최근 알림을 오래된 순으로 반환 (deque 복원용)"""
        with self._lock:
            rows = self._conn.execute(
                """SELECT id, threat_type, severity, src_ip, dst_ip, description,
                          details, timestamp, status, note, assignee,
                          origin, verdict, verdict_actor, verdict_reason, verdict_at
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
                "note": row[9], "assignee": row[10], "origin": row[11],
                "verdict": row[12], "verdict_actor": row[13],
                "verdict_reason": row[14], "verdict_at": row[15],
            })
        return result

    def search(self, severity=None, status=None, threat_type=None, verdict=None, origin=None,
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
        if verdict:
            where.append("verdict = ?"); params.append(verdict)
        if origin:
            where.append("origin = ?"); params.append(origin)
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
                           details, timestamp, status, note, assignee,
                           origin, verdict, verdict_actor, verdict_reason, verdict_at
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
                "note": row[9], "assignee": row[10], "origin": row[11],
                "verdict": row[12], "verdict_actor": row[13],
                "verdict_reason": row[14], "verdict_at": row[15],
            })
        return result, total

    def aggregate(self, days=14):
        """운영 지표용 시계열 집계 (최근 N일). timestamp 는 'YYYY-MM-DD HH:MM:SS'."""
        since = f"-{int(days)} days"
        with self._lock:
            c = self._conn
            # 일별 볼륨 (심각도 분리)
            by_day = c.execute(
                """SELECT strftime('%Y-%m-%d', timestamp) d,
                          SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END),
                          SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END),
                          SUM(CASE WHEN severity NOT IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END),
                          COUNT(*)
                   FROM alerts
                   WHERE timestamp >= datetime('now', ?, 'localtime')
                   GROUP BY d ORDER BY d""", (since,)).fetchall()
            # 상태 분포
            by_status = dict(c.execute(
                """SELECT status, COUNT(*) FROM alerts
                   WHERE timestamp >= datetime('now', ?, 'localtime')
                   GROUP BY status""", (since,)).fetchall())
            # 시간대(0~23) × 요일(0=일~6) 히트맵
            hd = c.execute(
                """SELECT CAST(strftime('%w', timestamp) AS INT) dow,
                          CAST(strftime('%H', timestamp) AS INT) hr, COUNT(*)
                   FROM alerts
                   WHERE timestamp >= datetime('now', ?, 'localtime')
                   GROUP BY dow, hr""", (since,)).fetchall()
            # TOP 위협 유형 / 공격자
            top_types = c.execute(
                """SELECT threat_type, COUNT(*) n FROM alerts
                   WHERE timestamp >= datetime('now', ?, 'localtime')
                   GROUP BY threat_type ORDER BY n DESC LIMIT 8""", (since,)).fetchall()
            # 실제 IP 만 (EDR 등 호스트명/빈값 제외 — 최소 3개 점)
            top_ips = c.execute(
                """SELECT src_ip, COUNT(*) n FROM alerts
                   WHERE timestamp >= datetime('now', ?, 'localtime')
                         AND src_ip LIKE '%.%.%.%'
                   GROUP BY src_ip ORDER BY n DESC LIMIT 10""", (since,)).fetchall()
            total = c.execute(
                """SELECT COUNT(*) FROM alerts
                   WHERE timestamp >= datetime('now', ?, 'localtime')""", (since,)).fetchone()[0]

        heat = [[0] * 24 for _ in range(7)]
        for dow, hr, n in hd:
            if dow is not None and hr is not None:
                heat[dow][hr] = n
        return {
            "days": int(days),
            "total": total,
            "by_day": [{"date": d, "critical": cr, "high": hi, "other": ot, "total": tt}
                       for d, cr, hi, ot, tt in by_day],
            "by_status": by_status,
            "heatmap": heat,
            "top_types": [{"type": t, "count": n} for t, n in top_types],
            "top_ips": [{"ip": ip, "count": n} for ip, n in top_ips],
        }

    def since(self, hours=24, limit=5000):
        """최근 N시간 알림(실 IP 출발지만) — 상관관계 분석용. 시간 오름차순."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT id, threat_type, severity, src_ip, dst_ip, timestamp
                   FROM alerts
                   WHERE timestamp >= datetime('now', ?, 'localtime')
                         AND src_ip LIKE '%.%.%.%'
                   ORDER BY timestamp ASC LIMIT ?""",
                (f"-{int(hours)} hours", int(limit))).fetchall()
        return [{"id": r[0], "threat_type": r[1], "severity": r[2],
                 "src_ip": r[3], "dst_ip": r[4], "timestamp": r[5]} for r in rows]

    def grouped_recent(self, hours=24, min_count=2, limit=20):
        """최근 반복 알림을 출발지·위협유형별로 묶어 조사 우선순위로 반환한다."""
        hours = max(1, min(24 * 30, int(hours)))
        min_count = max(2, int(min_count))
        limit = max(1, min(100, int(limit)))
        with self._lock:
            rows = self._conn.execute(
                """SELECT src_ip, threat_type, COUNT(*) AS cnt,
                          MIN(timestamp), MAX(timestamp),
                          SUM(CASE WHEN status='OPEN' THEN 1 ELSE 0 END),
                          MAX(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                                            WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END)
                   FROM alerts
                   WHERE timestamp >= datetime('now', ?, 'localtime')
                         AND COALESCE(src_ip, '') != ''
                   GROUP BY src_ip, threat_type
                   HAVING COUNT(*) >= ?
                   ORDER BY MAX(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                                               WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END) DESC,
                            SUM(CASE WHEN status='OPEN' THEN 1 ELSE 0 END) DESC,
                            cnt DESC, MAX(timestamp) DESC
                   LIMIT ?""",
                (f"-{hours} hours", min_count, limit)).fetchall()
        sev = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}
        return [{"src_ip": r[0], "threat_type": r[1], "count": r[2],
                 "first_seen": r[3], "last_seen": r[4], "open_count": r[5],
                 "severity": sev.get(r[6], "INFO")} for r in rows]

    def snort_sid_stats(self, limit=30):
        """분석가 확정 판정을 기준으로 SID별 정·오탐 품질을 집계한다."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT CAST(json_extract(details, '$.signature_id') AS INTEGER) sid,
                          COUNT(*) total,
                          SUM(CASE WHEN verdict='TRUE_POSITIVE' THEN 1 ELSE 0 END) tp,
                          SUM(CASE WHEN verdict='FALSE_POSITIVE' THEN 1 ELSE 0 END) fp,
                          MAX(timestamp) last_seen
                   FROM alerts WHERE threat_type='SNORT_ALERT'
                         AND json_extract(details, '$.signature_id') IS NOT NULL
                   GROUP BY sid ORDER BY total DESC, last_seen DESC LIMIT ?""",
                (max(1, min(200, int(limit))),)).fetchall()
        return [{"sid": r[0], "total": r[1], "tp": r[2], "fp": r[3],
                 "unreviewed": r[1] - r[2] - r[3],
                 "accuracy": round(r[2] * 100 / (r[2] + r[3]), 1)
                             if r[2] + r[3] else None,
                 "last_seen": r[4]} for r in rows]

    def _ensure_archive(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts_archive (
                id          INTEGER PRIMARY KEY,
                threat_type TEXT, severity TEXT, src_ip TEXT, dst_ip TEXT,
                description TEXT, details TEXT, timestamp TEXT,
                status TEXT, note TEXT, assignee TEXT,
                archived_at TEXT
            )""")
        self._migrate_alert_columns("alerts_archive")

    def retention_stats(self):
        """보존 현황 — 활성/아카이브 건수, 최고(古)/최신 시각."""
        with self._lock:
            self._ensure_archive()
            live = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            oldest, newest = self._conn.execute(
                "SELECT MIN(timestamp), MAX(timestamp) FROM alerts").fetchone()
            arch = self._conn.execute("SELECT COUNT(*) FROM alerts_archive").fetchone()[0]
            arch_newest = self._conn.execute(
                "SELECT MAX(timestamp) FROM alerts_archive").fetchone()[0]
        return {"live": live, "archived": arch, "oldest": oldest,
                "newest": newest, "archived_newest": arch_newest}

    def retention_preview(self, live_days=90, archive_days=365):
        """정리 실행 전 이동/영구삭제 예정 건수를 변경 없이 조회한다."""
        with self._lock:
            self._ensure_archive()
            to_archive = self._conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE timestamp < datetime('now', ?, 'localtime')",
                (f"-{int(live_days)} days",)).fetchone()[0]
            to_delete = self._conn.execute(
                """SELECT COUNT(*) FROM alerts_archive
                   WHERE COALESCE(archived_at, timestamp) < datetime('now', ?, 'localtime')""",
                (f"-{int(archive_days)} days",)).fetchone()[0]
        return {"to_archive": to_archive, "archive_to_delete": to_delete}

    def purge_archive_older_than(self, days):
        """아카이브된 뒤 N일이 지난 항목만 영구 삭제한다. 활성 알림은 건드리지 않는다."""
        with self._lock:
            self._ensure_archive()
            arg = f"-{int(days)} days"
            count = self._conn.execute(
                """SELECT COUNT(*) FROM alerts_archive
                   WHERE COALESCE(archived_at, timestamp) < datetime('now', ?, 'localtime')""",
                (arg,)).fetchone()[0]
            if count:
                self._conn.execute(
                    """DELETE FROM alerts_archive
                       WHERE COALESCE(archived_at, timestamp) < datetime('now', ?, 'localtime')""",
                    (arg,))
                self._conn.commit()
        return count

    def archive_older_than(self, days):
        """N일 이전 알림을 아카이브 테이블로 이동(무손실). 이동 건수 반환."""
        from datetime import datetime
        days = int(days)
        with self._lock:
            self._ensure_archive()
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cutoff_expr = "datetime('now', ?, 'localtime')"
            arg = f"-{days} days"
            moved = self._conn.execute(
                f"SELECT COUNT(*) FROM alerts WHERE timestamp < {cutoff_expr}",
                (arg,)).fetchone()[0]
            if moved:
                self._conn.execute(
                    f"""INSERT OR REPLACE INTO alerts_archive
                        (id, threat_type, severity, src_ip, dst_ip, description,
                         details, timestamp, status, note, assignee, archived_at,
                         origin, verdict, verdict_actor, verdict_reason, verdict_at)
                        SELECT id, threat_type, severity, src_ip, dst_ip, description,
                               details, timestamp, status, note, assignee, ?,
                               origin, verdict, verdict_actor, verdict_reason, verdict_at
                        FROM alerts WHERE timestamp < {cutoff_expr}""", (now, arg))
                self._conn.execute(
                    f"DELETE FROM alerts WHERE timestamp < {cutoff_expr}", (arg,))
                self._conn.commit()
        return moved

    def production_cutover(self, cutoff):
        """컷오버 이전 활성 알림을 legacy로 표시해 무손실 아카이브한다."""
        from datetime import datetime
        with self._lock:
            self._ensure_archive()
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            count = self._conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE timestamp < ?", (cutoff,)).fetchone()[0]
            if not count:
                return 0
            self._conn.execute(
                "UPDATE alerts SET origin='legacy' WHERE timestamp < ?", (cutoff,))
            self._conn.execute(
                """INSERT OR REPLACE INTO alerts_archive
                   (id, threat_type, severity, src_ip, dst_ip, description, details,
                    timestamp, status, note, assignee, archived_at, origin, verdict,
                    verdict_actor, verdict_reason, verdict_at)
                   SELECT id, threat_type, severity, src_ip, dst_ip, description, details,
                          timestamp, status, note, assignee, ?, origin, verdict,
                          verdict_actor, verdict_reason, verdict_at
                   FROM alerts WHERE timestamp < ?""", (now, cutoff))
            self._conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
            self._conn.commit()
        return count

    def purge_older_than(self, days):
        """N일 이전 알림을 활성·아카이브 테이블에서 영구 삭제. 삭제 건수 반환."""
        days = int(days)
        arg = f"-{days} days"
        cutoff = "datetime('now', ?, 'localtime')"
        with self._lock:
            self._ensure_archive()
            n1 = self._conn.execute(
                f"SELECT COUNT(*) FROM alerts WHERE timestamp < {cutoff}", (arg,)).fetchone()[0]
            self._conn.execute(f"DELETE FROM alerts WHERE timestamp < {cutoff}", (arg,))
            n2 = self._conn.execute(
                f"SELECT COUNT(*) FROM alerts_archive WHERE timestamp < {cutoff}", (arg,)).fetchone()[0]
            self._conn.execute(f"DELETE FROM alerts_archive WHERE timestamp < {cutoff}", (arg,))
            self._conn.commit()
        return n1 + n2

    def max_id(self):
        with self._lock:
            self._ensure_archive()
            row = self._conn.execute(
                "SELECT MAX(id) FROM (SELECT id FROM alerts UNION ALL SELECT id FROM alerts_archive)"
            ).fetchone()
        return row[0] or 0

    def close(self):
        with self._lock:
            self._conn.close()
