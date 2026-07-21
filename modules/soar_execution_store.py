"""SOAR 플레이북 실행 이력을 보존하는 SQLite 저장소."""
import json
import os
import sqlite3
import threading


class SOARExecutionStore:
    def __init__(self, db_path="data/soar_executions.db"):
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS executions (
                    id INTEGER PRIMARY KEY,
                    playbook TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started TEXT NOT NULL,
                    finished TEXT,
                    snapshot TEXT NOT NULL,
                    context TEXT NOT NULL DEFAULT '{}'
                )
            """)
            self._conn.commit()

    def save(self, entry, context=None):
        """스냅샷을 upsert한다. context=None이면 기존 재시도 컨텍스트를 보존한다."""
        snapshot = json.dumps(entry, ensure_ascii=False)
        with self._lock:
            if context is None:
                self._conn.execute(
                    """INSERT INTO executions(id, playbook, status, started, finished, snapshot)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET playbook=excluded.playbook,
                         status=excluded.status, started=excluded.started,
                         finished=excluded.finished, snapshot=excluded.snapshot""",
                    (entry["id"], entry["playbook"], entry["status"], entry["started"],
                     entry.get("finished"), snapshot),
                )
            else:
                self._conn.execute(
                    """INSERT INTO executions
                       (id, playbook, status, started, finished, snapshot, context)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET playbook=excluded.playbook,
                         status=excluded.status, started=excluded.started,
                         finished=excluded.finished, snapshot=excluded.snapshot,
                         context=excluded.context""",
                    (entry["id"], entry["playbook"], entry["status"], entry["started"],
                     entry.get("finished"), snapshot,
                     json.dumps(context, ensure_ascii=False)),
                )
            self._conn.commit()

    def load_recent(self, limit=100):
        with self._lock:
            rows = self._conn.execute(
                "SELECT snapshot FROM executions ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        result = []
        for row in rows:
            try:
                result.append(json.loads(row[0]))
            except (TypeError, json.JSONDecodeError):
                continue
        return result

    def get(self, execution_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT snapshot, context FROM executions WHERE id=?", (execution_id,)
            ).fetchone()
        if not row:
            return None, None
        try:
            return json.loads(row[0]), json.loads(row[1] or "{}")
        except (TypeError, json.JSONDecodeError):
            return None, None
