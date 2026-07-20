"""
데이터 보존 정리 — 로그·저장 데이터를 N일(기본 3일)만 유지하고 자동 삭제.

대상:
  - 알림 DB(alerts + alerts_archive)      : alert_store.purge_older_than
  - 감사 로그 DB(audit)                    : audit_log.purge_older_than
  - 일일 리포트 파일(data/reports/*.json)  : mtime 기준 삭제
  - 로그 파일(logs/*, data/*.log)          : mtime 기준 삭제
  - 생성된 Ansible 플레이북(data/ansible/*.yml) : mtime 기준 삭제

시작 시 1회 + 주기(기본 6시간)로 실행한다. 어떤 예외도 대시보드를 막지 않는다.
"""
import os
import glob
import time
import threading

# (경로 패턴, 재귀 여부) — mtime 이 cutoff 이전이면 삭제
_FILE_TARGETS = [
    "logs/*",
    "data/*.log",
    "data/reports/*",
    "data/ansible/*.yml",
]


def _purge_files(base_dir, days):
    cutoff = time.time() - days * 86400
    removed = 0
    for pattern in _FILE_TARGETS:
        for path in glob.glob(os.path.join(base_dir, pattern)):
            try:
                if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                    os.remove(path)
                    removed += 1
            except OSError:
                pass
    return removed


def run_cleanup(app, days):
    """1회 정리 실행. (삭제 알림 수, 감사 수, 파일 수) 반환."""
    days = int(days)
    n_alerts = n_audit = n_files = 0

    store = getattr(getattr(app, "threat_detector", None), "store", None)
    if store is not None:
        try:
            n_alerts = store.purge_older_than(days)
        except Exception as e:
            print(f"[Retention] 알림 정리 실패: {e}")

    audit = getattr(app, "audit", None)
    if audit is not None:
        try:
            n_audit = audit.purge_older_than(days)
        except Exception as e:
            print(f"[Retention] 감사 정리 실패: {e}")

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        n_files = _purge_files(base_dir, days)
    except Exception as e:
        print(f"[Retention] 파일 정리 실패: {e}")

    if n_alerts or n_audit or n_files:
        print(f"[Retention] {days}일 경과 정리 — 알림 {n_alerts} · 감사 {n_audit} · 파일 {n_files} 삭제")
    return n_alerts, n_audit, n_files


def start(app, days=3, interval_hours=6):
    """시작 시 1회 + interval_hours 주기로 정리하는 데몬 스레드 시작."""
    days = int(days)

    def _loop():
        time.sleep(10)              # 다른 서비스 기동 후
        while True:
            try:
                run_cleanup(app, days)
            except Exception as e:
                print(f"[Retention] 정리 루프 오류: {e}")
            time.sleep(interval_hours * 3600)

    threading.Thread(target=_loop, daemon=True).start()
    print(f"[Retention] 데이터 보존 {days}일 — {interval_hours}시간 주기 자동 삭제 시작")
