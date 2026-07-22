#!/usr/bin/env python3
"""기존 활성 알림을 legacy 아카이브로 옮겨 실운영 데이터 경계를 만든다."""
import argparse
import os
import shutil
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.alert_store import AlertStore


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="data/alerts.db")
    parser.add_argument("--cutoff", default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    store = AlertStore(args.db)
    before = store.retention_stats()
    print({"cutoff": args.cutoff, "live_before": before["live"], "apply": args.apply})
    if not args.apply:
        return
    backup = f"{args.db}.pre-production-{datetime.now().strftime('%Y%m%d-%H%M%S')}.bak"
    store._conn.execute("PRAGMA wal_checkpoint(FULL)")
    shutil.copy2(args.db, backup)
    moved = store.production_cutover(args.cutoff)
    after = store.retention_stats()
    print({"backup": backup, "moved": moved, "live_after": after["live"],
           "archived": after["archived"]})


if __name__ == "__main__":
    main()
