#!/usr/bin/env python3
"""과거 simulate 차단 기록을 실전 UFW 활성 목록과 무손실 분리한다."""
import os
import shutil
from datetime import datetime

path = "data/blocklist.txt"
if not os.path.exists(path):
    raise SystemExit("blocklist 없음")
with open(path, encoding="utf-8") as f:
    lines = [line for line in f if line.strip()]
simulated = [line for line in lines if "|simulate|" in line]
active = [line for line in lines if "|simulate|" not in line]
stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = f"data/blocklist_legacy_simulate_{stamp}.txt"
shutil.copy2(path, backup)
tmp = path + ".cutover.tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.writelines(active)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, path)
print({"backup": backup, "simulated_archived": len(simulated),
       "active_remaining": len(active)})
