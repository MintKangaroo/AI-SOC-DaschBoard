#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "sudo로 실행하세요: sudo bash scripts/enable_ufw_safe.sh"
  exit 1
fi

backup_dir="/var/backups/soc-dashboard-firewall-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"
ufw status numbered > "$backup_dir/ufw-status-before.txt" 2>&1 || true
iptables-save > "$backup_dir/iptables-before.rules"

# 원격 관리·현재 서비스 경로를 방화벽 활성화보다 먼저 보장한다.
ufw allow 22/tcp comment 'SSH management'
ufw allow 80/tcp comment 'HTTP service'
ufw allow in on tailscale0 comment 'Tailscale trusted management'
ufw allow in on tailscale0 to any port 5055 proto tcp comment 'SOC dashboard'

ufw default deny incoming
ufw default allow outgoing
ufw --force enable

echo "방화벽 백업: $backup_dir"
ufw status verbose
