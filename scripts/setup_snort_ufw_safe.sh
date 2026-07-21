#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "sudo로 실행하세요: sudo bash scripts/setup_snort_ufw_safe.sh"
  exit 1
fi

backup_dir="/var/backups/soc-dashboard-firewall-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"
ufw status numbered > "$backup_dir/ufw-status-before.txt" 2>&1 || true
iptables-save > "$backup_dir/iptables-before.rules"

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y snort ufw

# 관리 경로를 먼저 허용해 원격 잠금을 방지한다.
ufw allow 22/tcp comment 'SSH management'
ufw allow 80/tcp comment 'HTTP service'
ufw allow in on tailscale0 comment 'Tailscale trusted management'
ufw allow in on tailscale0 to any port 5055 proto tcp comment 'SOC dashboard'

# 기존 정책이 이미 운영 중이면 유지한다. 신규 활성화 때만 보수적 기본 정책 적용.
if ! ufw status | grep -q '^Status: active'; then
  ufw default deny incoming
  ufw default allow outgoing
  ufw --force enable
fi

install -d -o snort -g snort /var/log/snort
touch /var/log/snort/alert
chgrp adm /var/log/snort/alert
chmod 0640 /var/log/snort/alert
usermod -aG adm "${SUDO_USER:-mintkangaroo}"

echo "백업: $backup_dir"
echo "UFW 규칙을 확인하세요: sudo ufw status numbered"
echo "Snort 설정 검증: sudo snort -T -c /etc/snort/snort.conf -i eth0"
echo "주의: 이 스크립트는 SOAR passwordless sudo 권한을 만들지 않습니다."
