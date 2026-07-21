#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "sudo로 실행하세요: sudo bash scripts/repair_snort_single_interface.sh"
  exit 1
fi

conf="/etc/snort/snort.debian.conf"
if [[ ! -f "$conf" ]]; then
  echo "Snort Debian 설정을 찾을 수 없습니다: $conf"
  exit 1
fi

stamp="$(date +%Y%m%d-%H%M%S)"
cp -a "$conf" "${conf}.soc-backup-${stamp}"

set_value() {
  local key="$1" value="$2"
  if grep -q "^${key}=" "$conf"; then
    sed -i "s|^${key}=.*|${key}=\"${value}\"|" "$conf"
  else
    printf '%s="%s"\n' "$key" "$value" >> "$conf"
  fi
}

# 외부 트래픽이 실제로 들어오는 기본 NIC만 감시한다. Tailscale/Docker 브리지는
# 정상 내부 트래픽 오탐과 중복 메모리 사용을 막기 위해 제외한다.
set_value DEBIAN_SNORT_INTERFACE eth0
set_value DEBIAN_SNORT_HOME_NET 172.23.160.0/20
set_value DEBIAN_SNORT_STARTUP boot

systemctl stop snort || true
# 구형 init 스크립트가 남긴 고아 프로세스만 정확한 실행 파일명으로 종료한다.
pkill -x snort || true
sleep 1
# Snort 2 데몬이 SIGTERM을 무시하고 남는 경우 시작 전에 강제 정리한다.
if pgrep -x snort >/dev/null; then
  pkill -9 -x snort
  sleep 1
fi
systemctl reset-failed snort || true
systemctl start snort

install -d -o snort -g adm -m 2750 /var/log/snort
touch /var/log/snort/snort.alert.fast
chown snort:adm /var/log/snort/snort.alert.fast
chmod 0640 /var/log/snort/snort.alert.fast

echo "설정 백업: ${conf}.soc-backup-${stamp}"
systemctl --no-pager --full status snort
ps -C snort -o pid,%cpu,%mem,rss,args
