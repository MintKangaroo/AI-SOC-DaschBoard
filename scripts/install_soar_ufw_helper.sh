#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
  echo "sudo로 실행하세요: sudo bash scripts/install_soar_ufw_helper.sh"; exit 1
fi
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install -o root -g root -m 0755 "$repo_dir/scripts/soc-ufw" /usr/local/sbin/soc-ufw
user_name="${SUDO_USER:-mintkangaroo}"
sudoers_file="/etc/sudoers.d/soc-dashboard-ufw"
printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/soc-ufw *\n' "$user_name" > "$sudoers_file"
chmod 0440 "$sudoers_file"
visudo -cf "$sudoers_file"
/usr/local/sbin/soc-ufw status
runuser -u "$user_name" -- sudo -n /usr/local/sbin/soc-ufw status
env_file="$repo_dir/.env"
if [[ -f "$env_file" ]]; then
  if grep -q '^SOAR_BLOCK_MODE=' "$env_file"; then
    sed -i 's/^SOAR_BLOCK_MODE=.*/SOAR_BLOCK_MODE=ufw/' "$env_file"
  else
    printf '\nSOAR_BLOCK_MODE=ufw\n' >> "$env_file"
  fi
fi
echo "제한 helper 설치 완료: $sudoers_file"
echo "SOAR_BLOCK_MODE=ufw 반영 완료 — 대시보드를 재시작하세요."
