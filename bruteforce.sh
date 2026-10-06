#!/usr/bin/env bash
# bruteforce.sh — Фаза 0 емуляції IR-01: брутфорс RDP проти ENERGY з Ubuntu-машини.
# ТІЛЬКИ для авторизованого лабораторного тесту. Ціль — тестовий обліковий запис RECON01_..._user,
# створений заздалегідь на ENERGY. Робить серію НЕВДАЛИХ спроб, потім один УСПІШНИЙ вхід.
#
# Використання:
#   ./bruteforce.sh <ENERGY_IP> <RECON01_..._user> [correct_password] [attempts]
# Приклад:
#   ./bruteforce.sh 10.23.2.50 RECON01_20261007_1530_user 'Rdp_Pass_1!' 6
#
# Потрібен hydra:  sudo apt install -y hydra
set -u

TARGET="${1:-}"
USER="${2:-}"
REALPASS="${3:-Rdp_Pass_1!}"
ATTEMPTS="${4:-6}"

if [[ -z "$TARGET" || -z "$USER" ]]; then
  echo "Usage: $0 <ENERGY_IP> <RECON01_..._user> [correct_password] [attempts]"
  exit 1
fi
if ! command -v hydra >/dev/null; then
  echo "hydra не встановлено. Виконайте: sudo apt install -y hydra"
  exit 1
fi

echo "=== bruteforce RDP | target $TARGET | user $USER | $(date -u '+%Y-%m-%d %H:%M:%SZ') ==="

# 1) Серія НЕВДАЛИХ паролів (генеруємо явно неправильні) -> 4625 (type 10) + 4776 + RdpCoreTS 140
WL="$(mktemp)"
for i in $(seq 1 "$ATTEMPTS"); do echo "WrongPwd_${i}"; done > "$WL"

echo "[1] Невдалі спроби ($ATTEMPTS):"
hydra -t 1 -W 1 -f -l "$USER" -P "$WL" "rdp://$TARGET" 2>&1 | grep -Ei 'login:|attempt|error' || true
rm -f "$WL"

# 2) Один УСПІШНИЙ вхід -> 4624 (type 10) + 1149 + LocalSessionManager 21/25
echo "[2] Успішний вхід (правильний пароль):"
hydra -t 1 -f -l "$USER" -p "$REALPASS" "rdp://$TARGET" 2>&1 | grep -Ei 'login:|password:|host:' || true

echo "=== done. На ENERGY очікуються: 4625(type10) серія, 4776, RdpCoreTS 140; на успіху 4624(type10), 1149, 21/25 ==="
