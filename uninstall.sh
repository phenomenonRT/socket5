#!/usr/bin/env bash
# ==============================================================================
# SOCKS5 Anti-DPI Server Uninstaller
# GitHub: https://github.com/phenomenonRT/socket5
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

CONFIG_FILE="/etc/socks5-antidpi.conf"

if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}[ERROR] Запустите от root (или sudo).${NC}" >&2
    exit 1
fi

echo -e "${YELLOW}${BOLD}=== Полное удаление SOCKS5 Anti-DPI ===${NC}"
read -rp "Вы уверены, что хотите полностью удалить прокси и правила? [y/N]: " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
    echo "Отмена."
    exit 0
fi

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

SOCKS_PORT="${SOCKS_PORT:-1080}"
QUEUE_NUM="${QUEUE_NUM:-200}"
MULTIPORT_LIST="${MULTIPORT_LIST:-}"

echo -e "${BLUE}[1/5] Остановка и отключение служб...${NC}"
systemctl stop socks5-winclamp danted 2>/dev/null || true
systemctl disable socks5-winclamp danted 2>/dev/null || true
rm -f /etc/systemd/system/socks5-winclamp.service
systemctl daemon-reload

echo -e "${BLUE}[2/5] Очистка правил iptables...${NC}"
iptables -t mangle -D OUTPUT -p tcp --sport "${SOCKS_PORT}" -j NFQUEUE --queue-num "${QUEUE_NUM}" 2>/dev/null || true
iptables -D INPUT -p tcp --dport "${SOCKS_PORT}" -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p tcp --dport "${SOCKS_PORT}" --syn -m hashlimit --hashlimit-name s5_syn --hashlimit 25/sec --hashlimit-burst 50 --hashlimit-mode srcip -j ACCEPT 2>/dev/null || true

if [[ -n "$MULTIPORT_LIST" ]]; then
    iptables -t nat -D PREROUTING -i "${DEFAULT_IF:-}" -p tcp -m multiport --dports "$MULTIPORT_LIST" -j REDIRECT --to-ports "${SOCKS_PORT}" 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp -m multiport --dports "$MULTIPORT_LIST" -j REDIRECT --to-ports "${SOCKS_PORT}" 2>/dev/null || true
    iptables -D INPUT -p tcp -m multiport --dports "$MULTIPORT_LIST" -j ACCEPT 2>/dev/null || true
fi

if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save 2>/dev/null || true
fi

echo -e "${BLUE}[3/5] Удаление бинарных файлов и утилит...${NC}"
rm -f /usr/local/bin/socks5-winclamp
rm -f /usr/local/bin/socks5-control
rm -rf /opt/socks5-antidpi

echo -e "${BLUE}[4/5] Очистка файлов конфигурации...${NC}"
rm -f /etc/sysctl.d/99-socks5-antidpi.conf
rm -f "$CONFIG_FILE"

echo -e "${BLUE}[5/5] Завершение...${NC}"
echo -e "${GREEN}${BOLD}[OK] SOCKS5 Anti-DPI успешно удален!${NC}"
