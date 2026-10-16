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

SOCKS_PORT="1080"
SOCKS_USER="proxyuser"
QUEUE_NUM="200"
MULTIPORT_LIST=""
DEFAULT_IF=""
SOCKS_USER_CREATED="0"

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    SOCKS_PORT="${SOCKS_PORT:-1080}"
    SOCKS_USER="${SOCKS_USER:-proxyuser}"
    QUEUE_NUM="${QUEUE_NUM:-200}"
    MULTIPORT_LIST="${MULTIPORT_LIST:-}"
    DEFAULT_IF="${DEFAULT_IF:-}"
    SOCKS_USER_CREATED="${SOCKS_USER_CREATED:-0}"
fi

delete_rule() {
    # Removes up to 3 duplicate copies of an iptables rule
    for _ in 1 2 3; do
        "$@" 2>/dev/null || break
    done
}

echo -e "${BLUE}[1/7] Остановка и отключение служб...${NC}"
systemctl stop socks5-winclamp danted 2>/dev/null || true
systemctl disable socks5-winclamp danted 2>/dev/null || true
systemctl disable socks5-nic-tuning.service 2>/dev/null || true
systemctl disable socks5-ipset-restore.service 2>/dev/null || true
rm -f /etc/systemd/system/socks5-winclamp.service
rm -f /etc/systemd/system/socks5-nic-tuning.service
rm -f /etc/systemd/system/socks5-ipset-restore.service
systemctl daemon-reload 2>/dev/null || true

echo -e "${BLUE}[2/7] Очистка правил iptables...${NC}"
# NFQUEUE (new form with --queue-bypass and legacy form)
delete_rule iptables -t mangle -D OUTPUT -p tcp --sport "${SOCKS_PORT}" -j NFQUEUE --queue-num "${QUEUE_NUM}" --queue-bypass
delete_rule iptables -t mangle -D OUTPUT -p tcp --sport "${SOCKS_PORT}" -j NFQUEUE --queue-num "${QUEUE_NUM}"
# INPUT (new chain jump + legacy accept rules)
delete_rule iptables -D INPUT -p tcp --dport "${SOCKS_PORT}" -j SOCKS5-FW
delete_rule iptables -D INPUT -p tcp --dport "${SOCKS_PORT}" -j ACCEPT
delete_rule iptables -D INPUT -p tcp --dport "${SOCKS_PORT}" --syn -m hashlimit --hashlimit-name s5_syn --hashlimit 25/sec --hashlimit-burst 50 --hashlimit-mode srcip -j ACCEPT

iptables -F SOCKS5-FW 2>/dev/null || true
iptables -X SOCKS5-FW 2>/dev/null || true

if [[ -n "$MULTIPORT_LIST" ]]; then
    delete_rule iptables -t nat -D PREROUTING -i "${DEFAULT_IF}" -p tcp -m multiport --dports "$MULTIPORT_LIST" -j REDIRECT --to-ports "${SOCKS_PORT}"
    delete_rule iptables -t nat -D PREROUTING -p tcp -m multiport --dports "$MULTIPORT_LIST" -j REDIRECT --to-ports "${SOCKS_PORT}"
    delete_rule iptables -D INPUT -p tcp -m multiport --dports "$MULTIPORT_LIST" -j ACCEPT
fi

echo -e "${BLUE}[3/7] Удаление ipset-наборов (stealth/ban)...${NC}"
ipset destroy socks5_allow 2>/dev/null || true
ipset destroy socks5_ban 2>/dev/null || true
ipset destroy socks5_enroll 2>/dev/null || true

if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save 2>/dev/null || true
fi

echo -e "${BLUE}[4/7] Удаление бинарных файлов и утилит...${NC}"
rm -f /usr/local/bin/socks5-winclamp
rm -f /usr/local/bin/socks5-control
rm -f /usr/local/bin/socks5-nic-tuning
rm -f /usr/local/bin/socks5-ipset-restore
rm -rf /opt/socks5-antidpi

echo -e "${BLUE}[5/7] Очистка файлов конфигурации...${NC}"
rm -f /etc/sysctl.d/99-socks5-antidpi.conf
rm -f /etc/logrotate.d/socks5-danted
rm -f "$CONFIG_FILE"
# Apply sysctl defaults back (window scaling, BBR is left as-is on purpose)
sysctl --system &>/dev/null || true

echo -e "${BLUE}[6/7] Восстановление конфигурации Dante...${NC}"
if [[ -f /etc/danted.conf.socks5-backup ]]; then
    mv -f /etc/danted.conf.socks5-backup /etc/danted.conf
    echo -e "    ${GREEN}Восстановлен исходный /etc/danted.conf${NC}"
else
    rm -f /etc/danted.conf
fi

echo -e "${BLUE}[7/7] Завершение...${NC}"
if [[ "$SOCKS_USER_CREATED" == "1" ]] && id "$SOCKS_USER" &>/dev/null; then
    userdel "$SOCKS_USER" 2>/dev/null || true
    echo -e "    ${GREEN}Пользователь ${SOCKS_USER} удален${NC}"
fi

echo -e "${GREEN}${BOLD}[OK] SOCKS5 Anti-DPI успешно удален!${NC}"
echo -e "Пакет danted оставлен в системе (удалить при необходимости: sudo apt remove danted-server)."
