#!/usr/bin/env bash
# ==============================================================================
# SOCKS5 Anti-DPI Server Management Tool
# GitHub: https://github.com/phenomenonRT/socket5
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CONFIG_FILE="/etc/socks5-antidpi.conf"
INSTALL_DIR="/opt/socks5-antidpi"
IPSET_SAVE="${INSTALL_DIR}/ipset.save"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${RED}[ERROR] Файл конфигурации $CONFIG_FILE не найден. Сервер установлен?${NC}" >&2
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

# Defaults for older configs
SOCKS_PORT="${SOCKS_PORT:-1080}"
SOCKS_USER="${SOCKS_USER:-proxyuser}"
SOCKS_PASS="${SOCKS_PASS:-}"
BYPASS_MODE="${BYPASS_MODE:-1}"
MULTIPORT_LIST="${MULTIPORT_LIST:-}"
CLAMP_WINDOW="${CLAMP_WINDOW:-2}"
QUEUE_NUM="${QUEUE_NUM:-200}"
DEFAULT_IF="${DEFAULT_IF:-}"
STEALTH_MODE="${STEALTH_MODE:-off}"
BAN_AFTER="${BAN_AFTER:-6}"
BAN_TIME="${BAN_TIME:-3600}"
ENROLL_MINUTES="${ENROLL_MINUTES:-30}"

ALLOW_SET="socks5_allow"
BAN_SET="socks5_ban"
OPEN_SET="socks5_enroll"
FW_CHAIN="SOCKS5-FW"

PASS_RE='^[A-Za-z0-9._~!@%^+=,?*-]{8,64}$'

need_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo -e "${RED}[ERROR] Для этого действия нужен root (sudo socks5-control ...)${NC}" >&2
        return 1
    fi
}

is_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local o
    IFS='.' read -ra o <<< "$ip"
    local part
    for part in "${o[@]}"; do
        (( part >= 0 && part <= 255 )) || return 1
    done
    return 0
}

save_config() {
    cat > "$CONFIG_FILE" <<EOF_CFG
SOCKS_PORT='${SOCKS_PORT}'
SOCKS_USER='${SOCKS_USER}'
SOCKS_PASS='${SOCKS_PASS}'
BYPASS_MODE='${BYPASS_MODE}'
MULTIPORT_LIST='${MULTIPORT_LIST}'
CLAMP_WINDOW='${CLAMP_WINDOW}'
QUEUE_NUM='${QUEUE_NUM}'
DEFAULT_IF='${DEFAULT_IF}'
STEALTH_MODE='${STEALTH_MODE}'
BAN_AFTER='${BAN_AFTER}'
BAN_TIME='${BAN_TIME}'
ENROLL_MINUTES='${ENROLL_MINUTES}'
INSTALL_DATE='${INSTALL_DATE:-}'
EOF_CFG
    chmod 600 "$CONFIG_FILE"
}

ipset_save_state() {
    need_root || return 0
    mkdir -p "$INSTALL_DIR"
    ipset save "$ALLOW_SET" "$BAN_SET" "$OPEN_SET" > "$IPSET_SAVE" 2>/dev/null || true
}

ipset_count() {
    local out
    out=$(ipset list -t "$1" 2>/dev/null | awk '/^Entries:/ {print $2}') || true
    echo "${out:-?}"
}

# Rebuilds the SOCKS5-FW filter chain according to STEALTH_MODE.
fw_rebuild_chain() {
    need_root || return 1
    iptables -N "$FW_CHAIN" 2>/dev/null || true
    iptables -F "$FW_CHAIN"

    # 1. Banned / known prober IPs are silently dropped
    iptables -A "$FW_CHAIN" -m set --match-set "$BAN_SET" src -j DROP

    # 2. Loopback is always allowed (local curl/ss checks keep working)
    iptables -A "$FW_CHAIN" -i lo -j ACCEPT

    # 3. Smart SYN limiter (works because over-limit SYNs hit the DROP below)
    iptables -A "$FW_CHAIN" -p tcp --syn -m hashlimit \
        --hashlimit-name s5_syn --hashlimit 25/sec --hashlimit-burst 50 \
        --hashlimit-mode srcip -j ACCEPT
    iptables -A "$FW_CHAIN" -p tcp --syn -j DROP

    # 4. Stealth: only enrolled IPs may reach the SOCKS5 daemon
    if [[ "$STEALTH_MODE" == "on" ]]; then
        iptables -A "$FW_CHAIN" -m set --match-set "$ALLOW_SET" src -j ACCEPT
        iptables -A "$FW_CHAIN" -m set --match-set "$OPEN_SET" src -j ACCEPT
        iptables -A "$FW_CHAIN" -j DROP
    else
        iptables -A "$FW_CHAIN" -j ACCEPT
    fi

    # Attach to INPUT for the local SOCKS5 port (mirror ports are NATed to it)
    if ! iptables -C INPUT -p tcp --dport "$SOCKS_PORT" -j "$FW_CHAIN" 2>/dev/null; then
        iptables -I INPUT 1 -p tcp --dport "$SOCKS_PORT" -j "$FW_CHAIN"
    fi

    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    fi
}

show_menu() {
    clear
    echo -e "${CYAN}${BOLD}======================================================================${NC}"
    echo -e "${CYAN}${BOLD}         SOCKS5 Anti-DPI — Панель управления сервером                ${NC}"
    echo -e "${CYAN}${BOLD}======================================================================${NC}"
    echo -e "Порт: ${GREEN}${SOCKS_PORT}${NC} | Пользователь: ${GREEN}${SOCKS_USER}${NC} | Stealth: ${YELLOW}${STEALTH_MODE}${NC}"
    if [[ -n "${MULTIPORT_LIST:-}" ]]; then
        echo -e "Зеркала портов: ${YELLOW}${MULTIPORT_LIST}${NC}"
    fi
    echo ""
    echo "  1) Статус служб и сетевая статистика"
    echo "  2) Показать данные и ссылки для подключения"
    echo "  3) Показать QR-код для Telegram"
    echo "  4) Просмотр логов в реальном времени"
    echo "  5) Сменить пароль пользователя"
    echo "  6) Перезапустить прокси"
    echo "  7) Остановить прокси"
    echo "  8) Запустить прокси"
    echo "  9) Stealth (невидимость): вкл/выкл/статус"
    echo " 10) Открыть окно записи нового клиента (enroll)"
    echo " 11) Список разрешенных и забаненных IP"
    echo "  0) Выход"
    echo ""
    read -rp "Выберите пункт меню [1-11, 0]: " CHOICE
    case "$CHOICE" in
        1) action_status; read -rp "Нажмите Enter для продолжения..." ;;
        2) action_info; read -rp "Нажмите Enter для продолжения..." ;;
        3) action_qr; read -rp "Нажмите Enter для продолжения..." ;;
        4) action_logs ;;
        5) action_passwd ;;
        6) action_restart; sleep 1 ;;
        7) action_stop; sleep 1 ;;
        8) action_start; sleep 1 ;;
        9) action_stealth_menu ;;
        10) action_enroll; read -rp "Нажмите Enter для продолжения..." ;;
        11) action_list; read -rp "Нажмите Enter для продолжения..." ;;
        0) exit 0 ;;
        *) echo "Неверный выбор"; sleep 1 ;;
    esac
}

action_status() {
    echo -e "\n${CYAN}${BOLD}=== Статус SOCKS5 Anti-DPI ===${NC}\n"

    echo -e "${BOLD}1. Dante Daemon (SOCKS5):${NC}"
    if systemctl is-active --quiet danted; then
        echo -e "   Статус: ${GREEN}АКТИВЕН (RUNNING)${NC}"
    else
        echo -e "   Статус: ${RED}ОСТАНОВЛЕН${NC}"
    fi

    echo -e "\n${BOLD}2. TCP Window Clamper (Anti-DPI):${NC}"
    if systemctl is-active --quiet socks5-winclamp; then
        echo -e "   Статус: ${GREEN}АКТИВЕН (RUNNING)${NC}"
        killall -USR1 socks5-winclamp 2>/dev/null || pkill -USR1 socks5-winclamp 2>/dev/null || true
        sleep 1
        local recent_stats
        recent_stats=$(journalctl -u socks5-winclamp -n 10 --no-pager 2>/dev/null | grep "Stats:" | tail -n 1 || true)
        if [[ -n "$recent_stats" ]]; then
            echo -e "   ${CYAN}${recent_stats}${NC}"
        fi
    else
        echo -e "   Статус: ${RED}ОСТАНОВЛЕН${NC}"
    fi

    echo -e "\n${BOLD}3. Stealth-режим (невидимость для сканеров/ТСПУ):${NC}"
    echo -e "   Режим: ${YELLOW}${STEALTH_MODE}${NC}"
    echo -e "   Разрешённых IP: ${GREEN}$(ipset_count "$ALLOW_SET")${NC} | Забанено: ${RED}$(ipset_count "$BAN_SET")${NC}"

    echo -e "\n${BOLD}4. Счетчики пакетов очереди NFQUEUE (iptables):${NC}"
    iptables -t mangle -L OUTPUT -v -n --line-numbers 2>/dev/null | grep -E "NFQUEUE|Chain" || true

    if [[ -n "${MULTIPORT_LIST:-}" ]]; then
        echo -e "\n${BOLD}5. Счетчики мультипортового зеркала (Redirect):${NC}"
        iptables -t nat -L PREROUTING -v -n 2>/dev/null | grep -E "REDIRECT|to-ports" || true
    fi

    echo -e "\n${BOLD}6. Активные соединения с клиентами:${NC}"
    ss -tan state established "( sport = :${SOCKS_PORT} )" 2>/dev/null | head -n 15 || true
    echo ""
}

action_info() {
    SERVER_IP=$(curl -s4 --max-time 3 https://api.ipify.org || echo "YOUR_SERVER_IP")
    echo -e "\n${CYAN}${BOLD}=== Данные для подключения ===${NC}"
    echo -e "  • Сервер:         ${GREEN}${SERVER_IP}${NC}"
    echo -e "  • Основной порт:  ${GREEN}${SOCKS_PORT}${NC}"
    if [[ -n "${MULTIPORT_LIST:-}" ]]; then
        echo -e "  • Зеркальные порты: ${YELLOW}${MULTIPORT_LIST}${NC}"
    fi
    echo -e "  • Логин:          ${GREEN}${SOCKS_USER}${NC}"
    echo -e "  • Пароль:         ${GREEN}${SOCKS_PASS}${NC}"
    echo ""
    echo -e "  • SOCKS5 URL:     ${YELLOW}socks5://${SOCKS_USER}:${SOCKS_PASS}@${SERVER_IP}:${SOCKS_PORT}${NC}"
    echo -e "  • Telegram порт ${SOCKS_PORT}:"
    echo -e "    ${YELLOW}tg://socks?server=${SERVER_IP}&port=${SOCKS_PORT}&user=${SOCKS_USER}&pass=${SOCKS_PASS}${NC}"
    if [[ -n "${MULTIPORT_LIST:-}" ]]; then
        FIRST_MIRROR=$(echo "$MULTIPORT_LIST" | cut -d',' -f1)
        echo -e "  • Telegram резервный порт ${FIRST_MIRROR} (маскировка):"
        echo -e "    ${YELLOW}tg://socks?server=${SERVER_IP}&port=${FIRST_MIRROR}&user=${SOCKS_USER}&pass=${SOCKS_PASS}${NC}"
    fi
    echo ""
    echo -e "  • Проверка через curl:"
    echo -e "    ${CYAN}curl -x socks5h://${SOCKS_USER}:${SOCKS_PASS}@${SERVER_IP}:${SOCKS_PORT} https://api.ipify.org${NC}"
    echo ""
    if [[ "$STEALTH_MODE" == "on" ]]; then
        echo -e "  • Stealth включён: IP этого устройства должен быть в списке разрешенных."
        echo -e "    Проверить/добавить: ${CYAN}socks5-control allow <IP>${NC}"
        echo -e "    Первое подключение с верным паролем добавляет IP автоматически."
    fi
    echo -e "  • Безопасность:"
    echo -e "    ${YELLOW}⚠️  SOCKS5 не шифрует открытый трафик (это не VPN). Защищены только HTTPS и Telegram.${NC}"
    echo ""
}

action_qr() {
    SERVER_IP=$(curl -s4 --max-time 3 https://api.ipify.org || echo "YOUR_SERVER_IP")
    local tg_url="tg://socks?server=${SERVER_IP}&port=${SOCKS_PORT}&user=${SOCKS_USER}&pass=${SOCKS_PASS}"
    if ! command -v qrencode &>/dev/null; then
        echo -e "${YELLOW}[!] Утилита qrencode не установлена. Установка...${NC}"
        apt-get install -y -qq qrencode 2>/dev/null || true
    fi
    if command -v qrencode &>/dev/null; then
        echo -e "\n${CYAN}${BOLD}=== QR-код для быстрого подключения в Telegram ===${NC}\n"
        qrencode -t ANSI256 "$tg_url" 2>/dev/null || qrencode -t UTF8 "$tg_url" 2>/dev/null || true
        echo -e "\nСсылка: ${YELLOW}${tg_url}${NC}\n"
    else
        echo -e "${RED}[ERROR] qrencode недоступен. Ссылка для подключения:${NC}"
        echo -e "${YELLOW}${tg_url}${NC}"
    fi
}

action_logs() {
    echo -e "${CYAN}${BOLD}=== Просмотр логов в реальном времени (Ctrl+C для возврата) ===${NC}"
    journalctl -u socks5-winclamp -u danted -f || true
}

action_passwd() {
    local new_pass="${1:-}"
    if [[ -z "$new_pass" ]]; then
        read -rsp "Введите новый пароль для ${SOCKS_USER}: " new_pass || new_pass=""
        echo ""
    fi
    if [[ -z "$new_pass" ]]; then
        return 0
    fi
    if ! [[ "$new_pass" =~ $PASS_RE ]]; then
        echo -e "${RED}[ERROR] Пароль может содержать только A-Z a-z 0-9 . _ ~ ! @ % ^ + = , ? * - (8-64 символов).${NC}" >&2
        return 1
    fi
    need_root || return 1
    echo "${SOCKS_USER}:${new_pass}" | chpasswd
    SOCKS_PASS="$new_pass"
    save_config
    echo -e "${GREEN}[OK] Пароль успешно изменен!${NC}"
}

action_restart() {
    need_root || return 1
    echo -e "${BLUE}[*] Перезапуск служб...${NC}"
    systemctl restart socks5-winclamp danted
    echo -e "${GREEN}[OK] Службы перезапущены.${NC}"
}

action_stop() {
    need_root || return 1
    echo -e "${BLUE}[*] Остановка служб...${NC}"
    systemctl stop socks5-winclamp danted
    echo -e "${YELLOW}[OK] Службы остановлены.${NC}"
}

action_start() {
    need_root || return 1
    echo -e "${BLUE}[*] Запуск служб...${NC}"
    systemctl start socks5-winclamp danted
    echo -e "${GREEN}[OK] Службы запущены.${NC}"
}

action_stealth_set() {
    local mode="$1"
    need_root || return 1
    if [[ "$mode" != "on" && "$mode" != "off" ]]; then
        echo "Использование: socks5-control stealth [on|off|status]"
        return 1
    fi
    STEALTH_MODE="$mode"
    save_config
    fw_rebuild_chain
    if [[ "$mode" == "on" ]]; then
        echo -e "${GREEN}[OK] Stealth включён: неизвестные IP молча отбрасываются (порт выглядит закрытым).${NC}"
        echo -e "${YELLOW}    Не забудьте про окно записи: socks5-control enroll${NC}"
    else
        echo -e "${YELLOW}[OK] Stealth выключен: сервер отвечает всем IP (как раньше).${NC}"
    fi
    ipset_save_state
}

action_stealth_status() {
    echo -e "\n${BOLD}Stealth:${NC} ${YELLOW}${STEALTH_MODE}${NC}"
    echo -e "${BOLD}Разрешённые IP (${ALLOW_SET}): ${GREEN}$(ipset_count "$ALLOW_SET")${NC}"
    echo -e "${BOLD}Забаненные IP (${BAN_SET}): ${RED}$(ipset_count "$BAN_SET")${NC}"
    if iptables -C INPUT -p tcp --dport "$SOCKS_PORT" -j "$FW_CHAIN" 2>/dev/null; then
        echo -e "${BOLD}Цепочка ${FW_CHAIN}:${NC} ${GREEN}подключена к INPUT${NC}"
    else
        echo -e "${BOLD}Цепочка ${FW_CHAIN}:${NC} ${RED}НЕ подключена (запустите: socks5-control stealth on)${NC}"
    fi
    echo ""
}

action_stealth_menu() {
    echo ""
    echo "  1) Включить stealth"
    echo "  2) Выключить stealth"
    echo "  3) Показать статус"
    read -rp "Ваш выбор [1-3]: " SC
    case "$SC" in
        1) action_stealth_set "on"; read -rp "Нажмите Enter..." ;;
        2) action_stealth_set "off"; read -rp "Нажмите Enter..." ;;
        3) action_stealth_status; read -rp "Нажмите Enter..." ;;
        *) : ;;
    esac
}

action_enroll() {
    need_root || return 1
    local mins="${1:-}"
    if [[ -z "$mins" ]]; then
        read -rp "На сколько минут открыть запись новых клиентов? [${ENROLL_MINUTES}]: " mins
        mins="${mins:-$ENROLL_MINUTES}"
    fi
    if ! [[ "$mins" =~ ^[0-9]{1,3}$ ]] || (( mins < 1 )); then
        echo -e "${RED}[ERROR] Некорректное число минут.${NC}" >&2
        return 1
    fi
    if ! ipset add "$OPEN_SET" 0.0.0.0/0 timeout "$((mins * 60))" -exist; then
        echo -e "${RED}[ERROR] Не удалось открыть окно (ipset недоступен?).${NC}" >&2
        return 1
    fi
    ipset_save_state
    echo -e "${GREEN}[OK] Окно записи открыто на ${mins} мин.${NC}"
    echo -e "    Подключите новое устройство к прокси с правильным паролем —"
    echo -e "    его IP автоматически попадёт в список разрешенных (${ALLOW_SET})."
}

action_allow() {
    need_root || return 1
    local ip="${1:-}"
    if [[ -z "$ip" ]]; then
        read -rp "Введите IPv4-адрес клиента для разрешения: " ip
    fi
    if ! is_ipv4 "$ip"; then
        echo -e "${RED}[ERROR] Некорректный IPv4-адрес: $ip${NC}" >&2
        return 1
    fi
    if ! ipset add "$ALLOW_SET" "$ip" -exist; then
        echo -e "${RED}[ERROR] Не удалось добавить IP (ipset недоступен?).${NC}" >&2
        return 1
    fi
    ipset del "$BAN_SET" "$ip" -exist 2>/dev/null || true
    ipset_save_state
    echo -e "${GREEN}[OK] IP ${ip} добавлен в список разрешенных (и снят с бана).${NC}"
}

action_deny() {
    need_root || return 1
    local ip="${1:-}"
    if [[ -z "$ip" ]]; then
        read -rp "Введите IPv4-адрес для блокировки: " ip
    fi
    if ! is_ipv4 "$ip"; then
        echo -e "${RED}[ERROR] Некорректный IPv4-адрес: $ip${NC}" >&2
        return 1
    fi
    if ! ipset add "$BAN_SET" "$ip" timeout 0 -exist; then
        echo -e "${RED}[ERROR] Не удалось заблокировать IP (ipset недоступен?).${NC}" >&2
        return 1
    fi
    ipset del "$ALLOW_SET" "$ip" -exist 2>/dev/null || true
    ipset_save_state
    echo -e "${GREEN}[OK] IP ${ip} заблокирован (без срока).${NC}"
}

action_unban() {
    need_root || return 1
    local ip="${1:-}"
    if [[ -z "$ip" ]]; then
        read -rp "Введите IPv4-адрес для разблокировки: " ip
    fi
    if ! is_ipv4 "$ip"; then
        echo -e "${RED}[ERROR] Некорректный IPv4-адрес: $ip${NC}" >&2
        return 1
    fi
    if ! ipset del "$BAN_SET" "$ip" -exist; then
        echo -e "${RED}[ERROR] Не удалось снять бан (ipset недоступен?).${NC}" >&2
        return 1
    fi
    ipset_save_state
    echo -e "${GREEN}[OK] IP ${ip} разблокирован.${NC}"
}

action_list() {
    echo -e "\n${CYAN}${BOLD}=== Разрешенные IP (${ALLOW_SET}) ===${NC}"
    if [[ "$(ipset_count "$ALLOW_SET")" == "0" ]]; then
        echo "  (пусто — при stealth никто не подключится, сделайте: socks5-control enroll)"
    else
        ipset list "$ALLOW_SET" 2>/dev/null | awk '/^[0-9]/{print "  "$1}' || true
    fi
    echo -e "\n${CYAN}${BOLD}=== Забаненные IP (${BAN_SET}) ===${NC}"
    if [[ "$(ipset_count "$BAN_SET")" == "0" ]]; then
        echo "  (пусто)"
    else
        ipset list "$BAN_SET" 2>/dev/null | awk '/^[0-9]/{print "  "$1}' || true
    fi
    echo -e "\n${CYAN}${BOLD}=== Окно записи (${OPEN_SET}) ===${NC}"
    if [[ "$(ipset_count "$OPEN_SET")" == "0" ]]; then
        echo "  (закрыто)"
    else
        echo "  (открыто: новые устройства будут записаны)"
    fi
    echo ""
}

show_help() {
    echo "Использование: socks5-control <команда> [аргумент]"
    echo ""
    echo "  status                 Статус служб, NFQUEUE и stealth"
    echo "  info                   Данные и ссылки для подключения"
    echo "  qr                     QR-код для Telegram"
    echo "  logs                   Логи в реальном времени"
    echo "  passwd [пароль]        Смена пароля (без аргумента — интерактивно)"
    echo "  restart|stop|start     Управление службами"
    echo "  stealth on|off|status  Режим невидимости (только разрешенные IP)"
    echo "  enroll [минуты]        Открыть окно записи новых клиентов"
    echo "  allow <IP>             Разрешить IP вручную"
    echo "  deny <IP>              Заблокировать IP навсегда"
    echo "  unban <IP>             Снять бан с IP"
    echo "  list                   Списки разрешенных/забаненных IP"
}

# Direct CLI flags or interactive menu
if [[ $# -eq 0 ]]; then
    while true; do
        show_menu
    done
else
    case "$1" in
        status)  action_status ;;
        info)    action_info ;;
        qr)      action_qr ;;
        logs)    action_logs ;;
        restart) action_restart ;;
        stop)    action_stop ;;
        start)   action_start ;;
        passwd)  action_passwd "${2:-}" ;;
        stealth)
            if [[ "${2:-}" == "on" || "${2:-}" == "off" ]]; then
                action_stealth_set "$2"
            else
                action_stealth_status
            fi
            ;;
        enroll)  action_enroll "${2:-}" ;;
        allow)   action_allow "${2:-}" ;;
        deny)    action_deny "${2:-}" ;;
        unban)   action_unban "${2:-}" ;;
        list)    action_list ;;
        -h|--help|help) show_help ;;
        *)
            show_help
            ;;
    esac
fi
