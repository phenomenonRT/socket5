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

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${RED}[ERROR] Файл конфигурации $CONFIG_FILE не найден. Сервер установлен?${NC}" >&2
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

show_menu() {
    clear
    echo -e "${CYAN}${BOLD}======================================================================${NC}"
    echo -e "${CYAN}${BOLD}         SOCKS5 Anti-DPI — Панель управления сервером                ${NC}"
    echo -e "${CYAN}${BOLD}======================================================================${NC}"
    echo -e "Порт: ${GREEN}${SOCKS_PORT}${NC} | Пользователь: ${GREEN}${SOCKS_USER}${NC}"
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
    echo "  0) Выход"
    echo ""
    read -rp "Выберите пункт меню [1-8, 0]: " CHOICE
    case "$CHOICE" in
        1) action_status; read -rp "Нажмите Enter для продолжения..." ;;
        2) action_info; read -rp "Нажмите Enter для продолжения..." ;;
        3) action_qr; read -rp "Нажмите Enter для продолжения..." ;;
        4) action_logs ;;
        5) action_passwd ;;
        6) action_restart; sleep 1 ;;
        7) action_stop; sleep 1 ;;
        8) action_start; sleep 1 ;;
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
        # Trigger stats dump
        killall -USR1 socks5-winclamp 2>/dev/null || pkill -USR1 socks5-winclamp 2>/dev/null || true
        local recent_stats
        recent_stats=$(journalctl -u socks5-winclamp -n 5 --no-pager 2>/dev/null | grep "Stats:" | tail -n 1 || true)
        if [[ -n "$recent_stats" ]]; then
            echo -e "   ${CYAN}${recent_stats}${NC}"
        fi
    else
        echo -e "   Статус: ${RED}ОСТАНОВЛЕН${NC}"
    fi

    echo -e "\n${BOLD}3. Счетчики пакетов очереди NFQUEUE (iptables):${NC}"
    iptables -t mangle -L OUTPUT -v -n --line-numbers | grep -E "NFQUEUE|Chain" || true

    if [[ -n "${MULTIPORT_LIST:-}" ]]; then
        echo -e "\n${BOLD}4. Счетчики мультипортового зеркала (Redirect):${NC}"
        iptables -t nat -L PREROUTING -v -n | grep -E "REDIRECT|to-ports" || true
    fi

    echo -e "\n${BOLD}5. Активные соединения с клиентами:${NC}"
    ss -tan state established "( sport = :${SOCKS_PORT} )" | head -n 15
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
    journalctl -u socks5-winclamp -u danted -f
}

action_passwd() {
    read -rp "Введите новый пароль для ${SOCKS_USER}: " NEW_PASS
    if [[ -n "$NEW_PASS" ]]; then
        echo "${SOCKS_USER}:${NEW_PASS}" | chpasswd
        sed -i "s/^SOCKS_PASS=.*/SOCKS_PASS=${NEW_PASS}/" "$CONFIG_FILE"
        echo -e "${GREEN}[OK] Пароль успешно изменен!${NC}"
    fi
}

action_restart() {
    echo -e "${BLUE}[*] Перезапуск служб...${NC}"
    systemctl restart socks5-winclamp danted
    echo -e "${GREEN}[OK] Службы перезапущены.${NC}"
}

action_stop() {
    echo -e "${BLUE}[*] Остановка служб...${NC}"
    systemctl stop socks5-winclamp danted
    echo -e "${YELLOW}[OK] Службы остановлены.${NC}"
}

action_start() {
    echo -e "${BLUE}[*] Запуск служб...${NC}"
    systemctl start socks5-winclamp danted
    echo -e "${GREEN}[OK] Службы запущены.${NC}"
}

# Direct CLI flags or interactive menu
if [[ $# -eq 0 ]]; then
    while true; do
        show_menu
    done
else
    case "$1" in
        status) action_status ;;
        info) action_info ;;
        qr) action_qr ;;
        logs) action_logs ;;
        restart) action_restart ;;
        stop) action_stop ;;
        start) action_start ;;
        passwd)
            if [[ -n "${2:-}" ]]; then
                echo "${SOCKS_USER}:${2}" | chpasswd
                sed -i "s/^SOCKS_PASS=.*/SOCKS_PASS=${2}/" "$CONFIG_FILE"
                echo -e "${GREEN}[OK] Пароль успешно изменен.${NC}"
            else
                action_passwd
            fi
            ;;
        *)
            echo "Использование: socks5-control [status|info|qr|logs|restart|stop|start|passwd]"
            ;;
    esac
fi
