#!/usr/bin/env bash
# ==============================================================================
# SOCKS5 Anti-DPI Suite — Online Installer
# GitHub: https://github.com/phenomenonRT/socket5
# Bypass Russian TSPU / РКН DPI without changing any client software!
# Supported OS: Ubuntu 20.04 / 22.04 / 24.04, Debian 10 / 11 / 12
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

REPO="phenomenonRT/socket5"
BRANCH="${SOCKET5_BRANCH:-main}"
RAW_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}"

INSTALL_DIR="/opt/socks5-antidpi"
CONFIG_FILE="/etc/socks5-antidpi.conf"

echo -e "${CYAN}${BOLD}"
echo "======================================================================"
echo "    SOCKS5 Anti-DPI Suite — Серверный обход блокировок ТСПУ"
echo "    GitHub: https://github.com/${REPO}"
echo "======================================================================"
echo -e "${NC}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}[ERROR] Запустите скрипт с правами root: sudo bash install.sh${NC}" >&2
    exit 1
fi

# Detect package manager
if ! command -v apt-get &>/dev/null; then
    echo -e "${RED}[ERROR] Поддерживаются только ОС на базе Debian/Ubuntu (apt).${NC}" >&2
    exit 1
fi

# Create installation directory
mkdir -p "$INSTALL_DIR"

# Download helper function
download_repo_file() {
    local filename="$1"
    local target="${INSTALL_DIR}/${filename}"

    if [[ -f "./${filename}" ]]; then
        cp "./${filename}" "$target"
    else
        echo -e "  ↳ Загрузка ${filename} с GitHub (${REPO})..."
        if ! curl -fsSL --retry 3 --max-time 15 "${RAW_URL}/${filename}" -o "$target" 2>/dev/null; then
            # If download fails, check if we have embedded fallback
            if [[ "$filename" == "socks5-winclamp.c" ]]; then
                echo -e "${YELLOW}  ↳ Внимание: онлайн-загрузка недоступна, создается встроенный исходник...${NC}"
                write_embedded_winclamp "$target"
            elif [[ "$filename" == "socks5-control.sh" ]]; then
                write_embedded_control "$target"
            elif [[ "$filename" == "uninstall.sh" ]]; then
                write_embedded_uninstall "$target"
            fi
        fi
    fi
}

write_embedded_winclamp() {
    local target="$1"
    cat > "$target" << 'EOF_C'
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

static volatile bool g_running = true;
static uint16_t g_clamp_window = 2;
static uint16_t g_queue_num = 200;
static bool g_clamp_connect = true;
static bool g_verbose = false;

static void sig_handler(int signo) { (void)signo; g_running = false; }

static inline void update_tcp_checksum(uint16_t *csum, uint16_t old_val, uint16_t new_val) {
    uint32_t sum = (~(*csum) & 0xffff) + (~old_val & 0xffff) + (new_val & 0xffff);
    while (sum >> 16) { sum = (sum & 0xffff) + (sum >> 16); }
    uint16_t res = (uint16_t)(~sum);
    *csum = (res == 0) ? 0xffff : res;
}

static int packet_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                           struct nfq_data *nfa, void *data) {
    (void)nfmsg; (void)data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return 0;
    uint32_t id = ntohl(ph->packet_id);
    unsigned char *payload = NULL;
    int len = nfq_get_payload(nfa, &payload);
    if (len < 0 || !payload) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    bool modified = false;
    struct iphdr *iph = (struct iphdr *)payload;
    if (iph->version == 4 && iph->protocol == IPPROTO_TCP) {
        int ip_hl = iph->ihl * 4;
        if (len >= ip_hl + (int)sizeof(struct tcphdr)) {
            struct tcphdr *tcph = (struct tcphdr *)(payload + ip_hl);
            int tcp_hl = tcph->doff * 4;
            unsigned char *tcp_data = payload + ip_hl + tcp_hl;
            int tcp_data_len = len - (ip_hl + tcp_hl);

            bool should_clamp = false;
            if (tcph->syn && tcph->ack) {
                should_clamp = true;
            } else if (g_clamp_connect && tcp_data_len >= 2 && tcp_data[0] == 0x05 &&
                       (tcp_data[1] == 0x00 || tcp_data[1] == 0x02)) {
                should_clamp = true;
            } else if (g_clamp_connect && tcp_data_len >= 2 && tcp_data[0] == 0x01 && tcp_data[1] == 0x00) {
                should_clamp = true;
            }

            if (should_clamp) {
                uint16_t old_win = tcph->window;
                uint16_t new_win = htons(g_clamp_window);
                if (old_win != new_win) {
                    tcph->window = new_win;
                    update_tcp_checksum(&tcph->check, old_win, new_win);
                    modified = true;
                }
            }
        }
    }
    if (modified) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "q:w:svh")) != -1) {
        switch (opt) {
            case 'q': g_queue_num = (uint16_t)atoi(optarg); break;
            case 'w': g_clamp_window = (uint16_t)atoi(optarg); break;
            case 's': g_clamp_connect = false; break;
            case 'v': g_verbose = true; break;
            default: break;
        }
    }
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    struct nfq_handle *h = nfq_open();
    if (!h) return 1;
    nfq_bind_pf(h, AF_INET);
    struct nfq_q_handle *qh = nfq_create_queue(h, g_queue_num, &packet_callback, NULL);
    if (!qh) return 1;
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));
    while (g_running) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) nfq_handle_packet(h, buf, rv);
    }
    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
EOF_C
}

write_embedded_control() {
    local target="$1"
    # shellcheck disable=SC2016
    cat > "$target" << 'EOF_SH'
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
    if [[ "${MULTIPORT_LIST:-}" =~ 443 ]]; then
        echo -e "  • Telegram порт 443 (HTTPS маскировка):"
        echo -e "    ${YELLOW}tg://socks?server=${SERVER_IP}&port=443&user=${SOCKS_USER}&pass=${SOCKS_PASS}${NC}"
    fi
    echo ""
    echo -e "  • Проверка через curl:"
    echo -e "    ${CYAN}curl -x socks5h://${SOCKS_USER}:${SOCKS_PASS}@${SERVER_IP}:${SOCKS_PORT} https://api.ipify.org${NC}"
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
EOF_SH
    chmod 755 "$target"
}

write_embedded_uninstall() {
    local target="$1"
    cat > "$target" << 'EOF_UNINSTALL'
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
EOF_UNINSTALL
    chmod 755 "$target"
}

# --- Parse Arguments or Interactive Mode ---
ARG_PORT=""
ARG_USER=""
ARG_PASS=""
ARG_MODE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port) ARG_PORT="$2"; shift 2 ;;
        -u|--user) ARG_USER="$2"; shift 2 ;;
        -P|--password) ARG_PASS="$2"; shift 2 ;;
        -m|--mode) ARG_MODE="$2"; shift 2 ;;
        -h|--help)
            echo "Использование: bash install.sh [-p порт] [-u логин] [-P пароль] [-m режим]"
            echo "Режимы (-m):"
            echo "  1 - Ультра (Window Clamping + Multiport 443,8443,53 + Anti-Probe)"
            echo "  2 - Классик (Только Window Clamping на одном порту)"
            exit 0 ;;
        *) shift ;;
    esac
done

# Detect Network
DEFAULT_IF=$(ip -4 route show default | awk '{print $5}' | head -n1 || ip route | grep '^default' | head -n1 | awk '{print $5}' || true)
SERVER_IP=$(curl -s4 --max-time 4 https://api.ipify.org || curl -s4 --max-time 4 https://ifconfig.me || echo "YOUR_SERVER_IP")

echo -e "Сетевой интерфейс: ${GREEN}${DEFAULT_IF}${NC}"
echo -e "Внешний IP адрес:  ${GREEN}${SERVER_IP}${NC}\n"

# Mode selection
if [[ -z "$ARG_MODE" ]]; then
    echo -e "${BOLD}Выберите режим обхода блокировок:${NC}"
    echo -e "  ${CYAN}1)${NC} ${BOLD}УЛЬТРА (Рекомендуется)${NC}"
    echo -e "     • Двухэтапная нарезка TCP-окна (Greeting + Connect)"
    echo -e "     • Мультипортовое зеркало: слушает сразу на портах ${YELLOW}443, 8443, 1080, 2083, 53${NC}"
    echo -e "     • Защита от активных зондов РКН (Anti-Active Probing)"
    echo -e "     • BBR сетевое ускорение"
    echo -e "  ${CYAN}2)${NC} ${BOLD}КЛАССИКА${NC}"
    echo -e "     • Нарезка TCP-окна только на одном выбранном порту"
    read -rp "Выберите вариант [1]: " INPUT_MODE
    BYPASS_MODE="${INPUT_MODE:-1}"
else
    BYPASS_MODE="$ARG_MODE"
fi

if [[ -z "$ARG_PORT" ]]; then
    read -rp "Основной порт SOCKS5 [по умолчанию: 1080]: " INPUT_PORT
    SOCKS_PORT="${INPUT_PORT:-1080}"
else
    SOCKS_PORT="$ARG_PORT"
fi

if [[ -z "$ARG_USER" ]]; then
    read -rp "Имя пользователя [по умолчанию: proxyuser]: " INPUT_USER
    SOCKS_USER="${INPUT_USER:-proxyuser}"
else
    SOCKS_USER="$ARG_USER"
fi

if [[ -z "$ARG_PASS" ]]; then
    read -rp "Пароль [Enter для случайного]: " INPUT_PASS
    if [[ -z "$INPUT_PASS" ]]; then
        SOCKS_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 14)
    else
        SOCKS_PASS="$INPUT_PASS"
    fi
else
    SOCKS_PASS="$ARG_PASS"
fi

CLAMP_WINDOW=2
QUEUE_NUM=200

echo -e "\n${BLUE}[1/6] Установка системных пакетов и зависимостей...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    build-essential \
    libnetfilter-queue-dev \
    dante-server \
    iptables \
    iptables-persistent \
    netfilter-persistent \
    curl \
    ethtool \
    ca-certificates \
    qrencode

echo -e "${BLUE}[2/6] Загрузка и компиляция ядра обхода (socks5-winclamp)...${NC}"
download_repo_file "socks5-winclamp.c"
download_repo_file "socks5-control.sh"
download_repo_file "uninstall.sh"

gcc -O2 -Wall "${INSTALL_DIR}/socks5-winclamp.c" -lnetfilter_queue -o /usr/local/bin/socks5-winclamp
chmod 755 /usr/local/bin/socks5-winclamp
install -m 755 "${INSTALL_DIR}/socks5-control.sh" /usr/local/bin/socks5-control

echo -e "${BLUE}[3/6] Конфигурация SOCKS5 (Dante)...${NC}"
if ! id "$SOCKS_USER" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -M "$SOCKS_USER"
fi
echo "${SOCKS_USER}:${SOCKS_PASS}" | chpasswd

cat > /etc/danted.conf <<EOF
logoutput: /var/log/danted.log
internal: 0.0.0.0 port = ${SOCKS_PORT}
external: ${DEFAULT_IF}

socksmethod: username
clientmethod: none

user.privileged: root
user.unprivileged: nobody

client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error
}

socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error
}
EOF

echo -e "${BLUE}[4/6] Настройка службы systemd...${NC}"
cat > /etc/systemd/system/socks5-winclamp.service <<EOF
[Unit]
Description=SOCKS5 Anti-DPI TCP Window Clamper
After=network.target danted.service
Wants=danted.service

[Service]
Type=simple
ExecStart=/usr/local/bin/socks5-winclamp -q ${QUEUE_NUM} -w ${CLAMP_WINDOW}
Restart=always
RestartSec=2
KillMode=process
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable socks5-winclamp danted
systemctl restart socks5-winclamp danted

echo -e "${BLUE}[5/6] Применение сетевых правил (iptables / Multiport / Anti-Probe)...${NC}"

# Очистка старых правил
iptables -t mangle -D OUTPUT -p tcp --sport "${SOCKS_PORT}" -j NFQUEUE --queue-num "${QUEUE_NUM}" 2>/dev/null || true
iptables -D INPUT -p tcp --dport "${SOCKS_PORT}" -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p tcp --dport "${SOCKS_PORT}" --syn -m hashlimit --hashlimit-name s5_syn --hashlimit 25/sec --hashlimit-burst 50 --hashlimit-mode srcip -j ACCEPT 2>/dev/null || true

# 1. Заворачиваем исходящие пакеты SOCKS5 в NFQUEUE для зажатия TCP-окна
iptables -t mangle -I OUTPUT -p tcp --sport "${SOCKS_PORT}" -j NFQUEUE --queue-num "${QUEUE_NUM}"

# 2. Smart SYN Limiter (Защита от шторма SYN и сброса ТСПУ)
iptables -I INPUT -p tcp --dport "${SOCKS_PORT}" --syn -m hashlimit --hashlimit-name s5_syn --hashlimit 25/sec --hashlimit-burst 50 --hashlimit-mode srcip -j ACCEPT

# 3. Разрешаем входящий порт
iptables -I INPUT -p tcp --dport "${SOCKS_PORT}" -j ACCEPT

MULTIPORT_LIST=""
if [[ "$BYPASS_MODE" == "1" ]]; then
    # Мультипортовый режим: проверяем порты-кандидаты (443, 8443, 2083, 53)
    MIRROR_CANDIDATES=(443 8443 2083 53)
    VALID_MIRRORS=()
    for p in "${MIRROR_CANDIDATES[@]}"; do
        if [[ "$p" == "$SOCKS_PORT" ]]; then
            continue
        fi
        if ss -tulpn 2>/dev/null | grep -qE "(:|\])${p}\s"; then
            echo -e "    ${YELLOW}[!] Порт ${p} уже используется другой службой на сервере, пропускаем.${NC}"
        else
            VALID_MIRRORS+=("$p")
        fi
    done

    if [[ ${#VALID_MIRRORS[@]} -gt 0 ]]; then
        MIRROR_PORTS=$(IFS=,; echo "${VALID_MIRRORS[*]}")
        MULTIPORT_LIST="$MIRROR_PORTS"

        # Очищаем старые редиректы
        iptables -t nat -D PREROUTING -i "${DEFAULT_IF}" -p tcp -m multiport --dports "$MIRROR_PORTS" -j REDIRECT --to-ports "${SOCKS_PORT}" 2>/dev/null || true
        iptables -t nat -D PREROUTING -p tcp -m multiport --dports "$MIRROR_PORTS" -j REDIRECT --to-ports "${SOCKS_PORT}" 2>/dev/null || true
        iptables -D INPUT -p tcp -m multiport --dports "$MIRROR_PORTS" -j ACCEPT 2>/dev/null || true

        # Добавляем редирект на внешнем интерфейсе
        iptables -t nat -A PREROUTING -i "${DEFAULT_IF}" -p tcp -m multiport --dports "$MIRROR_PORTS" -j REDIRECT --to-ports "${SOCKS_PORT}"
        iptables -I INPUT -p tcp -m multiport --dports "$MIRROR_PORTS" -j ACCEPT
        echo -e "    ${GREEN}[+] Включено мультипортовое зеркалирование: ${MIRROR_PORTS}${NC}"
    fi
fi

# Сохранение правил iptables
netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

# Отключение аппаратной сегментации (TSO/GSO)
ethtool -K "$DEFAULT_IF" tso off gso off gro off 2>/dev/null || true

echo -e "${BLUE}[6/6] Оптимизация TCP BBR и фиксация TCP Window...${NC}"
cat > /etc/sysctl.d/99-socks5-antidpi.conf <<EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_window_scaling = 0
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF
sysctl -p /etc/sysctl.d/99-socks5-antidpi.conf &>/dev/null || true

# Сохранение метаданных
cat > "$CONFIG_FILE" <<EOF
SOCKS_PORT=${SOCKS_PORT}
SOCKS_USER=${SOCKS_USER}
SOCKS_PASS=${SOCKS_PASS}
BYPASS_MODE=${BYPASS_MODE}
MULTIPORT_LIST="${MULTIPORT_LIST}"
CLAMP_WINDOW=${CLAMP_WINDOW}
QUEUE_NUM=${QUEUE_NUM}
DEFAULT_IF=${DEFAULT_IF}
INSTALL_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
EOF
chmod 600 "$CONFIG_FILE"

echo -e "\n${GREEN}${BOLD}======================================================================${NC}"
echo -e "${GREEN}${BOLD}             УСТАНОВКА УСПЕШНО ЗАВЕРШЕНА!${NC}"
echo -e "${GREEN}${BOLD}======================================================================${NC}\n"

echo -e "Параметры для подключения:"
echo -e "  • Сервер:       ${CYAN}${SERVER_IP}${NC}"
echo -e "  • Основной порт:${CYAN}${SOCKS_PORT}${NC}"
if [[ -n "$MULTIPORT_LIST" ]]; then
echo -e "  • Зеркала (порты):${YELLOW}${MULTIPORT_LIST}${NC} (можно указывать любой из них!)"
fi
echo -e "  • Логин:        ${CYAN}${SOCKS_USER}${NC}"
echo -e "  • Пароль:       ${CYAN}${SOCKS_PASS}${NC}"

echo -e "\n${BOLD}Готовые ссылки:${NC}"
echo -e "  • Telegram порт ${SOCKS_PORT}:"
echo -e "    ${YELLOW}tg://socks?server=${SERVER_IP}&port=${SOCKS_PORT}&user=${SOCKS_USER}&pass=${SOCKS_PASS}${NC}"
if [[ -n "$MULTIPORT_LIST" ]]; then
echo -e "  • Telegram резервный порт 443 (HTTPS маскировка):"
echo -e "    ${YELLOW}tg://socks?server=${SERVER_IP}&port=443&user=${SOCKS_USER}&pass=${SOCKS_PASS}${NC}"
fi

echo -e "\n${BOLD}Быстрая проверка из терминала на клиенте:${NC}"
echo -e "  ${CYAN}curl -x socks5h://${SOCKS_USER}:${SOCKS_PASS}@${SERVER_IP}:${SOCKS_PORT} https://api.ipify.org${NC}"

echo -e "\n${BOLD}Команды управления:${NC}"
echo -e "  • Статус:   ${CYAN}socks5-control status${NC}"
echo -e "  • Логи:     ${CYAN}socks5-control logs${NC}"
echo -e "  • Инфо:     ${CYAN}socks5-control info${NC}\n"
