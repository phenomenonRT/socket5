#!/usr/bin/env bash
# ==============================================================================
# SOCKS5 Anti-DPI Suite — Online Installer
# GitHub: https://github.com/phenomenonRT/socket5
# Bypass Russian TSPU / РКН DPI without changing any client software!
# Supported OS: Ubuntu 20.04 / 22.04 / 24.04 / 26.04, Debian 10 / 11 / 12 / 13
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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
echo -e "${YELLOW}${BOLD}⚠️  ВНИМАНИЕ ПО БЕЗОПАСНОСТИ И ЗАЩИТЕ ДАННЫХ:${NC}"
echo -e "   • SOCKS5 — открытый прокси-протокол, он ${RED}${BOLD}НЕ шифрует${NC} трафик (это не VPN)."
echo -e "   • Комплекс предназначен только для ${CYAN}обхода блокировок ТСПУ${NC}."
echo -e "   • Данные защищены только внутри приложений с шифрованием (Telegram, HTTPS).\n"

if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}[ERROR] Запустите скрипт с правами root: sudo bash install.sh${NC}" >&2
    exit 1
fi

# Detect package manager
if ! command -v apt-get &>/dev/null; then
    echo -e "${RED}[ERROR] Поддерживаются только ОС на базе Debian/Ubuntu (apt).${NC}" >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# Helpers: prompts that work also when the script is piped (curl ... | bash)
# ------------------------------------------------------------------------------

ask_var() {
    local __var="$1" __prompt="$2" __default="${3:-}" __ans=""
    if [[ -t 0 ]]; then
        read -rp "$__prompt" __ans || __ans=""
    elif [[ -r /dev/tty ]]; then
        read -rp "$__prompt" __ans < /dev/tty || __ans=""
    fi
    printf -v "$__var" '%s' "${__ans:-$__default}"
}

ask_secret() {
    local __var="$1" __prompt="$2" __ans=""
    if [[ -t 0 ]]; then
        read -rsp "$__prompt" __ans || __ans=""
    elif [[ -r /dev/tty ]]; then
        read -rsp "$__prompt" __ans < /dev/tty || __ans=""
    fi
    echo ""
    printf -v "$__var" '%s' "$__ans"
}

ask_yesno() {
    # ask_yesno <var> <prompt> <default: y|n>
    local __var="$1" __prompt="$2" __default="${3:-y}" __ans=""
    local suffix="[Y/n]"
    [[ "$__default" == "n" ]] && suffix="[y/N]"
    if [[ -t 0 ]]; then
        read -rp "${__prompt} ${suffix}: " __ans || __ans=""
    elif [[ -r /dev/tty ]]; then
        read -rp "${__prompt} ${suffix}: " __ans < /dev/tty || __ans=""
    fi
    __ans="${__ans:-$__default}"
    case "${__ans,,}" in
        y|yes|д|да) printf -v "$__var" '%s' "y" ;;
        *)          printf -v "$__var" '%s' "n" ;;
    esac
}

PORT_RE='^[0-9]{1,5}$'
USER_RE='^[a-zA-Z0-9._-]{1,32}$'
PASS_RE='^[A-Za-z0-9._~!@%^+=,?*-]{8,64}$'

valid_port() {
    local p="$1"
    [[ "$p" =~ $PORT_RE ]] || return 1
    (( p >= 1 && p <= 65535 ))
}

valid_user() {
    [[ "$1" =~ $USER_RE ]]
}

valid_pass() {
    [[ "$1" =~ $PASS_RE ]]
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

# ------------------------------------------------------------------------------
# Parse arguments
# ------------------------------------------------------------------------------

ARG_PORT=""
ARG_USER=""
ARG_PASS=""
ARG_MODE=""
ARG_MIRRORS=""
ARG_STEALTH=""
ARG_ENROLL_MIN=""
ALLOW_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port) ARG_PORT="${2:-}"; shift 2 ;;
        -u|--user) ARG_USER="${2:-}"; shift 2 ;;
        -P|--password) ARG_PASS="${2:-}"; shift 2 ;;
        -m|--mode) ARG_MODE="${2:-}"; shift 2 ;;
        -M|--mirrors) ARG_MIRRORS="${2:-}"; shift 2 ;;
        -a|--allow) ALLOW_ARGS+=("${2:-}"); shift 2 ;;
        --stealth) ARG_STEALTH="on"; shift ;;
        --no-stealth) ARG_STEALTH="off"; shift ;;
        --enroll-min) ARG_ENROLL_MIN="${2:-}"; shift 2 ;;
        -h|--help)
            echo "Использование: bash install.sh [ОПЦИИ]"
            echo ""
            echo "Опции:"
            echo "  -p, --port <порт>          Основной порт SOCKS5 (по умолчанию 1080)"
            echo "  -u, --user <логин>         Имя пользователя (proxyuser)"
            echo "  -P, --password <пароль>    Пароль (по умолчанию случайный)"
            echo "  -m, --mode <1|2>           1 - Ультра, 2 - Классика"
            echo "  -M, --mirrors <порты>      Зеркальные порты через запятую (8443,2083)"
            echo "  -a, --allow <IP>           Сразу разрешить IP клиента (можно повторять)"
            echo "  --stealth | --no-stealth   Принудительно вкл/выкл режим невидимости"
            echo "  --enroll-min <минуты>      Длина окна записи клиентов (по умолчанию 30)"
            echo "  -h, --help                 Эта справка"
            exit 0 ;;
        *) shift ;;
    esac
done

# ------------------------------------------------------------------------------
# Read previous config (for clean rule replacement on reinstall)
# ------------------------------------------------------------------------------

PREV_PORT="" PREV_QUEUE="" PREV_MIRRORS="" PREV_IF=""
if [[ -f "$CONFIG_FILE" ]]; then
    PREV_LINE=$(bash -c 'source "$1" 2>/dev/null || true; printf "%s|%s|%s|%s" "${SOCKS_PORT:-}" "${QUEUE_NUM:-}" "${MULTIPORT_LIST:-}" "${DEFAULT_IF:-}"' _ "$CONFIG_FILE" 2>/dev/null || true)
    IFS='|' read -r PREV_PORT PREV_QUEUE PREV_MIRRORS PREV_IF <<< "$PREV_LINE"
fi

# ------------------------------------------------------------------------------
# Network detection
# ------------------------------------------------------------------------------

DEFAULT_IF=$(ip -4 route show default 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' || true)
if [[ -z "$DEFAULT_IF" ]]; then
    DEFAULT_IF=$(ip route 2>/dev/null | awk '/default/ && /dev/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' || true)
fi
if [[ -z "$DEFAULT_IF" ]]; then
    DEFAULT_IF=$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1 || true)
fi
if [[ -z "$DEFAULT_IF" ]]; then
    echo -e "${RED}[ERROR] Не удалось определить сетевой интерфейс (ip route пуст).${NC}" >&2
    exit 1
fi
SERVER_IP=$(curl -s4 --max-time 4 https://api.ipify.org || curl -s4 --max-time 4 https://ifconfig.me || echo "YOUR_SERVER_IP")

echo -e "Сетевой интерфейс: ${GREEN}${DEFAULT_IF}${NC}"
echo -e "Внешний IP адрес:  ${GREEN}${SERVER_IP}${NC}\n"

# ------------------------------------------------------------------------------
# Interactive questions
# ------------------------------------------------------------------------------

if [[ -z "$ARG_MODE" ]]; then
    echo -e "${BOLD}Выберите режим обхода блокировок:${NC}"
    echo -e "  ${CYAN}1)${NC} ${BOLD}УЛЬТРА (Рекомендуется)${NC}"
    echo -e "     • Двухэтапная нарезка TCP-окна (Greeting + Connect)"
    echo -e "     • Мультипортовое зеркало: слушает сразу на портах ${YELLOW}443, 8443, 1080, 2083, 53${NC}"
    echo -e "     • Stealth: невидимость для сканеров и активных зондов ТСПУ"
    echo -e "     • BBR сетевое ускорение"
    echo -e "  ${CYAN}2)${NC} ${BOLD}КЛАССИКА${NC}"
    echo -e "     • Нарезка TCP-окна только на одном выбранном порту"
    ask_var BYPASS_MODE "Выберите вариант [1]: " "1"
else
    BYPASS_MODE="$ARG_MODE"
fi
if [[ "$BYPASS_MODE" != "1" && "$BYPASS_MODE" != "2" ]]; then
    echo -e "${YELLOW}[!] Неизвестный режим '${BYPASS_MODE}', использую Ультра (1).${NC}"
    BYPASS_MODE="1"
fi

if [[ -z "$ARG_PORT" ]]; then
    ask_var INPUT_PORT "Основной порт SOCKS5 [по умолчанию: 1080]: " "1080"
    SOCKS_PORT="$INPUT_PORT"
else
    SOCKS_PORT="$ARG_PORT"
fi
if ! valid_port "$SOCKS_PORT"; then
    echo -e "${RED}[ERROR] Некорректный порт: '${SOCKS_PORT}'. Нужен 1..65535.${NC}" >&2
    exit 1
fi

if [[ -z "$ARG_USER" ]]; then
    ask_var INPUT_USER "Имя пользователя [по умолчанию: proxyuser]: " "proxyuser"
    SOCKS_USER="$INPUT_USER"
else
    SOCKS_USER="$ARG_USER"
fi
if ! valid_user "$SOCKS_USER"; then
    echo -e "${RED}[ERROR] Некорректный логин: '${SOCKS_USER}'. Разрешены A-Z a-z 0-9 . _ - (до 32 символов).${NC}" >&2
    exit 1
fi

if [[ -z "$ARG_PASS" ]]; then
    ask_secret INPUT_PASS "Пароль [Enter — сгенерировать случайный]: "
    if [[ -z "$INPUT_PASS" ]]; then
        SOCKS_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 14)
    else
        SOCKS_PASS="$INPUT_PASS"
    fi
else
    SOCKS_PASS="$ARG_PASS"
fi
if ! valid_pass "$SOCKS_PASS"; then
    echo -e "${RED}[ERROR] Пароль не соответствует требованиям.${NC}" >&2
    echo -e "Разрешены: A-Z a-z 0-9 . _ ~ ! @ % ^ + = , ? * - (8-64 символов, без пробелов и кавычек).${NC}" >&2
    exit 1
fi

# Stealth mode (anti-probing / anti-scanner)
if [[ -z "$ARG_STEALTH" ]]; then
    echo -e "\n${BOLD}Режим невидимости (Stealth):${NC}"
    echo -e "  • Сканеры и активные зонды ТСПУ будут видеть ${YELLOW}молча закрытый порт${NC} — без ответов SOCKS5."
    echo -e "  • Подключаться смогут только IP из списка разрешенных."
    echo -e "  • Первое подключение с верным паролем в окне записи добавляет IP автоматически."
    ask_yesno STEALTH_ANSWER "Включить Stealth? (рекомендуется)" "y"
    if [[ "$STEALTH_ANSWER" == "y" ]]; then
        STEALTH_MODE="on"
    else
        STEALTH_MODE="off"
    fi
else
    STEALTH_MODE="$ARG_STEALTH"
fi

ENROLL_MINUTES="${ARG_ENROLL_MIN:-30}"
if ! [[ "$ENROLL_MINUTES" =~ ^[0-9]{1,3}$ ]] || (( ENROLL_MINUTES < 1 )); then
    ENROLL_MINUTES=30
fi

# Validate --allow arguments
VALID_ALLOW=()
for ip in "${ALLOW_ARGS[@]:-}"; do
    [[ -z "$ip" ]] && continue
    if is_ipv4 "$ip"; then
        VALID_ALLOW+=("$ip")
    else
        echo -e "${YELLOW}[!] Пропускаю некорректный IP из --allow: '${ip}'${NC}"
    fi
done

CLAMP_WINDOW=2
QUEUE_NUM=200
BAN_AFTER=6
BAN_TIME=3600

# ------------------------------------------------------------------------------
# Create installation directory
# ------------------------------------------------------------------------------

mkdir -p "$INSTALL_DIR"

# ------------------------------------------------------------------------------
# Download helper (with embedded offline fallbacks)
# ------------------------------------------------------------------------------

download_repo_file() {
    local filename="$1"
    local target="${INSTALL_DIR}/${filename}"

    if [[ -f "./${filename}" ]]; then
        cp "./${filename}" "$target"
        return 0
    fi

    echo -e "  ↳ Загрузка ${filename} с GitHub (${REPO})..."
    if curl -fsSL --retry 3 --max-time 15 "${RAW_URL}/${filename}" -o "$target" 2>/dev/null; then
        return 0
    fi

    # Offline fallback: embedded copies
    case "$filename" in
        socks5-winclamp.c)
            echo -e "${YELLOW}  ↳ Онлайн-загрузка недоступна, создается встроенный исходник...${NC}"
            write_embedded_winclamp "$target" ;;
        socks5-control.sh)
            echo -e "${YELLOW}  ↳ Онлайн-загрузка недоступна, создается встроенная панель...${NC}"
            write_embedded_control "$target" ;;
        uninstall.sh)
            echo -e "${YELLOW}  ↳ Онлайн-загрузка недоступна, создается встроенный деинсталлятор...${NC}"
            write_embedded_uninstall "$target" ;;
        *)
            echo -e "${RED}[ERROR] Не удалось получить ${filename} и нет встроенной копии.${NC}" >&2
            return 1 ;;
    esac
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
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define PKT_BUF_SIZE 65536
#define STRIKE_SLOTS 4096
#define CONN_SLOTS   8192
#define CONN_TTL_SEC 60
#define STRIKE_WINDOW 3600

static volatile bool g_running = true;
static uint16_t g_clamp_window = 2;
static uint16_t g_queue_num = 200;
static bool g_clamp_connect = true;
static char g_enroll_set[64] = "socks5_allow";
static char g_ban_set[64] = "socks5_ban";
static int g_ban_after = 6;
static int g_ban_time = 3600;
static bool g_ipset_ok = false;

static void sig_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) g_running = false;
}

static inline void update_tcp_checksum(uint16_t *csum, uint16_t old_val, uint16_t new_val) {
    uint32_t sum = (~(*csum) & 0xffff) + (~old_val & 0xffff) + (new_val & 0xffff);
    while (sum >> 16) { sum = (sum & 0xffff) + (sum >> 16); }
    uint16_t res = (uint16_t)(~sum);
    *csum = (res == 0) ? 0xffff : res;
}

static uint16_t pick_window(void) {
    if (g_clamp_window <= 1) return 1;
    return (uint16_t)(1 + rand() % g_clamp_window);
}

static bool run_ipset(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) { execvp("ipset", argv); _exit(127); }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void ipset_init(void) {
    bool ok = true;
    char ban_time_s[16];
    snprintf(ban_time_s, sizeof(ban_time_s), "%d", g_ban_time);
    if (g_enroll_set[0] != '\0') {
        char *argv[] = { "ipset", "create", g_enroll_set, "hash:ip",
                         "maxelem", "8192", "-exist", NULL };
        ok = run_ipset(argv) && ok;
    }
    if (g_ban_set[0] != '\0' && g_ban_after > 0) {
        char *argv[] = { "ipset", "create", g_ban_set, "hash:ip",
                         "timeout", ban_time_s, "maxelem", "65536",
                         "-exist", NULL };
        ok = run_ipset(argv) && ok;
    }
    g_ipset_ok = ok;
    if (!ok) fprintf(stderr, "[socks5-winclamp] WARNING: ipset unavailable, TOFU/auto-ban disabled\n");
}

static void ipset_enroll(const char *ip) {
    if (!g_ipset_ok || g_enroll_set[0] == '\0') return;
    char *argv[] = { "ipset", "add", g_enroll_set, (char *)ip, "-exist", NULL };
    if (run_ipset(argv)) { printf("[socks5-winclamp] Enrolled client IP: %s\n", ip); fflush(stdout); }
}

static void ipset_ban(const char *ip) {
    if (!g_ipset_ok || g_ban_set[0] == '\0' || g_ban_after <= 0) return;
    char ban_time_s[16];
    snprintf(ban_time_s, sizeof(ban_time_s), "%d", g_ban_time);
    char *argv[] = { "ipset", "add", g_ban_set, (char *)ip, "timeout", ban_time_s, "-exist", NULL };
    if (run_ipset(argv)) { printf("[socks5-winclamp] Banned IP %s for %d seconds\n", ip, g_ban_time); fflush(stdout); }
}

/* Recently-enrolled IP cache: avoid fork+exec on every reconnect */
#define RECENT_ENROLL_SLOTS 64
static uint32_t g_recent_enroll_ip[RECENT_ENROLL_SLOTS];
static time_t   g_recent_enroll_ts[RECENT_ENROLL_SLOTS];
static uint32_t g_recent_enroll_pos = 0;

static bool enroll_recently_done(uint32_t ip) {
    time_t now = time(NULL);
    for (int i = 0; i < RECENT_ENROLL_SLOTS; i++) {
        if (g_recent_enroll_ip[i] == ip && now - g_recent_enroll_ts[i] < 300) return true;
    }
    return false;
}

static void enroll_mark(uint32_t ip) {
    g_recent_enroll_ip[g_recent_enroll_pos] = ip;
    g_recent_enroll_ts[g_recent_enroll_pos] = time(NULL);
    g_recent_enroll_pos = (g_recent_enroll_pos + 1) % RECENT_ENROLL_SLOTS;
}

struct strike_entry { uint32_t ip; uint32_t count; time_t first; time_t last; };
static struct strike_entry g_strikes[STRIKE_SLOTS];

static uint32_t hash_u32(uint32_t x) { x *= 2654435761u; return x ^ (x >> 16); }

static void ip_to_str(uint32_t ip, char *buf, size_t buflen) {
    struct in_addr a; a.s_addr = htonl(ip);
    inet_ntop(AF_INET, &a, buf, (socklen_t)buflen);
}

static void strike_reset(uint32_t ip) {
    uint32_t idx = hash_u32(ip) & (STRIKE_SLOTS - 1);
    for (int i = 0; i < 4; i++) {
        struct strike_entry *e = &g_strikes[(idx + i) & (STRIKE_SLOTS - 1)];
        if (e->ip == ip) { e->count = 0; return; }
        if (e->ip == 0) return;
    }
}

static void strike_register(uint32_t ip) {
    time_t now = time(NULL);
    uint32_t idx = hash_u32(ip) & (STRIKE_SLOTS - 1);
    struct strike_entry *e = NULL;
    for (int i = 0; i < 4; i++) {
        struct strike_entry *cand = &g_strikes[(idx + i) & (STRIKE_SLOTS - 1)];
        if (cand->ip == ip) { e = cand; break; }
        if (e == NULL && (cand->ip == 0 || now - cand->last > STRIKE_WINDOW)) e = cand;
    }
    if (e == NULL) return;
    if (e->ip != ip) { e->ip = ip; e->count = 0; e->first = now; }
    e->count++;
    e->last = now;
    if (g_ban_after > 0 && e->count >= (uint32_t)g_ban_after && now - e->first <= STRIKE_WINDOW) {
        char ipstr[INET_ADDRSTRLEN];
        ip_to_str(ip, ipstr, sizeof(ipstr));
        ipset_ban(ipstr);
        e->count = 0;
        e->first = now;
    }
}

enum conn_state { CS_UNUSED = 0, CS_NEW, CS_WAIT_AUTH, CS_WAIT_CONNECT };
struct conn_entry { uint8_t state; uint32_t ip; uint16_t cport; time_t ts; };
static struct conn_entry g_conns[CONN_SLOTS];

static struct conn_entry *conn_get(uint32_t ip, uint16_t cport, bool create) {
    time_t now = time(NULL);
    uint32_t base = hash_u32(ip ^ ((uint32_t)cport << 16)) & (CONN_SLOTS - 1);
    struct conn_entry *free_slot = NULL;
    for (int i = 0; i < 16; i++) {
        struct conn_entry *e = &g_conns[(base + i) & (CONN_SLOTS - 1)];
        if (e->state != CS_UNUSED && e->ip == ip && e->cport == cport) {
            if (now - e->ts > CONN_TTL_SEC) { e->state = CS_UNUSED; return NULL; }
            if (create) e->ts = now;
            return e;
        }
        if (e->state == CS_UNUSED || now - e->ts > CONN_TTL_SEC) {
            if (free_slot == NULL) free_slot = e;
        }
    }
    if (create && free_slot != NULL) {
        free_slot->state = CS_NEW;
        free_slot->ip = ip;
        free_slot->cport = cport;
        free_slot->ts = now;
        return free_slot;
    }
    return NULL;
}

static void conn_forget(uint32_t ip, uint16_t cport) {
    struct conn_entry *e = conn_get(ip, cport, false);
    if (e != NULL) e->state = CS_UNUSED;
}

static void conn_observe(uint32_t ip, uint16_t cport, const unsigned char *data, int data_len) {
    if (data_len < 2) return;
    struct conn_entry *e = conn_get(ip, cport, false);
    if (e == NULL || e->state == CS_UNUSED) return;
    uint8_t b0 = data[0], b1 = data[1];
    char ipstr[INET_ADDRSTRLEN];
    if (b0 == 0x05 && b1 == 0x02) {
        e->state = CS_WAIT_AUTH;
    } else if (b0 == 0x01 && b1 == 0x00) {
        if (!enroll_recently_done(ip)) { ip_to_str(ip, ipstr, sizeof(ipstr)); ipset_enroll(ipstr); enroll_mark(ip); }
        strike_reset(ip);
        e->state = CS_WAIT_CONNECT;
    } else if (b0 == 0x01) {
        strike_register(ip);
        e->state = CS_WAIT_CONNECT;
    } else if (b0 == 0x05 && b1 == 0x00) {
        if (!enroll_recently_done(ip)) { ip_to_str(ip, ipstr, sizeof(ipstr)); ipset_enroll(ipstr); enroll_mark(ip); }
        strike_reset(ip);
        e->state = CS_UNUSED;
    } else if (b0 == 0x05 && b1 == 0xff) {
        strike_register(ip);
        e->state = CS_UNUSED;
    } else if (b0 == 0x05) {
        e->state = CS_UNUSED;
    } else {
        e->state = CS_UNUSED;
    }
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
        if (ip_hl >= (int)sizeof(struct iphdr) && len >= ip_hl + (int)sizeof(struct tcphdr)) {
            struct tcphdr *tcph = (struct tcphdr *)(payload + ip_hl);
            int tcp_hl = tcph->doff * 4;
            if (tcp_hl >= (int)sizeof(struct tcphdr) && len >= ip_hl + tcp_hl) {
                unsigned char *tcp_data = payload + ip_hl + tcp_hl;
                int tcp_data_len = len - (ip_hl + tcp_hl);
                uint32_t client_ip = ntohl(iph->daddr);
                uint16_t client_port = ntohs(tcph->dest);

                bool should_clamp = false;
                if (tcph->syn && tcph->ack) {
                    should_clamp = true;
                    if (g_clamp_connect || g_ban_after > 0 || g_enroll_set[0] != '\0') (void)conn_get(client_ip, client_port, true);
                } else if (tcph->fin || tcph->rst) {
                    conn_forget(client_ip, client_port);
                } else if (tcp_data_len >= 2) {
                    if (g_clamp_connect &&
                        ((tcp_data[0] == 0x05 && (tcp_data[1] == 0x00 || tcp_data[1] == 0x02)) ||
                         (tcp_data[0] == 0x01 && tcp_data[1] == 0x00))) {
                        should_clamp = true;
                    }
                    if (g_ban_after > 0 || g_enroll_set[0] != '\0') {
                        conn_observe(client_ip, client_port, tcp_data, tcp_data_len);
                    }
                }

                if (should_clamp) {
                    uint16_t old_win = tcph->window;
                    uint16_t new_win = htons(pick_window());
                    if (old_win != new_win) {
                        tcph->window = new_win;
                        update_tcp_checksum(&tcph->check, old_win, new_win);
                        modified = true;
                    }
                }
            }
        }
    } else if (iph->version == 6) {
        if (len >= (int)(sizeof(struct ip6_hdr) + sizeof(struct tcphdr))) {
            struct ip6_hdr *ip6h = (struct ip6_hdr *)payload;
            if (ip6h->ip6_nxt == IPPROTO_TCP) {
                int ip_hl6 = sizeof(struct ip6_hdr);
                struct tcphdr *tcph = (struct tcphdr *)(payload + ip_hl6);
                int tcp_hl = tcph->doff * 4;
                if (tcp_hl >= (int)sizeof(struct tcphdr) && len >= ip_hl6 + tcp_hl) {
                    unsigned char *tcp_data = payload + ip_hl6 + tcp_hl;
                    int tcp_data_len = len - (ip_hl6 + tcp_hl);
                    bool should_clamp = false;
                    if (tcph->syn && tcph->ack) {
                        should_clamp = true;
                    } else if (tcp_data_len >= 2 && g_clamp_connect &&
                               ((tcp_data[0] == 0x05 && (tcp_data[1] == 0x00 || tcp_data[1] == 0x02)) ||
                                (tcp_data[0] == 0x01 && tcp_data[1] == 0x00))) {
                        should_clamp = true;
                    }
                    if (should_clamp) {
                        uint16_t old_win = tcph->window;
                        uint16_t new_win = htons(pick_window());
                        if (old_win != new_win) {
                            tcph->window = new_win;
                            update_tcp_checksum(&tcph->check, old_win, new_win);
                            modified = true;
                        }
                    }
                }
            }
        }
    }

    if (modified) return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    static struct option long_options[] = {
        { "queue",      required_argument, 0, 'q' },
        { "window",     required_argument, 0, 'w' },
        { "syn-only",   no_argument,       0, 's' },
        { "enroll-set", required_argument, 0, 'E' },
        { "ban-set",    required_argument, 0, 'D' },
        { "ban-after",  required_argument, 0, 'n' },
        { "ban-time",   required_argument, 0, 't' },
        { "verbose",    no_argument,       0, 'v' },
        { "help",       no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "q:w:sE:D:n:t:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'q': g_queue_num = (uint16_t)atoi(optarg); break;
            case 'w': g_clamp_window = (uint16_t)atoi(optarg); break;
            case 's': g_clamp_connect = false; break;
            case 'E': snprintf(g_enroll_set, sizeof(g_enroll_set), "%s", optarg); break;
            case 'D': snprintf(g_ban_set, sizeof(g_ban_set), "%s", optarg); break;
            case 'n': g_ban_after = atoi(optarg); if (g_ban_after < 0) g_ban_after = 0; break;
            case 't': g_ban_time = atoi(optarg); if (g_ban_time < 1) g_ban_time = 1; break;
            default: break;
        }
    }
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    ipset_init();

    struct nfq_handle *h = nfq_open();
    if (!h) return 1;
    nfq_bind_pf(h, AF_INET);
    struct nfq_q_handle *qh = nfq_create_queue(h, g_queue_num, &packet_callback, NULL);
    if (!qh) return 1;
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    int fd = nfq_fd(h);
    static unsigned char pkt_buf[PKT_BUF_SIZE] __attribute__((aligned(8)));
    while (g_running) {
        int rv = recv(fd, pkt_buf, sizeof(pkt_buf), 0);
        if (rv > 0) nfq_handle_packet(h, (char *)pkt_buf, rv);
        else if (rv < 0) { if (errno == EINTR) continue; if (!g_running) break; usleep(1000); }
    }
    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
EOF_C
    chmod 644 "$target"
}

write_embedded_control() {
    local target="$1"
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
EOF_UNINSTALL
    chmod 755 "$target"
}

# ------------------------------------------------------------------------------
# [1/7] Packages
# ------------------------------------------------------------------------------

echo -e "\n${BLUE}[1/7] Установка системных пакетов и зависимостей...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    build-essential \
    libnetfilter-queue-dev \
    dante-server \
    iptables \
    iptables-persistent \
    netfilter-persistent \
    ipset \
    curl \
    ethtool \
    ca-certificates \
    qrencode

# ------------------------------------------------------------------------------
# [2/7] Build & install the bypass daemon
# ------------------------------------------------------------------------------

echo -e "${BLUE}[2/7] Загрузка и компиляция ядра обхода (socks5-winclamp)...${NC}"
download_repo_file "socks5-winclamp.c"
download_repo_file "socks5-control.sh"
download_repo_file "uninstall.sh"

gcc -O2 -Wall -Wextra "${INSTALL_DIR}/socks5-winclamp.c" -lnetfilter_queue -o /usr/local/bin/socks5-winclamp
chmod 755 /usr/local/bin/socks5-winclamp
install -m 755 "${INSTALL_DIR}/socks5-control.sh" /usr/local/bin/socks5-control

# ------------------------------------------------------------------------------
# [3/7] Dante configuration
# ------------------------------------------------------------------------------

echo -e "${BLUE}[3/7] Конфигурация SOCKS5 (Dante)...${NC}"
SOCKS_USER_CREATED=0
if ! id "$SOCKS_USER" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -M "$SOCKS_USER"
    SOCKS_USER_CREATED=1
fi
echo "${SOCKS_USER}:${SOCKS_PASS}" | chpasswd

if [[ -f /etc/danted.conf && ! -f /etc/danted.conf.socks5-backup ]]; then
    cp -p /etc/danted.conf /etc/danted.conf.socks5-backup
fi

cat > /etc/danted.conf <<EOF_DANTED
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
EOF_DANTED

# ------------------------------------------------------------------------------
# [4/7] systemd units (winclamp, NIC tuning, ipset restore)
# ------------------------------------------------------------------------------

echo -e "${BLUE}[4/7] Настройка служб systemd..."
cat > /etc/systemd/system/socks5-winclamp.service <<EOF_UNIT
[Unit]
Description=SOCKS5 Anti-DPI TCP Window Clamper
After=network.target danted.service
Wants=danted.service

[Service]
Type=simple
ExecStart=/usr/local/bin/socks5-winclamp -q ${QUEUE_NUM} -w ${CLAMP_WINDOW} -E socks5_allow -D socks5_ban -n ${BAN_AFTER} -t ${BAN_TIME}
Restart=always
RestartSec=2
KillMode=process
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF_UNIT

cat > /usr/local/bin/socks5-nic-tuning <<'EOF_NIC'
#!/usr/bin/env bash
# Disable TSO/GSO/GRO on every boot so NFQUEUE always sees real-size segments
set -u
for IF in $(ip -o -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1)}}' | sort -u); do
    ethtool -K "$IF" tso off gso off gro off 2>/dev/null || true
done
exit 0
EOF_NIC
chmod 755 /usr/local/bin/socks5-nic-tuning

cat > /etc/systemd/system/socks5-nic-tuning.service <<'EOF_NICUNIT'
[Unit]
Description=Disable TSO/GSO/GRO for the SOCKS5 Anti-DPI suite
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/socks5-nic-tuning

[Install]
WantedBy=multi-user.target
EOF_NICUNIT

cat > /usr/local/bin/socks5-ipset-restore <<EOF_IPSET
#!/usr/bin/env bash
# Restore SOCKS5 Anti-DPI ipsets before netfilter-persistent applies the rules
ipset create socks5_allow hash:ip maxelem 8192 -exist 2>/dev/null || true
ipset create socks5_ban hash:ip timeout ${BAN_TIME} maxelem 65536 -exist 2>/dev/null || true
ipset create socks5_enroll hash:net timeout 86400 maxelem 1024 -exist 2>/dev/null || true
if [[ -f "${INSTALL_DIR}/ipset.save" ]]; then
    ipset restore -exist -f "${INSTALL_DIR}/ipset.save" 2>/dev/null || true
fi
exit 0
EOF_IPSET
chmod 755 /usr/local/bin/socks5-ipset-restore

cat > /etc/systemd/system/socks5-ipset-restore.service <<'EOF_IUNIT'
[Unit]
Description=Restore SOCKS5 Anti-DPI ipsets before firewall rules
Before=netfilter-persistent.service
After=systemd-modules-load.service
DefaultDependencies=no
Wants=systemd-modules-load.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/socks5-ipset-restore

[Install]
WantedBy=multi-user.target
EOF_IUNIT

cat > /etc/logrotate.d/socks5-danted <<'EOF_LOGR'
/var/log/danted.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF_LOGR

systemctl daemon-reload
systemctl enable socks5-winclamp danted socks5-nic-tuning.service socks5-ipset-restore.service
systemctl restart socks5-winclamp danted

# ------------------------------------------------------------------------------
# [5/7] iptables: NFQUEUE, stealth chain, ipsets, port mirroring
# ------------------------------------------------------------------------------

echo -e "${BLUE}[5/7] Применение сетевых правил (iptables / Multiport / Stealth)...${NC}"

del_rule() {
    for _ in 1 2 3; do
        "$@" 2>/dev/null || break
    done
}

is_port_in_use() {
    local port="$1"
    # 1. Listening socket via ss
    if ss -tlnH 2>/dev/null | grep -qE "(:|\])${port}\s"; then
        return 0
    fi
    # 2. Listening socket via lsof
    if command -v lsof &>/dev/null && lsof -iTCP:"${port}" -sTCP:LISTEN &>/dev/null; then
        return 0
    fi
    # 3. Docker container port mappings (bridge / host)
    if command -v docker &>/dev/null && docker ps --format '{{.Ports}}' 2>/dev/null | grep -qE "(:|->)${port}/"; then
        return 0
    fi
    # 4. iptables NAT table rules (captures Docker DNAT even when userland-proxy is disabled)
    if iptables -t nat -S 2>/dev/null | grep -v "REDIRECT --to-ports ${SOCKS_PORT}" | grep -qE -- "--dport\s+${port}\b"; then
        return 0
    fi
    return 1
}

# --- Cleanup of previous / legacy rules ---
for P in "$PREV_PORT" "$SOCKS_PORT"; do
    [[ -n "$P" ]] || continue
    for Q in "$PREV_QUEUE" "$QUEUE_NUM"; do
        [[ -n "$Q" ]] || continue
        del_rule iptables -t mangle -D OUTPUT -p tcp --sport "$P" -j NFQUEUE --queue-num "$Q" --queue-bypass
        del_rule iptables -t mangle -D OUTPUT -p tcp --sport "$P" -j NFQUEUE --queue-num "$Q"
    done
    del_rule iptables -D INPUT -p tcp --dport "$P" -j SOCKS5-FW
    del_rule iptables -D INPUT -p tcp --dport "$P" -j ACCEPT
    del_rule iptables -D INPUT -p tcp --dport "$P" --syn -m hashlimit --hashlimit-name s5_syn --hashlimit 25/sec --hashlimit-burst 50 --hashlimit-mode srcip -j ACCEPT
done

if [[ -n "$PREV_MIRRORS" ]]; then
    if [[ -n "$PREV_IF" ]]; then
        del_rule iptables -t nat -D PREROUTING -i "$PREV_IF" -p tcp -m multiport --dports "$PREV_MIRRORS" -j REDIRECT --to-ports "${PREV_PORT:-$SOCKS_PORT}"
    fi
    del_rule iptables -t nat -D PREROUTING -p tcp -m multiport --dports "$PREV_MIRRORS" -j REDIRECT --to-ports "${PREV_PORT:-$SOCKS_PORT}"
    del_rule iptables -D INPUT -p tcp -m multiport --dports "$PREV_MIRRORS" -j ACCEPT
fi

# --- ipsets for stealth / auto-ban ---
ipset create socks5_allow hash:ip maxelem 8192 -exist
ipset create socks5_ban hash:ip timeout "${BAN_TIME}" maxelem 65536 -exist
ipset create socks5_enroll hash:net timeout 86400 maxelem 1024 -exist

for ip in "${VALID_ALLOW[@]:-}"; do
    [[ -z "$ip" ]] && continue
    ipset add socks5_allow "$ip" -exist
    echo -e "    ${GREEN}[+] IP ${ip} добавлен в список разрешенных${NC}"
done

# --- Stealth firewall chain ---
# ORDER MATTERS: 1) banned IPs are silently dropped
#                2) loopback (local curl/ss checks) is always allowed
#                3) SYN flood limiter (real one: over-limit SYNs hit DROP)
#                4) stealth => only allowed/enrolled IPs pass, everyone else is dropped
iptables -N SOCKS5-FW 2>/dev/null || iptables -F SOCKS5-FW
iptables -A SOCKS5-FW -m set --match-set socks5_ban src -j DROP
iptables -A SOCKS5-FW -i lo -j ACCEPT
iptables -A SOCKS5-FW -p tcp --syn -m hashlimit \
    --hashlimit-name s5_syn --hashlimit 25/sec --hashlimit-burst 50 \
    --hashlimit-mode srcip -j ACCEPT
iptables -A SOCKS5-FW -p tcp --syn -j DROP
if [[ "$STEALTH_MODE" == "on" ]]; then
    iptables -A SOCKS5-FW -m set --match-set socks5_allow src -j ACCEPT
    iptables -A SOCKS5-FW -m set --match-set socks5_enroll src -j ACCEPT
    iptables -A SOCKS5-FW -j DROP
else
    iptables -A SOCKS5-FW -j ACCEPT
fi
if ! iptables -C INPUT -p tcp --dport "$SOCKS_PORT" -j SOCKS5-FW 2>/dev/null; then
    iptables -I INPUT 1 -p tcp --dport "$SOCKS_PORT" -j SOCKS5-FW
fi

# --- NFQUEUE for the window clamper (--queue-bypass keeps traffic flowing
#     even if the daemon is briefly restarting) ---
iptables -t mangle -I OUTPUT -p tcp --sport "$SOCKS_PORT" -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass

# --- Port mirroring (Ultra mode) ---
MULTIPORT_LIST=""
if [[ "$BYPASS_MODE" == "1" ]]; then
    if [[ -n "$ARG_MIRRORS" ]]; then
        IFS=',' read -ra USER_CANDIDATES <<< "$ARG_MIRRORS"
        MIRROR_CANDIDATES=("${USER_CANDIDATES[@]}")
    else
        MIRROR_CANDIDATES=(443 8443 2083 53)
    fi

    VALID_MIRRORS=()
    for p in "${MIRROR_CANDIDATES[@]}"; do
        p=$(echo "$p" | tr -d ' ')
        [[ -z "$p" ]] && continue
        if ! valid_port "$p"; then
            echo -e "    ${YELLOW}[!] Некорректный порт зеркала '${p}', пропускаем.${NC}"
            continue
        fi
        [[ "$p" == "$SOCKS_PORT" ]] && continue
        if is_port_in_use "$p"; then
            echo -e "    ${YELLOW}[!] Порт ${p} занят другой службой (процесс/Docker/iptables), пропускаем.${NC}"
        else
            VALID_MIRRORS+=("$p")
        fi
    done

    if [[ ${#VALID_MIRRORS[@]} -gt 0 ]]; then
        MIRROR_PORTS=$(IFS=,; echo "${VALID_MIRRORS[*]}")
        MULTIPORT_LIST="$MIRROR_PORTS"

        del_rule iptables -t nat -D PREROUTING -i "$DEFAULT_IF" -p tcp -m multiport --dports "$MIRROR_PORTS" -j REDIRECT --to-ports "$SOCKS_PORT"
        del_rule iptables -t nat -D PREROUTING -p tcp -m multiport --dports "$MIRROR_PORTS" -j REDIRECT --to-ports "$SOCKS_PORT"

        iptables -t nat -A PREROUTING -i "$DEFAULT_IF" -p tcp -m multiport --dports "$MIRROR_PORTS" -j REDIRECT --to-ports "$SOCKS_PORT"
        echo -e "    ${GREEN}[+] Включено мультипортовое зеркалирование: ${MIRROR_PORTS}${NC}"
    else
        echo -e "    ${YELLOW}[!] Все порты-кандидаты зеркалирования заняты, работаем только на основном порту ${SOCKS_PORT}.${NC}"
    fi
fi

# --- Persist rules and ipsets ---
netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
mkdir -p "$INSTALL_DIR"
ipset save socks5_allow socks5_ban socks5_enroll > "$INSTALL_DIR/ipset.save" 2>/dev/null || true

# --- Disable segmentation offloads now (plus at every boot via the unit) ---
ethtool -K "$DEFAULT_IF" tso off gso off gro off 2>/dev/null || true

# ------------------------------------------------------------------------------
# [6/7] sysctl tuning
# ------------------------------------------------------------------------------

echo -e "${BLUE}[6/7] Оптимизация TCP BBR...${NC}"
cat > /etc/sysctl.d/99-socks5-antidpi.conf <<EOF_SYSCTL
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF_SYSCTL
sysctl -p /etc/sysctl.d/99-socks5-antidpi.conf &>/dev/null || true

# ------------------------------------------------------------------------------
# [7/7] Save metadata + open enrollment window
# ------------------------------------------------------------------------------

echo -e "${BLUE}[7/7] Сохранение конфигурации и окно записи клиентов...${NC}"
cat > "$CONFIG_FILE" <<EOF_CONF
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
SOCKS_USER_CREATED='${SOCKS_USER_CREATED}'
INSTALL_DATE='$(date -u +"%Y-%m-%dT%H:%M:%SZ")'
EOF_CONF
chmod 600 "$CONFIG_FILE"

if [[ "$STEALTH_MODE" == "on" ]]; then
    ipset add socks5_enroll 0.0.0.0/0 timeout "$((ENROLL_MINUTES * 60))" -exist
    ipset save socks5_allow socks5_ban socks5_enroll > "$INSTALL_DIR/ipset.save" 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------

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
    FIRST_MIRROR=$(echo "$MULTIPORT_LIST" | cut -d',' -f1)
    echo -e "  • Telegram резервный порт ${FIRST_MIRROR} (маскировка):"
    echo -e "    ${YELLOW}tg://socks?server=${SERVER_IP}&port=${FIRST_MIRROR}&user=${SOCKS_USER}&pass=${SOCKS_PASS}${NC}"
fi

echo -e "\n${BOLD}Быстрая проверка из терминала на клиенте:${NC}"
echo -e "  ${CYAN}curl -x socks5h://${SOCKS_USER}:${SOCKS_PASS}@${SERVER_IP}:${SOCKS_PORT} https://api.ipify.org${NC}"

if [[ "$STEALTH_MODE" == "on" ]]; then
    LOCAL_CLIENT_IP=$(echo "${SSH_CLIENT:-}" | awk '{print $1}')
    echo -e "\n${YELLOW}${BOLD}=== РЕЖИМ НЕВИДИМОСТИ (STEALTH) ВКЛЮЧЕН ===${NC}"
    echo -e "  • Сканеры и активные зонды ТСПУ видят ${BOLD}молча закрытый порт${NC} — без ответов SOCKS5."
    echo -e "  • Подключаться смогут только IP из списка разрешенных."
    echo -e "  • ${GREEN}Окно записи открыто на ${ENROLL_MINUTES} мин!${NC}"
    echo -e "    Подключите нужные устройства (Telegram/браузер) к прокси с верным"
    echo -e "    паролем в течение ${ENROLL_MINUTES} минут — их IP запомнятся автоматически."
    echo -e "  • Ваш текущий SSH IP: ${CYAN}${LOCAL_CLIENT_IP:-не определен}${NC}"
    echo -e "    Уже разрешенные IP: ${CYAN}socks5-control list${NC}"
    echo -e "  • Не успели/новое устройство: ${CYAN}socks5-control enroll 30${NC}"
    echo -e "  • Добавить IP вручную:        ${CYAN}socks5-control allow <IP>${NC}"
    echo -e "  • Отключить невидимость:      ${CYAN}socks5-control stealth off${NC}"
else
    echo -e "\n${YELLOW}[i] Stealth выключен: сервер отвечает всем IP. Включить: ${CYAN}socks5-control stealth on && socks5-control enroll${NC}"
fi

echo -e "\n${BOLD}Команды управления:${NC}"
echo -e "  • Статус:   ${CYAN}socks5-control status${NC}"
echo -e "  • Логи:     ${CYAN}socks5-control logs${NC}"
echo -e "  • Инфо:     ${CYAN}socks5-control info${NC}\n"
