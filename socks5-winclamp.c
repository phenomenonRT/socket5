/*
 * socks5-winclamp.c — SOCKS5 Server-Side TCP Window Clamper & Anti-DPI Daemon
 *
 * Part of SOCKS5 Anti-DPI Suite by phenomenonRT
 * GitHub: https://github.com/phenomenonRT/socket5
 *
 * Features:
 *   1. Clamps outbound SYN-ACK TCP window (random 1..N bytes) to force the
 *      client OS (Windows, iOS, Android, Linux, macOS) to split the SOCKS5
 *      Greeting (\x05\x01\x00) into several TCP segments.
 *   2. Clamps the server SOCKS5 method/auth responses so the client OS also
 *      splits the Connect request (\x05\x01\x00\x03...).
 *   3. Trust-On-First-Auth (TOFU): as soon as a client completes
 *      username/password authentication, its source IP is added to an ipset
 *      allow set (default: socks5_allow). This lets the stealth firewall mode
 *      silently DROP all unknown / scanner / DPI-probe IPs.
 *   4. Fail2ban-lite: several failed SOCKS5 handshakes from one IP put that
 *      IP into an ipset ban set (default: socks5_ban) for a configurable
 *      time. Real clients are immune because only wrong handshakes count.
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra socks5-winclamp.c -lnetfilter_queue -o socks5-winclamp
 */

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

#define PKT_BUF_SIZE     65536
#define STRIKE_SLOTS     4096
#define CONN_SLOTS       8192
#define CONN_TTL_SEC     60
#define STRIKE_WINDOW    3600

static volatile bool g_running = true;
static uint16_t g_clamp_window = 2;   /* max clamped window, randomized 1..N */
static uint16_t g_queue_num = 200;
static bool g_clamp_connect = true;   /* clamp method/auth responses too */
static bool g_verbose = false;

static char g_enroll_set[64] = "socks5_allow";
static char g_ban_set[64] = "socks5_ban";
static int g_ban_after = 6;           /* failed handshakes before ban, 0 = off */
static int g_ban_time = 3600;         /* ban duration, seconds */
static bool g_ipset_ok = false;

static uint64_t g_clamped_synack = 0;
static uint64_t g_clamped_response = 0;
static uint64_t g_total_packets = 0;
static uint64_t g_enrolled = 0;
static uint64_t g_banned = 0;

/* ------------------------------------------------------------------ */
/* Signal handling                                                     */
/* ------------------------------------------------------------------ */

static void sig_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        g_running = false;
    } else if (signo == SIGUSR1) {
        fprintf(stderr,
                "\n[socks5-winclamp] Stats: Total=%llu, SYN-ACKs clamped=%llu, "
                "Responses clamped=%llu, Enrolled=%llu, Banned=%llu\n",
                (unsigned long long)g_total_packets,
                (unsigned long long)g_clamped_synack,
                (unsigned long long)g_clamped_response,
                (unsigned long long)g_enrolled,
                (unsigned long long)g_banned);
    }
}

/* ------------------------------------------------------------------ */
/* RFC 1624 incremental 16-bit one's complement checksum update:       */
/*   HC' = ~(~HC + ~m + m')                                            */
/* ------------------------------------------------------------------ */

static inline void update_tcp_checksum(uint16_t *csum, uint16_t old_val, uint16_t new_val) {
    uint32_t sum = (~(*csum) & 0xffff) + (~old_val & 0xffff) + (new_val & 0xffff);
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    uint16_t res = (uint16_t)(~sum);
    *csum = (res == 0) ? 0xffff : res;
}

static uint16_t pick_window(void) {
    if (g_clamp_window <= 1) {
        return 1;
    }
    return (uint16_t)(1 + rand() % g_clamp_window);
}

/* ------------------------------------------------------------------ */
/* ipset helpers (TOFU enrollment + auto-ban)                          */
/* ------------------------------------------------------------------ */

static bool run_ipset(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) {
        return false;
    }
    if (pid == 0) {
        execvp("ipset", argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return false;
    }
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
    if (!ok) {
        fprintf(stderr,
                "[socks5-winclamp] WARNING: ipset is unavailable — "
                "TOFU enrollment and auto-ban are disabled\n");
    }
}

static void ipset_enroll(const char *ip) {
    if (!g_ipset_ok || g_enroll_set[0] == '\0') {
        return;
    }
    char *argv[] = { "ipset", "add", g_enroll_set, (char *)ip, "-exist", NULL };
    if (run_ipset(argv)) {
        g_enrolled++;
        printf("[socks5-winclamp] Enrolled client IP: %s\n", ip);
        fflush(stdout);
    }
}

static void ipset_ban(const char *ip) {
    if (!g_ipset_ok || g_ban_set[0] == '\0' || g_ban_after <= 0) {
        return;
    }
    char ban_time_s[16];
    snprintf(ban_time_s, sizeof(ban_time_s), "%d", g_ban_time);
    char *argv[] = { "ipset", "add", g_ban_set, (char *)ip,
                     "timeout", ban_time_s, "-exist", NULL };
    if (run_ipset(argv)) {
        g_banned++;
        printf("[socks5-winclamp] Banned IP %s for %d seconds (failed handshakes)\n",
               ip, g_ban_time);
        fflush(stdout);
    }
}

/* ------------------------------------------------------------------ */
/* Recently-enrolled IP cache: ipset add is idempotent, so skip the    */
/* fork+exec for clients that reconnect often (Telegram, browsers).    */
/* ------------------------------------------------------------------ */

#define RECENT_ENROLL_SLOTS 64
#define RECENT_ENROLL_TTL   300

static uint32_t g_recent_enroll_ip[RECENT_ENROLL_SLOTS];
static time_t   g_recent_enroll_ts[RECENT_ENROLL_SLOTS];
static uint32_t g_recent_enroll_pos = 0;

static bool enroll_recently_done(uint32_t ip) {
    time_t now = time(NULL);
    for (int i = 0; i < RECENT_ENROLL_SLOTS; i++) {
        if (g_recent_enroll_ip[i] == ip &&
            now - g_recent_enroll_ts[i] < RECENT_ENROLL_TTL) {
            return true;
        }
    }
    return false;
}

static void enroll_mark(uint32_t ip) {
    g_recent_enroll_ip[g_recent_enroll_pos] = ip;
    g_recent_enroll_ts[g_recent_enroll_pos] = time(NULL);
    g_recent_enroll_pos = (g_recent_enroll_pos + 1) % RECENT_ENROLL_SLOTS;
}

/* ------------------------------------------------------------------ */
/* Failed-handshake counter (fail2ban-lite)                            */
/* ------------------------------------------------------------------ */

struct strike_entry {
    uint32_t ip;      /* host order IPv4 address, 0 = unused */
    uint32_t count;
    time_t   first;
    time_t   last;
};

static struct strike_entry g_strikes[STRIKE_SLOTS];

static uint32_t hash_u32(uint32_t x) {
    x *= 2654435761u;
    return x ^ (x >> 16);
}

static void ip_to_str(uint32_t ip, char *buf, size_t buflen) {
    struct in_addr a;
    a.s_addr = htonl(ip);
    inet_ntop(AF_INET, &a, buf, (socklen_t)buflen);
}

static void strike_reset(uint32_t ip) {
    uint32_t idx = hash_u32(ip) & (STRIKE_SLOTS - 1);
    for (int i = 0; i < 4; i++) {
        struct strike_entry *e = &g_strikes[(idx + i) & (STRIKE_SLOTS - 1)];
        if (e->ip == ip) {
            e->count = 0;
            return;
        }
        if (e->ip == 0) {
            return;
        }
    }
}

static void strike_register(uint32_t ip) {
    time_t now = time(NULL);
    uint32_t idx = hash_u32(ip) & (STRIKE_SLOTS - 1);
    struct strike_entry *e = NULL;

    for (int i = 0; i < 4; i++) {
        struct strike_entry *cand = &g_strikes[(idx + i) & (STRIKE_SLOTS - 1)];
        if (cand->ip == ip) {
            e = cand;
            break;
        }
        if (e == NULL && (cand->ip == 0 || now - cand->last > STRIKE_WINDOW)) {
            e = cand;
        }
    }
    if (e == NULL) {
        return;   /* table is hot; skip counting rather than evict a live entry */
    }
    if (e->ip != ip) {
        e->ip = ip;
        e->count = 0;
        e->first = now;
    }
    e->count++;
    e->last = now;

    if (g_ban_after > 0 && e->count >= (uint32_t)g_ban_after &&
        now - e->first <= STRIKE_WINDOW) {
        char ipstr[INET_ADDRSTRLEN];
        ip_to_str(ip, ipstr, sizeof(ipstr));
        ipset_ban(ipstr);
        e->count = 0;
        e->first = now;
    }
}

/* ------------------------------------------------------------------ */
/* Per-connection SOCKS5 handshake tracker                             */
/*                                                                     */
/* Entries are created when an outbound SYN-ACK is seen, so sessions   */
/* that predate the daemon start are never misclassified as failed     */
/* handshakes (relayed payload may start with any byte pattern).       */
/* Only the server->client direction passes through this queue.        */
/* ------------------------------------------------------------------ */

enum conn_state {
    CS_UNUSED = 0,
    CS_NEW,             /* after SYN-ACK: waiting for method selection   */
    CS_WAIT_AUTH,       /* got \x05\x02: waiting for RFC1929 reply       */
    CS_WAIT_CONNECT     /* auth done: waiting for connect reply          */
};

struct conn_entry {
    uint8_t  state;
    uint32_t ip;     /* client IPv4, host order */
    uint16_t cport;  /* client port */
    time_t   ts;
};

static struct conn_entry g_conns[CONN_SLOTS];

static struct conn_entry *conn_get(uint32_t ip, uint16_t cport, bool create) {
    time_t now = time(NULL);
    uint32_t base = hash_u32(ip ^ ((uint32_t)cport << 16)) & (CONN_SLOTS - 1);
    struct conn_entry *free_slot = NULL;

    for (int i = 0; i < 16; i++) {
        struct conn_entry *e = &g_conns[(base + i) & (CONN_SLOTS - 1)];
        if (e->state != CS_UNUSED && e->ip == ip && e->cport == cport) {
            if (now - e->ts > CONN_TTL_SEC) {
                e->state = CS_UNUSED;
                return NULL;
            }
            if (create) {
                e->ts = now;
            }
            return e;
        }
        if (e->state == CS_UNUSED || now - e->ts > CONN_TTL_SEC) {
            if (free_slot == NULL) {
                free_slot = e;
            }
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
    if (e != NULL) {
        e->state = CS_UNUSED;
    }
}

/*
 * Called for every server->client payload while the connection is still in
 * a handshake state. Once the connect reply is seen the entry is removed and
 * relayed application data is never inspected again.
 */
static void conn_observe(uint32_t ip, uint16_t cport,
                         const unsigned char *data, int data_len) {
    if (data_len < 2) {
        return;
    }
    struct conn_entry *e = conn_get(ip, cport, false);
    if (e == NULL || e->state == CS_UNUSED) {
        return;
    }

    uint8_t b0 = data[0];
    uint8_t b1 = data[1];
    char ipstr[INET_ADDRSTRLEN];

    if (b0 == 0x05 && b1 == 0x02) {
        /* method selection: username/password required */
        e->state = CS_WAIT_AUTH;
    } else if (b0 == 0x01 && b1 == 0x00) {
        /* RFC1929 auth success -> TOFU enroll */
        if (!enroll_recently_done(ip)) {
            ip_to_str(ip, ipstr, sizeof(ipstr));
            ipset_enroll(ipstr);
            enroll_mark(ip);
        }
        strike_reset(ip);
        e->state = CS_WAIT_CONNECT;
    } else if (b0 == 0x01) {
        /* RFC1929 auth failure -> strike */
        strike_register(ip);
        e->state = CS_WAIT_CONNECT;
    } else if (b0 == 0x05 && b1 == 0x00) {
        /* connect reply success (also proves auth in username mode) */
        if (!enroll_recently_done(ip)) {
            ip_to_str(ip, ipstr, sizeof(ipstr));
            ipset_enroll(ipstr);
            enroll_mark(ip);
        }
        strike_reset(ip);
        e->state = CS_UNUSED;
    } else if (b0 == 0x05 && b1 == 0xff) {
        /* no acceptable methods -> probe or misconfigured client */
        strike_register(ip);
        e->state = CS_UNUSED;
    } else if (b0 == 0x05) {
        /* connect reply with error code */
        e->state = CS_UNUSED;
    } else {
        /* not SOCKS handshake traffic */
        e->state = CS_UNUSED;
    }
}

/* ------------------------------------------------------------------ */
/* Packet callback                                                     */
/* ------------------------------------------------------------------ */

static void clamp_tcp_window(struct tcphdr *tcph, const char *reason,
                             bool *modified, uint64_t *counter,
                             const char *peer_ip, uint16_t peer_port) {
    uint16_t old_win = tcph->window;
    uint16_t new_win = htons(pick_window());
    if (old_win == new_win) {
        return;
    }
    tcph->window = new_win;
    update_tcp_checksum(&tcph->check, old_win, new_win);
    *modified = true;
    (*counter)++;
    if (g_verbose) {
        printf("[%s] %s:%u | window: %u -> %u\n",
               reason, peer_ip, peer_port, ntohs(old_win), ntohs(new_win));
    }
}

static int packet_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                           struct nfq_data *nfa, void *data) {
    (void)nfmsg;
    (void)data;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        return 0;
    }
    uint32_t id = ntohl(ph->packet_id);

    unsigned char *payload = NULL;
    int len = nfq_get_payload(nfa, &payload);
    if (len < 0 || !payload) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    g_total_packets++;
    bool modified = false;

    /* --- IPv4 --- */
    struct iphdr *iph = (struct iphdr *)payload;
    if (iph->version == 4 && iph->protocol == IPPROTO_TCP) {
        int ip_hl = iph->ihl * 4;
        if (ip_hl >= (int)sizeof(struct iphdr) &&
            len >= ip_hl + (int)sizeof(struct tcphdr)) {
            struct tcphdr *tcph = (struct tcphdr *)(payload + ip_hl);
            int tcp_hl = tcph->doff * 4;
            if (tcp_hl >= (int)sizeof(struct tcphdr) && len >= ip_hl + tcp_hl) {
                unsigned char *tcp_data = payload + ip_hl + tcp_hl;
                int tcp_data_len = len - (ip_hl + tcp_hl);

                uint32_t client_ip = ntohl(iph->daddr);
                uint16_t client_port = ntohs(tcph->dest);
                char peer[INET_ADDRSTRLEN];

                if (tcph->syn && tcph->ack) {
                    /* new inbound connection: start handshake tracking */
                    if (g_clamp_connect || g_ban_after > 0 ||
                        g_enroll_set[0] != '\0') {
                        (void)conn_get(client_ip, client_port, true);
                    }
                    inet_ntop(AF_INET, &(iph->daddr), peer, sizeof(peer));
                    clamp_tcp_window(tcph, "SYN-ACK", &modified,
                                     &g_clamped_synack, peer, client_port);
                } else if (tcph->fin || tcph->rst) {
                    conn_forget(client_ip, client_port);
                } else if (tcp_data_len >= 2) {
                    if (g_clamp_connect &&
                        ((tcp_data[0] == 0x05 &&
                          (tcp_data[1] == 0x00 || tcp_data[1] == 0x02)) ||
                         (tcp_data[0] == 0x01 && tcp_data[1] == 0x00))) {
                        inet_ntop(AF_INET, &(iph->daddr), peer, sizeof(peer));
                        clamp_tcp_window(tcph, "SOCKS5 response", &modified,
                                         &g_clamped_response, peer, client_port);
                    }
                    if (g_ban_after > 0 || g_enroll_set[0] != '\0') {
                        conn_observe(client_ip, client_port, tcp_data, tcp_data_len);
                    }
                }
            }
        }
    }
    /* --- IPv6 (clamping only, ipset sets are IPv4) --- */
    else if (iph->version == 6) {
        if (len >= (int)(sizeof(struct ip6_hdr) + sizeof(struct tcphdr))) {
            struct ip6_hdr *ip6h = (struct ip6_hdr *)payload;
            if (ip6h->ip6_nxt == IPPROTO_TCP) {
                int ip_hl6 = sizeof(struct ip6_hdr);
                struct tcphdr *tcph = (struct tcphdr *)(payload + ip_hl6);
                int tcp_hl = tcph->doff * 4;
                if (tcp_hl >= (int)sizeof(struct tcphdr) &&
                    len >= ip_hl6 + tcp_hl) {
                    unsigned char *tcp_data = payload + ip_hl6 + tcp_hl;
                    int tcp_data_len = len - (ip_hl6 + tcp_hl);
                    char peer[INET6_ADDRSTRLEN];

                    if (tcph->syn && tcph->ack) {
                        inet_ntop(AF_INET6, &(ip6h->ip6_dst), peer, sizeof(peer));
                        clamp_tcp_window(tcph, "SYN-ACK", &modified,
                                         &g_clamped_synack, peer, ntohs(tcph->dest));
                    } else if (tcp_data_len >= 2 && g_clamp_connect &&
                               ((tcp_data[0] == 0x05 &&
                                 (tcp_data[1] == 0x00 || tcp_data[1] == 0x02)) ||
                                (tcp_data[0] == 0x01 && tcp_data[1] == 0x00))) {
                        inet_ntop(AF_INET6, &(ip6h->ip6_dst), peer, sizeof(peer));
                        clamp_tcp_window(tcph, "SOCKS5 response", &modified,
                                         &g_clamped_response, peer, ntohs(tcph->dest));
                    }
                }
            }
        }
    }

    if (modified) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */

static void print_help(const char *progname) {
    printf("SOCKS5 Server-Side TCP Window Clamper (Anti-DPI Suite)\n");
    printf("Author: phenomenonRT (https://github.com/phenomenonRT/socket5)\n\n");
    printf("Usage: %s [OPTIONS]\n\n", progname);
    printf("Options:\n");
    printf("  -q, --queue <num>      NFQUEUE number to bind (default: 200)\n");
    printf("  -w, --window <bytes>   Max clamped TCP window (default: 2). The\n");
    printf("                         actual value is randomized 1..N per packet.\n");
    printf("                         Values > 2 may break the greeting split!\n");
    printf("  -s, --syn-only         Clamp only SYN-ACK (no method/auth reply\n");
    printf("                         clamping, no handshake tracking)\n");
    printf("  -E, --enroll-set <n>   ipset name for TOFU-enrolled clients\n");
    printf("                         (default: socks5_allow, empty to disable)\n");
    printf("  -D, --ban-set <n>      ipset name for banned probers\n");
    printf("                         (default: socks5_ban)\n");
    printf("  -n, --ban-after <num>  Failed handshakes before an IP is banned\n");
    printf("                         (default: 6, 0 disables auto-ban)\n");
    printf("  -t, --ban-time <sec>   Ban duration in seconds (default: 3600)\n");
    printf("  -v, --verbose          Print real-time packet modification events\n");
    printf("  -h, --help             Show this help message\n\n");
}

int main(int argc, char **argv) {
    static struct option long_options[] = {
        {"queue",      required_argument, 0, 'q'},
        {"window",     required_argument, 0, 'w'},
        {"syn-only",   no_argument,       0, 's'},
        {"enroll-set", required_argument, 0, 'E'},
        {"ban-set",    required_argument, 0, 'D'},
        {"ban-after",  required_argument, 0, 'n'},
        {"ban-time",   required_argument, 0, 't'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "q:w:sE:D:n:t:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'q':
                g_queue_num = (uint16_t)atoi(optarg);
                break;
            case 'w':
                g_clamp_window = (uint16_t)atoi(optarg);
                if (g_clamp_window < 1 || g_clamp_window > 64) {
                    fprintf(stderr, "Error: Window size must be between 1 and 64 bytes.\n");
                    return 1;
                }
                if (g_clamp_window > 2) {
                    fprintf(stderr,
                            "Warning: window > 2 may not split the SOCKS5 greeting!\n");
                }
                break;
            case 's':
                g_clamp_connect = false;
                break;
            case 'E':
                snprintf(g_enroll_set, sizeof(g_enroll_set), "%s", optarg);
                break;
            case 'D':
                snprintf(g_ban_set, sizeof(g_ban_set), "%s", optarg);
                break;
            case 'n':
                g_ban_after = atoi(optarg);
                if (g_ban_after < 0) {
                    g_ban_after = 0;
                }
                break;
            case 't':
                g_ban_time = atoi(optarg);
                if (g_ban_time < 1) {
                    g_ban_time = 1;
                }
                break;
            case 'v':
                g_verbose = true;
                break;
            case 'h':
                print_help(argv[0]);
                return 0;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGUSR1, sig_handler);

    ipset_init();

    printf("=== SOCKS5 Anti-DPI TCP Window Clamper ===\n");
    printf("[*] Repository: https://github.com/phenomenonRT/socket5\n");
    printf("[*] NFQUEUE: %u\n", (unsigned)g_queue_num);
    printf("[*] Clamped Window: random 1..%u bytes\n", (unsigned)g_clamp_window);
    printf("[*] Clamp method/auth responses: %s\n", g_clamp_connect ? "ENABLED" : "DISABLED");
    printf("[*] TOFU enroll set: %s\n",
           (g_ipset_ok && g_enroll_set[0]) ? g_enroll_set : "DISABLED");
    printf("[*] Auto-ban: %s\n",
           (g_ipset_ok && g_ban_set[0] && g_ban_after > 0)
               ? g_ban_set
               : "DISABLED");
    printf("[*] Status: Active and listening for packets...\n");

    struct nfq_handle *h = nfq_open();
    if (!h) {
        perror("Error during nfq_open()");
        return 1;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        /* Not critical: queue may not be bound yet */
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("Error during nfq_bind_pf(AF_INET)");
        nfq_close(h);
        return 1;
    }

    struct nfq_q_handle *qh = nfq_create_queue(h, g_queue_num, &packet_callback, NULL);
    if (!qh) {
        perror("Error during nfq_create_queue()");
        nfq_close(h);
        return 1;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("Error setting copy_packet mode");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return 1;
    }

    int fd = nfq_fd(h);
    static unsigned char pkt_buf[PKT_BUF_SIZE] __attribute__((aligned(8)));

    while (g_running) {
        int rv = recv(fd, pkt_buf, sizeof(pkt_buf), 0);
        if (rv > 0) {
            nfq_handle_packet(h, (char *)pkt_buf, rv);
        } else if (rv < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (!g_running) {
                break;
            }
            /* ENOBUFS and friends: short pause instead of busy loop */
            usleep(1000);
        }
    }

    printf("\n[*] Stopping SOCKS5 Window Clamper...\n");
    printf("[*] Stats: Total=%llu, SYN-ACKs clamped=%llu, Responses clamped=%llu, "
           "Enrolled=%llu, Banned=%llu\n",
           (unsigned long long)g_total_packets,
           (unsigned long long)g_clamped_synack,
           (unsigned long long)g_clamped_response,
           (unsigned long long)g_enrolled,
           (unsigned long long)g_banned);

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
