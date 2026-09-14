/*
 * socks5-winclamp.c — SOCKS5 Server-Side TCP Window Clamper & Anti-DPI Daemon
 *
 * Part of SOCKS5 Anti-DPI Suite by phenomenonRT
 * GitHub: https://github.com/phenomenonRT/socket5
 *
 * Mechanics:
 *   1. Intercepts outbound SYN-ACK packets on NFQUEUE and clamps TCP Window to 1-2 bytes.
 *      -> Forces client OS (Windows, iOS, Android, Linux, macOS) to send SOCKS5 Greeting
 *         (\x05\x01\x00) split across two TCP segments (\x05\x01 then \x00).
 *   2. Intercepts server SOCKS5 choice response (\x05\x00 / \x05\x02) and clamps TCP Window.
 *      -> Forces client OS to split SOCKS5 Connect request (\x05\x01\x00\x03...).
 *   3. Result: TSPU (ТСПУ) DPI NEVER sees the full signature "\x05\x01\x00" in any packet!
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
static uint16_t g_clamp_window = 2; // Default: 2 bytes
static uint16_t g_queue_num = 200;
static bool g_clamp_connect = true; // Also clamp on method response to split connect request
static bool g_verbose = false;

static uint64_t g_clamped_synack = 0;
static uint64_t g_clamped_response = 0;
static uint64_t g_total_packets = 0;

static void sig_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        g_running = false;
    } else if (signo == SIGUSR1) {
        // Dump stats
        fprintf(stderr, "\n[socks5-winclamp] Stats: Total=%lu, SYN-ACKs clamped=%lu, Method responses clamped=%lu\n",
                g_total_packets, g_clamped_synack, g_clamped_response);
    }
}

/*
 * RFC 1624 incremental 16-bit one's complement checksum update:
 *   HC' = ~(~HC + ~m + m')
 */
static inline void update_tcp_checksum(uint16_t *csum, uint16_t old_val, uint16_t new_val) {
    uint32_t sum = (~(*csum) & 0xffff) + (~old_val & 0xffff) + (new_val & 0xffff);
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    uint16_t res = (uint16_t)(~sum);
    *csum = (res == 0) ? 0xffff : res;
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

    // --- IPv4 Handling ---
    struct iphdr *iph = (struct iphdr *)payload;
    if (iph->version == 4 && iph->protocol == IPPROTO_TCP) {
        int ip_hl = iph->ihl * 4;
        if (len >= ip_hl + (int)sizeof(struct tcphdr)) {
            struct tcphdr *tcph = (struct tcphdr *)(payload + ip_hl);
            int tcp_hl = tcph->doff * 4;
            unsigned char *tcp_data = payload + ip_hl + tcp_hl;
            int tcp_data_len = len - (ip_hl + tcp_hl);

            bool should_clamp = false;
            const char *reason = "";

            // 1. SYN+ACK: Force client to fragment SOCKS5 Greeting (\x05\x01\x00)
            if (tcph->syn && tcph->ack) {
                should_clamp = true;
                reason = "SYN-ACK handshake";
                g_clamped_synack++;
            }
            // 2. Server Greeting response (\x05\x00 or \x05\x02): Force client to fragment Connect request
            else if (g_clamp_connect && tcp_data_len >= 2 && tcp_data[0] == 0x05 &&
                     (tcp_data[1] == 0x00 || tcp_data[1] == 0x02)) {
                should_clamp = true;
                reason = "SOCKS5 method response";
                g_clamped_response++;
            }

            if (should_clamp) {
                uint16_t old_win = tcph->window;
                uint16_t new_win = htons(g_clamp_window);
                if (old_win != new_win) {
                    tcph->window = new_win;
                    update_tcp_checksum(&tcph->check, old_win, new_win);
                    modified = true;

                    if (g_verbose) {
                        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &(iph->saddr), src_ip, sizeof(src_ip));
                        inet_ntop(AF_INET, &(iph->daddr), dst_ip, sizeof(dst_ip));
                        printf("[IPv4 %s] %s:%u -> %s:%u | Clamped window: %u -> %u\n",
                               reason, src_ip, ntohs(tcph->source),
                               dst_ip, ntohs(tcph->dest),
                               ntohs(old_win), g_clamp_window);
                    }
                }
            }
        }
    }
    // --- IPv6 Handling ---
    else if (iph->version == 6) {
        if (len >= (int)(sizeof(struct ip6_hdr) + sizeof(struct tcphdr))) {
            struct ip6_hdr *ip6h = (struct ip6_hdr *)payload;
            if (ip6h->ip6_nxt == IPPROTO_TCP) {
                int ip_hl = sizeof(struct ip6_hdr);
                struct tcphdr *tcph = (struct tcphdr *)(payload + ip_hl);
                int tcp_hl = tcph->doff * 4;
                unsigned char *tcp_data = payload + ip_hl + tcp_hl;
                int tcp_data_len = len - (ip_hl + tcp_hl);

                bool should_clamp = false;
                const char *reason = "";

                if (tcph->syn && tcph->ack) {
                    should_clamp = true;
                    reason = "SYN-ACK handshake";
                    g_clamped_synack++;
                } else if (g_clamp_connect && tcp_data_len >= 2 && tcp_data[0] == 0x05 &&
                           (tcp_data[1] == 0x00 || tcp_data[1] == 0x02)) {
                    should_clamp = true;
                    reason = "SOCKS5 method response";
                    g_clamped_response++;
                }

                if (should_clamp) {
                    uint16_t old_win = tcph->window;
                    uint16_t new_win = htons(g_clamp_window);
                    if (old_win != new_win) {
                        tcph->window = new_win;
                        update_tcp_checksum(&tcph->check, old_win, new_win);
                        modified = true;

                        if (g_verbose) {
                            char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
                            inet_ntop(AF_INET6, &(ip6h->ip6_src), src_ip, sizeof(src_ip));
                            inet_ntop(AF_INET6, &(ip6h->ip6_dst), dst_ip, sizeof(dst_ip));
                            printf("[IPv6 %s] %s:%u -> %s:%u | Clamped window: %u -> %u\n",
                                   reason, src_ip, ntohs(tcph->source),
                                   dst_ip, ntohs(tcph->dest),
                                   ntohs(old_win), g_clamp_window);
                        }
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

static void print_help(const char *progname) {
    printf("SOCKS5 Server-Side TCP Window Clamper (Anti-DPI Suite)\n");
    printf("Author: phenomenonRT (https://github.com/phenomenonRT/socket5)\n\n");
    printf("Usage: %s [OPTIONS]\n\n", progname);
    printf("Options:\n");
    printf("  -q, --queue <num>     NFQUEUE number to bind (default: 200)\n");
    printf("  -w, --window <bytes>  Clamped TCP window size in bytes (default: 2, range: 1..10)\n");
    printf("  -s, --syn-only        Only clamp SYN-ACK (skip method response clamping)\n");
    printf("  -v, --verbose         Print real-time packet modification events\n");
    printf("  -h, --help            Show this help message\n\n");
}

int main(int argc, char **argv) {
    static struct option long_options[] = {
        {"queue",    required_argument, 0, 'q'},
        {"window",   required_argument, 0, 'w'},
        {"syn-only", no_argument,       0, 's'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "q:w:svh", long_options, NULL)) != -1) {
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
                break;
            case 's':
                g_clamp_connect = false;
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

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGUSR1, sig_handler);

    printf("=== SOCKS5 Anti-DPI TCP Window Clamper ===\n");
    printf("[*] Repository: https://github.com/phenomenonRT/socket5\n");
    printf("[*] NFQUEUE: %u\n", g_queue_num);
    printf("[*] Clamped Window: %u bytes\n", g_clamp_window);
    printf("[*] Clamp Connect Request: %s\n", g_clamp_connect ? "ENABLED" : "DISABLED");
    printf("[*] Status: Active and listening for packets...\n");

    struct nfq_handle *h = nfq_open();
    if (!h) {
        perror("Error during nfq_open()");
        return 1;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        // Not critical
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
    char buf[4096] __attribute__((aligned));

    while (g_running) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
        } else {
            if (!g_running) break;
        }
    }

    printf("\n[*] Stopping SOCKS5 Window Clamper...\n");
    printf("[*] Stats: Total=%lu, SYN-ACKs clamped=%lu, Method responses clamped=%lu\n",
           g_total_packets, g_clamped_synack, g_clamped_response);

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
