#!/usr/bin/env python3
"""
socks5-winclamp.py — Python fallback implementation of TCP Window Clamper
Uses netfilterqueue to clamp outbound SYN-ACK and SOCKS5 response window sizes.
"""

import sys
import struct
import argparse
from netfilterqueue import NetfilterQueue

def update_checksum(csum, old_val, new_val):
    # RFC 1624 incremental update
    s = (~csum & 0xffff) + (~old_val & 0xffff) + new_val
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    res = ~s & 0xffff
    return 0xffff if res == 0 else res

def make_handler(clamp_window=2, verbose=False):
    def process_packet(pkt):
        payload = bytearray(pkt.get_payload())
        if len(payload) < 20:
            pkt.accept()
            return

        version = payload[0] >> 4
        modified = False

        if version == 4:
            ip_hl = (payload[0] & 0x0f) * 4
            proto = payload[9]
            if proto == 6 and len(payload) >= ip_hl + 20:  # TCP
                tcp_offset = ip_hl
                flags = payload[tcp_offset + 13]
                syn = bool(flags & 0x02)
                ack = bool(flags & 0x10)
                tcp_hl = ((payload[tcp_offset + 12] >> 4) & 0x0f) * 4
                data_offset = tcp_offset + tcp_hl
                data_len = len(payload) - data_offset

                should_clamp = False
                if syn and ack:
                    should_clamp = True
                elif data_len >= 2 and payload[data_offset] == 0x05 and payload[data_offset + 1] in (0x00, 0x02):
                    should_clamp = True

                if should_clamp:
                    old_win = struct.unpack("!H", payload[tcp_offset + 14:tcp_offset + 16])[0]
                    new_win = clamp_window
                    if old_win != new_win:
                        struct.pack_into("!H", payload, tcp_offset + 14, new_win)
                        old_csum = struct.unpack("!H", payload[tcp_offset + 16:tcp_offset + 18])[0]
                        new_csum = update_checksum(old_csum, old_win, new_win)
                        struct.pack_into("!H", payload, tcp_offset + 16, new_csum)
                        modified = True
                        if verbose:
                            print(f"[Anti-DPI] Clamped TCP Window: {old_win} -> {new_win} bytes")

        if modified:
            pkt.set_payload(bytes(payload))
        pkt.accept()

    return process_packet

def main():
    parser = argparse.ArgumentParser(description="SOCKS5 Server-Side TCP Window Clamper")
    parser.add_argument("-q", "--queue", type=int, default=200, help="NFQUEUE number (default: 200)")
    parser.add_argument("-w", "--window", type=int, default=2, help="Clamped window size in bytes (default: 2)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    print(f"=== SOCKS5 Python TCP Window Clamper ===")
    print(f"[*] Queue: {args.queue}, Window: {args.window} bytes")

    nfqueue = NetfilterQueue()
    nfqueue.bind(args.queue, make_handler(args.window, args.verbose))
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()
