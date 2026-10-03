#!/usr/bin/env python3
"""Stand-in for a tunnel client, for checking the redirect actually works.

A tunnel client that accepts redirected connections has one hard requirement:
after the kernel has rewritten the destination to localhost, it still has to
learn where the connection was *originally* headed, or it has nowhere to send
it. That address survives in SO_ORIGINAL_DST.

This listens like such a client would, prints the original destination of every
connection it receives, and hangs up. If a connection to a listed address shows
up here, the split is working: the traffic was diverted instead of leaving
directly, and its real destination is still recoverable.

    ./redirect-probe.py [port]        # default 12345
"""

import socket
import struct
import sys

SO_ORIGINAL_DST = 80


def original_dst(conn):
    """Where the connection was headed before the kernel redirected it."""
    raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port, packed_ip = struct.unpack("!2xH4s8x", raw)
    return socket.inet_ntoa(packed_ip), port


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 12345

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    print(f"listening on 127.0.0.1:{port}", flush=True)

    while True:
        conn, peer = srv.accept()
        try:
            ip, dport = original_dst(conn)
            print(f"REDIRECTED from {peer[0]}:{peer[1]} -> {ip}:{dport}", flush=True)
        except OSError as e:
            # No original destination means the connection came straight here
            # rather than being redirected — worth seeing, not worth dying for.
            print(f"direct connection from {peer[0]}:{peer[1]} ({e})", flush=True)
        finally:
            conn.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
