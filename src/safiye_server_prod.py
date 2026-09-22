import asyncio
import threading
import queue
import json
import logging
import os
import re
import base64
import time
import copy
import subprocess
import secrets
import hmac
import frida
import anthropic as _anthropic
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from pydantic import BaseModel
from typing import Optional, List
from contextlib import asynccontextmanager

# Configure logging to both file and console
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("safiye_debug.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SafiyeServer")

# Global state
class State:
    frida_session = None
    frida_script = None
    frida_scripts: list = None
    frida_device = None
    on_device_output_cb = None
    intercept_mode = False
    connected_clients = set()
    packet_queue = queue.Queue()
    is_hooking = False
    ui_target_pid = None
    ui_target_name = None
    ui_started_at = None
    last_vuln_analysis = None
    mcp_last_seen: float = 0.0
    pending_analysis_data: dict = None
    session_events: list = None    # replayed to new WS clients
    session_snapshot: dict = None  # latest memory_dump / static_strings per type
    bridge = None                  # SafiyeBridge instance
    open_pipes: dict = None        # pipe_id → {"handle": int, "name": str}
    _pipe_id_seq: int = 0
    vuln_sources: dict = None      # source → [findings]; merged into last_vuln_analysis
    memcred_before_fps: list = None  # fingerprints from the pre-logout memory-cred scan

state = State()
state.session_events = []
state.session_snapshot = {}
state.frida_scripts = []
state.bridge = None
state.open_pipes = {}
state._pipe_id_seq = 0
state.vuln_sources = {}
state.memcred_before_fps = None


class _ConsoleBridgeHandler(logging.Handler):
    """Mirror Safiye's own log records into the UI 'System Output Log' by pushing
    them onto the same queue the WebSocket broadcaster drains. This is why the
    operator sees hook/spawn/intercept/repeater/error activity in the browser and
    not just in the terminal. INFO and above; the file log still keeps DEBUG."""
    def emit(self, record):
        try:
            q = getattr(state, "packet_queue", None)
            if q is None:
                return
            # Skip transport bookkeeping — it would spam the operator console and,
            # since a status broadcast logs one such line, keeps the bridge from
            # echoing its own plumbing.
            if record.getMessage().startswith("[OUTGOING WS]"):
                return
            q.put({"type": "console_output", "text": self.format(record) + "\n"})
        except Exception:
            pass   # the UI bridge must never break logging itself


_console_bridge = _ConsoleBridgeHandler()
_console_bridge.setLevel(logging.INFO)
_console_bridge.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
logger.addHandler(_console_bridge)

_REPLAY_STREAM   = {"tcp_out", "tcp_in", "dll_monitor", "registry_file_monitor", "bridge_req", "process_spawn", "crypto_event", "faker_hit", "repeater_seed"}
_REPLAY_SNAPSHOT = {"memory_dump", "static_strings"}

_RE_SQLI = re.compile(
    r"('\s*(?:OR|AND)\s+'?\d+\s*=\s*'?\d+"          # ' OR 1=1 , ' AND '1'='1
    r"|\bUNION\s+(?:ALL\s+)?SELECT\b"
    r"|;\s*(?:DROP|DELETE|UPDATE|INSERT|ALTER)\s"
    r"|\bxp_cmdshell\b"
    r"|\bWAITFOR\s+DELAY\b|\bpg_sleep\s*\(|\bBENCHMARK\s*\(|\bSLEEP\s*\(\s*\d"  # time-based
    r"|\bOR\s+1\s*=\s*1\b)",
    re.I | re.MULTILINE
)


_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "safiye_config.json")

def _load_config() -> dict:
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_config(data: dict) -> None:
    try:
        with open(_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error(f"[CONFIG] Save failed: {e}")


def _parse_raw_http_request(raw_content: str, scheme_override: str | None = None) -> tuple[str, str, dict, str]:
    """Parse a Burp-style raw HTTP request into method, URL, headers, body."""
    from urllib.parse import urlparse

    lines = raw_content.replace("\r\n", "\n").split("\n")
    first_line = lines[0].split()
    if len(first_line) < 2:
        raise Exception("Invalid HTTP request line")

    method = first_line[0]
    target = first_line[1]
    if len(first_line) == 2 and target.upper().startswith("HTTP/"):
        target = "/"
    headers = {}
    host = ""
    body_start = -1

    for i, line in enumerate(lines[1:]):
        line = line.rstrip("\r")
        if not line.strip():
            body_start = i + 2
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
            if k.lower().strip() == "host":
                host = v.strip()

    body = "\n".join(lines[body_start:]) if body_start != -1 else ""

    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        url = target
    else:
        if not host:
            raise Exception("Missing Host header")
        scheme = "https" if str(scheme_override or "").lower() == "https" else "http"
        url = f"{scheme}://{host}{target}"

    return method, url, headers, body


def _looks_like_ip(host: str) -> bool:
    """True if host is a literal IPv4/IPv6 address (so it should NOT be sent as
    a TLS SNI — SNI must be a hostname)."""
    import socket as _socket
    for fam in (_socket.AF_INET, _socket.AF_INET6):
        try:
            _socket.inet_pton(fam, host)
            return True
        except OSError:
            pass
    return False


def _extract_host_header(payload: bytes):
    """Pull the Host: header value out of an HTTP request payload, used as the
    TLS SNI when the operator targets a bare IP. Returns None for non-HTTP bytes."""
    try:
        head = payload[:8192].decode("latin-1", "replace")
        m = re.search(r"(?im)^Host:\s*([^\r\n:]+)", head)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    return None


def _tcp_replay(host: str, port: int, payload: bytes, read_timeout: float = 3.0,
                use_tls=None, server_hostname: str = None):
    """TCP Repeater core: open a FRESH connection to host:port, send the payload,
    and read whatever comes back until the peer goes quiet or closes.

    This is the workaround for the dead-socket problem: the original captured
    socket is closed by the time the operator replays, so we cannot reuse it.
    A new connection gets a new source port and a clean handshake.

    When the target speaks TLS (port 443, or use_tls forced True), the fresh
    socket is wrapped in TLS before the payload is sent — otherwise replaying an
    HTTPS request's plaintext over raw TCP just gets a handshake error / 400.
    Certificate verification is disabled so self-signed and IP targets still work
    during testing; `server_hostname` (or the request's Host header) drives SNI.

    Returns (ok: bool, status: str, response: bytes).
    """
    import socket as _socket, ssl as _ssl

    host = (host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]                       # strip IPv6 literal brackets
    if use_tls is None:
        use_tls = (port == 443)                 # sensible default

    try:
        raw = _socket.create_connection((host, port), timeout=5)
    except Exception as e:
        return (False, f"connect failed: {e}", b"")

    s = raw
    tls_label = ""
    if use_tls:
        try:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sni = server_hostname or (None if _looks_like_ip(host) else host)
            s = ctx.wrap_socket(raw, server_hostname=sni)
            tls_label = f" TLS[{s.version()}{', sni=' + sni if sni else ''}]"
        except Exception as e:
            try: raw.close()
            except Exception: pass
            return (False, f"TLS handshake failed: {e}", b"")

    try:
        s.sendall(payload)
    except Exception as e:
        try: s.close()
        except Exception: pass
        return (False, f"send failed: {e}", b"")

    chunks, total = [], 0
    s.settimeout(read_timeout)
    try:
        while total < 1024 * 1024:          # cap the response at 1 MB
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data)
            total += len(data)
    except _socket.timeout:
        pass
    except Exception:
        pass
    finally:
        try: s.close()
        except Exception: pass

    resp = b"".join(chunks)
    return (True, f"sent {len(payload)} bytes, received {len(resp)} bytes{tls_label}", resp)


_ANALYSIS_TOOLS = [
    {
        "name": "get_capture_data",
        "description": "Retrieves the pending Safiye runtime capture data for analysis.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "log_progress",
        "description": (
            "Send a real-time plain-text progress message to the Safiye UI. "
            "Call at the start of each analysis section and when you find something notable. "
            "No markdown, no emojis."
        ),
        "input_schema": {
            "type": "object",
            "required": ["message"],
            "properties": {"message": {"type": "string"}},
        },
    },
    {
        "name": "submit_findings",
        "description": "Submit all vulnerability findings to Safiye. Call once when analysis is complete.",
        "input_schema": {
            "type": "object",
            "required": ["findings"],
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["severity", "title", "description", "evidence", "verification_steps", "exploitation_notes"],
                        "properties": {
                            "severity":           {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                            "title":              {"type": "string"},
                            "description":        {"type": "string"},
                            "evidence":           {"type": "string"},
                            "verification_steps": {"type": "array", "items": {"type": "string"}},
                            "exploitation_notes": {"type": "string"},
                        },
                    },
                }
            },
        },
    },
]

_ANALYSIS_SYSTEM = (
    "You are an expert penetration tester performing automated runtime security analysis using Safiye. "
    "Analyze all captured data thoroughly. Use log_progress to report what you are doing in real-time. "
    "Report findings at every severity level — even INFO observations matter. "
    "Do not ask for confirmation. Do not stop early. Complete a full analysis."
)

_ANALYSIS_USER = (
    "Start the security analysis now. "
    "1. Call get_capture_data to retrieve the runtime capture data. "
    "2. Analyze every section: network packets (credentials, JWT, API keys, insecure protocols), "
    "DLL loads (hijacking, search-order, phantom DLLs), registry operations (secrets, persistence, HKLM writes), "
    "file operations (sensitive paths, world-writable dirs), memory strings (hardcoded secrets, private keys, "
    "connection strings), static PE strings (embedded secrets, debug flags, internal URLs). "
    "3. Call log_progress at the start of each section with the item count. "
    "4. Call log_progress when you find something notable. "
    "5. Call submit_findings with all findings when done."
)


def _run_claude_analysis(chars: int) -> None:
    def _log(msg: str):
        state.packet_queue.put({"type": "vuln_analysis_log", "message": msg})

    cfg = _load_config()
    # Prefer the environment variable so the key need not be stored on disk.
    api_key = os.environ.get("ANTHROPIC_API_KEY") or cfg.get("api_key", "")
    if not api_key:
        _log("No Anthropic API key configured. Enter your key in the sidebar and click Save.")
        return

    _log(f"AI analysis starting ({chars:,} chars) — connecting to Anthropic API...")
    client = _anthropic.Anthropic(api_key=api_key)
    # Model is configurable — env SAFIYE_MODEL, then config "model", else the current
    # default Claude Opus. Use the exact model id string (no date suffix).
    model_id = os.environ.get("SAFIYE_MODEL") or cfg.get("model") or "claude-opus-5"
    _log(f"Using model: {model_id}")
    messages = [{"role": "user", "content": _ANALYSIS_USER}]

    try:
        for _ in range(30):  # max 30 agentic turns
            response = client.messages.create(
                model=model_id,
                max_tokens=8192,
                system=_ANALYSIS_SYSTEM,
                tools=_ANALYSIS_TOOLS,
                messages=messages,
            )
            # Append assistant turn
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason != "tool_use":
                break

            tool_results = []
            done = False
            for block in response.content:
                if block.type != "tool_use":
                    continue

                tool_name  = block.name
                tool_input = block.input or {}
                tool_id    = block.id

                if tool_name == "get_capture_data":
                    if state.pending_analysis_data:
                        result = state.pending_analysis_data["formatted"]
                        _log(f"Capture data delivered to AI ({len(result):,} chars)")
                    else:
                        result = "No capture data available."
                    tool_results.append({"type": "tool_result", "tool_use_id": tool_id, "content": result})

                elif tool_name == "log_progress":
                    msg = tool_input.get("message", "").strip()
                    if msg:
                        _log(f"[AI] {msg}")
                    tool_results.append({"type": "tool_result", "tool_use_id": tool_id, "content": "logged"})

                elif tool_name == "submit_findings":
                    findings = tool_input.get("findings", [])
                    merged = _set_vuln_source("ai", findings)   # merge, don't clobber other detectors
                    state.packet_queue.put({"type": "vuln_findings", "findings": merged})
                    sev = {}
                    for f in findings:
                        s = f.get("severity", "?")
                        sev[s] = sev.get(s, 0) + 1
                    summary = ", ".join(f"{v}x {k}" for k, v in sev.items())
                    _log(f"Analysis complete — {len(findings)} finding(s) submitted ({summary})")
                    tool_results.append({"type": "tool_result", "tool_use_id": tool_id, "content": "submitted"})
                    done = True

            messages.append({"role": "user", "content": tool_results})
            if done:
                break

    except _anthropic.AuthenticationError:
        _log("API key is invalid. Check your Anthropic API key in the sidebar.")
    except _anthropic.RateLimitError:
        _log("Anthropic rate limit hit. Try again in a moment.")
    except Exception as exc:
        _log(f"Analysis error: {exc}")


def _now_ts() -> str:
    t = time.time()
    lt = time.localtime(t)
    ms = int((t % 1) * 1000)
    return f"{lt.tm_hour:02d}:{lt.tm_min:02d}:{lt.tm_sec:02d}.{ms:03d}"


async def broadcast_message(message: dict):
    """Send JSON message to all connected real-time clients."""
    disconnected = set()
    msg_type = message.get("type")

    # Store replayable events so new clients can restore session state
    if msg_type in _REPLAY_STREAM:
        ev = copy.copy(message)
        ev["_ts"] = _now_ts()
        state.session_events.append(ev)
        if len(state.session_events) > 3000:
            state.session_events = state.session_events[-3000:]
    elif msg_type in _REPLAY_SNAPSHOT:
        state.session_snapshot[msg_type] = copy.copy(message)

    if message.get("type") in ["memory_dump", "static_strings", "status"]:
        logger.info(f"[OUTGOING WS] Type: {message.get('type')}, Data Length: {len(message.get('data', [])) if isinstance(message.get('data'), list) else 'N/A'}")

    for client in state.connected_clients:
        try:
            await client.send_json(message)
        except Exception:
            disconnected.add(client)
    for c in disconnected:
        state.connected_clients.remove(c)

async def queue_processor():
    """Async task to pull from thread-safe queue and broadcast to WebSockets."""
    while True:
        try:
            while not state.packet_queue.empty():
                item = state.packet_queue.get_nowait()
                await broadcast_message(item)
            await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Queue processor error: {e}")
            await asyncio.sleep(1)

@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(queue_processor())
    yield

app = FastAPI(title="Safiye Web UI", lifespan=lifespan)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Defense-in-depth: Safiye renders bytes captured from hostile target
    # processes. A CSP that forbids inline/remote scripts means that even if an
    # escaping bug slips through, injected <script>/onerror cannot execute.
    # Inline styles are still used heavily, so style-src keeps 'unsafe-inline'.
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# ═══════════════════════════════════════════════════════════════════════════
# Bind / auth hardening (safiyemonitor-08)
# The tool runs on the operator's machine, on a target's network. Unguarded, any
# LAN host — or any web page the operator visits (via ws:// or a simple cross-site
# POST) — can drive Safiye: spawn hooks, replay TCP (SSRF), read disk, overwrite
# the API key. Defenses: loopback-only default bind, a per-session CSPRNG token
# required on every /api + /ws call (fail-closed), a Host-header allowlist
# (anti-DNS-rebinding), and a WS Origin allowlist. The browser page receives the
# token injected at serve time; the co-located MCP process reads it from a token
# file. NOTE: token secrecy assumes the UI is XSS-free for target-controlled data.
# ═══════════════════════════════════════════════════════════════════════════
SAFIYE_HOST = os.environ.get("SAFIYE_HOST", "127.0.0.1")   # set to 0.0.0.0 for remote access (opt-in)
SAFIYE_PORT = int(os.environ.get("SAFIYE_PORT", "5000"))
SESSION_TOKEN = secrets.token_urlsafe(32)

# Hand the token to the co-located MCP process (same machine, local file).
_TOKEN_FILE = os.path.join(BASE_DIR, ".safiye_session.token")
try:
    with open(_TOKEN_FILE, "w", encoding="utf-8") as _tf:
        _tf.write(SESSION_TOKEN)
    try:
        os.chmod(_TOKEN_FILE, 0o600)
    except OSError:
        pass
except OSError as _e:
    logger.warning(f"Could not write session token file: {_e}")

_LOOPBACK = ("127.0.0.1", "localhost", "::1", "0.0.0.0")
def _allowed_hosts():
    hs = {f"127.0.0.1:{SAFIYE_PORT}", f"localhost:{SAFIYE_PORT}", f"[::1]:{SAFIYE_PORT}",
          "127.0.0.1", "localhost"}
    if SAFIYE_HOST not in _LOOPBACK:
        hs.add(f"{SAFIYE_HOST}:{SAFIYE_PORT}"); hs.add(SAFIYE_HOST)
    for h in os.environ.get("SAFIYE_ALLOWED_HOSTS", "").split(","):
        if h.strip():
            hs.add(h.strip())
    return hs
_ALLOWED_HOSTS = _allowed_hosts()
_ALLOWED_ORIGINS = {f"http://{h}" for h in _ALLOWED_HOSTS} | {f"https://{h}" for h in _ALLOWED_HOSTS}
# Host allowlist is a loopback anti-rebinding control. It is strict only for a true
# loopback bind (127.0.0.1/localhost/::1). When the operator opts into 0.0.0.0
# (remote) we can't know the LAN Host they'll use, so relax it there — token +
# Origin still apply — unless they pin SAFIYE_ALLOWED_HOSTS (which re-enables it).
_HOST_CHECK = (SAFIYE_HOST in ("127.0.0.1", "localhost", "::1")) or bool(os.environ.get("SAFIYE_ALLOWED_HOSTS", "").strip())

def _token_ok(supplied: str) -> bool:
    return bool(supplied) and hmac.compare_digest(str(supplied), SESSION_TOKEN)

_PUBLIC_PREFIXES = ("/static/",)
_PUBLIC_PATHS = ("/favicon.ico",)

@app.middleware("http")
async def _security_middleware(request: Request, call_next):
    # 1) Host allowlist — defeats DNS-rebinding that would make evil.com same-origin.
    if _HOST_CHECK and request.headers.get("host", "") not in _ALLOWED_HOSTS:
        return JSONResponse({"error": "host not allowed"}, status_code=403)
    path = request.url.path
    # 2) The index page (injects the token) and static assets are unauthenticated.
    if path == "/" or path.startswith(_PUBLIC_PREFIXES) or path in _PUBLIC_PATHS:
        return await call_next(request)
    # 3) Everything else requires the per-session token (fail-closed). Header only —
    # never a query param, which would leak the token into logs / Referer. (The WS
    # handshake, which can't set a custom header from a browser, reads ?token= in
    # its own endpoint, not here.)
    supplied = request.headers.get("x-safiye-token") or ""
    if not _token_ok(supplied):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return await call_next(request)

class HookRequest(BaseModel):
    target_exe: str
    target_script: str
    target_scripts: Optional[List[str]] = None
    target_args: Optional[str] = ""

class AttachRequest(BaseModel):
    """Attach to an already-running process by PID or process name (no spawn)."""
    target: str
    target_script: Optional[str] = None
    target_scripts: Optional[List[str]] = None

def frida_on_message(message, data):
    """Callback from Frida JavaScript."""
    if message.get("type") == "send":
        payload = message.get("payload")
        if payload.get("type") == "alert":
            logger.warning(f"[VULNERABILITY DETECTED] {payload.get('title')}")
            report = {
                "type": "vulnerability_report",
                "vulnerabilities": [
                    {
                        "title": payload.get("title"),
                        "description": payload.get("message"),
                        "evidence_method": "Intercepted via Frida Runtime Hook",
                        "evidence_data": f"Real-time signature match on socket {payload.get('socket')}.",
                        "evidence_impact": "Potential Remote Code Execution (RCE) / Logic Bypass"
                    }
                ]
            }
            state.packet_queue.put(report)
            return

        if data:
            payload["body_hex"] = data.hex().upper()
            payload["body"] = data.decode("utf-8", errors="replace")

        if payload.get("type") == "repeater_tcp_response":
            hex_data = payload.get("body_hex", "")
            try:
                raw = bytes.fromhex(hex_data)
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                text = hex_data
            state.packet_queue.put({
                "type": "repeater_tcp_response",
                "socket": payload.get("socket"),
                "data": text,
                "data_hex": hex_data,
                "size": payload.get("size", 0)
            })
            return

        state.packet_queue.put(payload)
    elif message.get("type") == "log":
        logger.info(f"[FRIDA LOG] {message.get('payload')}")
        state.packet_queue.put({"type": "console_output", "text": message.get("payload") + "\n"})
    elif message.get("type") == "error":
        logger.error(f"[FRIDA ERROR] {message}")
        state.packet_queue.put({"type": "error", "message": str(message)})

def _clean_path(p: str) -> str:
    """Strip whitespace and surrounding quotes (Windows 'Copy as path' wraps in
    double quotes) and expand ~ and %ENV% so pasted paths just work."""
    if not p:
        return ""
    p = p.strip().strip('"').strip("'").strip()
    return os.path.expandvars(os.path.expanduser(p))


def _resolve_existing(p: str):
    """Return an absolute path to `p` if it can be found, else None.

    Relative paths are resolved against the current working directory, the Safiye
    project root, and src/ — so `demo/SafiyeFakerDemo.exe` or
    `hooks/safiye_frida_script.js` work no matter where the server was launched
    from (the whole reason spawn used to fail with a relative path)."""
    p = _clean_path(p)
    if not p:
        return None
    if os.path.isabs(p):
        return p if os.path.exists(p) else None
    project_root = os.path.dirname(BASE_DIR)   # BASE_DIR = .../src
    for base in (os.getcwd(), project_root, BASE_DIR):
        cand = os.path.abspath(os.path.join(base, p))
        if os.path.exists(cand):
            return cand
    return None


def _resolve_frida_scripts(target_scripts: list) -> list:
    """Resolve every requested Frida script to an absolute path or raise."""
    resolved_scripts = []
    for sp in target_scripts:
        rp = _resolve_existing(sp)
        if not rp:
            raise FileNotFoundError(
                f"Frida script not found: {sp!r}. "
                "Enter a full path, or a path relative to the Safiye project folder."
            )
        resolved_scripts.append(rp)
    return resolved_scripts


def _activate_session(session, resolved_scripts: list):
    """Load the resolved scripts into an attached/spawned Frida session and
    publish it as the active hook. Shared by spawn and PID/name attach."""
    loaded = []
    for path in resolved_scripts:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            js_code = f.read()
        s = session.create_script(js_code)
        s.on("message", frida_on_message)
        s.load()
        loaded.append(s)
    state.frida_session = session
    state.frida_script = loaded[0]   # primary script — has rpc.exports
    state.frida_scripts = loaded
    state.is_hooking = True
    state.memcred_before_fps = None  # fresh hook → drop any prior process's cred fingerprints
    return loaded


def _resolve_pid_target(device, target: str):
    """Turn an operator-supplied "PID or process name" string into a live PID.

    A pure-integer string is treated as a PID directly. Anything else is matched
    against the running-process list by name (exact, case-insensitive, with or
    without a trailing .exe; then a substring fallback). Raises with a helpful
    message when nothing — or more than one thing — matches."""
    target = (target or "").strip().strip('"').strip("'").strip()
    if not target:
        raise ValueError("Enter a PID or a running process name to attach to.")

    if target.isdigit():
        return int(target)

    try:
        procs = device.enumerate_processes()
    except Exception as e:
        raise RuntimeError(f"Could not enumerate running processes: {e}")

    want = target.lower()
    want_noext = want[:-4] if want.endswith(".exe") else want

    def _norm(name: str) -> str:
        n = (name or "").lower()
        return n[:-4] if n.endswith(".exe") else n

    exact = [p for p in procs if _norm(p.name) == want_noext]
    if len(exact) == 1:
        return exact[0].pid
    if len(exact) > 1:
        pids = ", ".join(str(p.pid) for p in exact)
        raise ValueError(
            f"Multiple processes named {target!r} are running (PIDs: {pids}). "
            "Attach by PID instead."
        )

    partial = [p for p in procs if want_noext in _norm(p.name)]
    if len(partial) == 1:
        return partial[0].pid
    if len(partial) > 1:
        shown = ", ".join(f"{p.name}({p.pid})" for p in partial[:8])
        raise ValueError(
            f"{target!r} matches several processes: {shown}. Attach by PID instead."
        )

    raise ValueError(
        f"No running process matches {target!r}. "
        "Check the exact name (e.g. notepad.exe) or use its numeric PID."
    )


def frida_worker_thread(target_exe: str, target_scripts: list, args: str):
    # A bare number is never an executable path — it's a PID. If "Start Spawn" is
    # handed one (e.g. a stale cached UI, or a paste into the wrong box), attach to
    # it instead of failing with a confusing "file not found".
    _t = _clean_path(target_exe)
    if _t.isdigit():
        state.packet_queue.put({
            "type": "console_output",
            "text": f"[Safiye] '{_t}' looks like a PID — attaching to the running process instead of spawning.\n"
        })
        return frida_attach_worker_thread(_t, target_scripts)
    try:
        exe = _resolve_existing(target_exe)
        if not exe:
            raise FileNotFoundError(
                f"Target executable not found: {target_exe!r}. "
                "Enter a full path, or a path relative to the Safiye project folder."
            )
        resolved_scripts = _resolve_frida_scripts(target_scripts)

        device = frida.get_local_device()
        spawn_args = [exe]
        if args:
            import shlex
            try:
                spawn_args.extend(shlex.split(args, posix=False))
            except ValueError:
                spawn_args.extend(args.split())
        spawn_env = dict(os.environ)
        spawn_env["PYTHONUTF8"] = "1"
        spawn_env["PYTHONIOENCODING"] = "utf-8"
        try:
            pid = device.spawn(spawn_args, env=spawn_env)
        except TypeError:
            pid = device.spawn(spawn_args)
        session = device.attach(pid)
        _activate_session(session, resolved_scripts)
        device.resume(pid)
        state.ui_target_pid = pid
        state.ui_target_name = os.path.basename(exe)
        state.ui_started_at = time.time()
        state.packet_queue.put({"type": "status", "message": "Hook Active!",
                                "target_pid": pid, "target_name": state.ui_target_name,
                                "started_at": state.ui_started_at})
    except Exception as e:
        logger.exception("Frida spawn error")
        state.packet_queue.put({"type": "status", "message": f"Error: {e}"})
        state.is_hooking = False


def frida_attach_worker_thread(target: str, target_scripts: list):
    """Attach the Frida hook to an ALREADY-RUNNING process by PID or name.

    Unlike the spawn path this never creates or resumes a process — the target
    keeps running uninterrupted while the scripts load into it."""
    try:
        resolved_scripts = _resolve_frida_scripts(target_scripts)
        device = frida.get_local_device()
        pid = _resolve_pid_target(device, target)
        session = device.attach(pid)
        _activate_session(session, resolved_scripts)
        state.ui_target_pid = pid
        state.ui_target_name = f"Process {pid}" if str(target).strip().isdigit() else str(target).strip()
        state.ui_started_at = time.time()
        state.packet_queue.put(
            {"type": "status", "message": "Hook Active!", "target_pid": pid,
             "target_name": state.ui_target_name, "started_at": state.ui_started_at}
        )
        state.packet_queue.put(
            {"type": "console_output",
             "text": f"[Safiye] Attached to running process PID {pid}.\n"}
        )
    except Exception as e:
        logger.exception("Frida attach error")
        state.packet_queue.put({"type": "status", "message": f"Error: {e}"})
        state.is_hooking = False

@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    # Serve index.html with the per-session token injected as a <meta> tag. A meta
    # tag (not an inline <script>) is used deliberately: the CSP is script-src
    # 'self', which would block an inline script. app.js reads the meta and sends
    # the token on every /api call + the WS. The token is token_urlsafe → only
    # [A-Za-z0-9_-], safe inside a double-quoted HTML attribute.
    with open(os.path.join(BASE_DIR, "templates", "index.html"), encoding="utf-8") as f:
        html = f.read()
    meta = f'<meta name="safiye-token" content="{SESSION_TOKEN}">'
    if "</head>" in html:
        html = html.replace("</head>", meta + "\n</head>", 1)
    else:
        html = meta + html
    return HTMLResponse(html)

@app.get("/api/status")
async def get_status():
    return {"is_hooking": state.is_hooking, "mcp_last_seen": state.mcp_last_seen or 0,
            "target_pid": state.ui_target_pid if state.is_hooking else None,
            "target_name": state.ui_target_name if state.is_hooking else None,
            "started_at": state.ui_started_at if state.is_hooking else None}

@app.get("/api/pipes")
async def get_pipes():
    try:
        import os
        names = os.listdir(r"\\.\pipe\\")
        pipes = [{"index": i + 1, "name": n} for i, n in enumerate(sorted(names))]
        return {"pipes": pipes}
    except Exception as e:
        return {"pipes": [], "error": str(e)}

@app.post("/api/mcp_ping")
async def mcp_ping():
    state.mcp_last_seen = time.time()
    return {"status": "ok"}


def _build_repeater_body(item: dict) -> str:
    """Accept either a raw HTTP request or structured method/url/headers/body fields."""
    raw = item.get("request") or item.get("raw") or item.get("raw_request")
    if raw:
        return str(raw).replace("\r\n", "\n").replace("\n", "\r\n")

    method = str(item.get("method") or "GET").upper()
    url = str(item.get("url") or item.get("path") or "/")
    headers = item.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    payload = item.get("payload")
    if payload is None:
        payload = item.get("data")
    if payload is None:
        payload = ""
    payload = str(payload)

    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        default_port = 443 if parsed.scheme == "https" else 80
        host_header = parsed.netloc
        dest = item.get("dest") or f"{parsed.hostname}:{parsed.port or default_port}"
    else:
        path = url if url.startswith("/") else "/" + url
        host_header = str(item.get("host") or headers.get("Host") or headers.get("host") or "")
        dest = item.get("dest") or host_header

    lines = [f"{method} {path} HTTP/1.1"]
    if host_header and not any(str(k).lower() == "host" for k in headers):
        lines.append(f"Host: {host_header}")
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if payload and not any(str(k).lower() == "content-length" for k in headers):
        lines.append(f"Content-Length: {len(payload.encode('utf-8'))}")
    lines.append("")
    lines.append(payload)
    item.setdefault("dest", dest)
    return "\r\n".join(lines)


@app.post("/api/repeater/push")
async def repeater_push(request: Request):
    """
    MCP/API entrypoint: push one or more raw requests into the Repeater UI.
    This only creates Repeater tabs; it does not send/replay traffic.
    """
    state.mcp_last_seen = time.time()
    try:
        body = await request.json()
        items = body.get("requests") if isinstance(body, dict) else None
        if items is None:
            items = [body]
        if not isinstance(items, list):
            return {"status": "error", "error": "Expected a request object or {requests: [...]}"}

        pushed = []
        for idx, item in enumerate(items, 1):
            if not isinstance(item, dict):
                return {"status": "error", "error": f"Request #{idx} is not an object."}
            repeater_body = _build_repeater_body(item)
            if not repeater_body.strip():
                return {"status": "error", "error": f"Request #{idx} is empty."}

            event = {
                "type": "repeater_seed",
                "title": str(item.get("title") or item.get("name") or f"MCP Request {idx}"),
                "direction": "MCP Repeater Seed",
                "dest": str(item.get("dest") or ""),
                "socket": str(item.get("socket") or "HTTP"),
                "body": repeater_body,
                "body_hex": repeater_body.encode("utf-8", errors="replace").hex(),
                "size": len(repeater_body.encode("utf-8", errors="replace")),
                "source": "mcp",
            }
            await broadcast_message(event)
            pushed.append({"title": event["title"], "dest": event["dest"], "size": event["size"]})

        await broadcast_message({
            "type": "vuln_analysis_log",
            "message": f"[AI] Pushed {len(pushed)} request(s) into Repeater."
        })
        logger.info(f"[REPEATER_PUSH] {len(pushed)} request(s) pushed from MCP/API.")
        return {"status": "ok", "count": len(pushed), "requests": pushed}
    except Exception as exc:
        logger.exception("[REPEATER_PUSH] Error")
        return {"status": "error", "error": str(exc)}

@app.get("/api/browse_file")
async def browse_file():
    import tkinter as tk
    from tkinter import filedialog
    def open_dialog():
        root = tk.Tk(); root.withdraw(); root.attributes("-topmost", True)
        path = filedialog.askopenfilename()
        root.destroy(); return path
    p = await asyncio.to_thread(open_dialog)
    return {"path": p or ""}

class BridgeStartRequest(BaseModel):
    bridge_port: Optional[int] = 8081
    burp_host:   Optional[str] = "127.0.0.1"
    burp_port:   Optional[int] = 8080

@app.post("/api/bridge/start")
async def bridge_start(req: BridgeStartRequest):
    from safiye_bridge import SafiyeBridge
    if state.bridge and state.bridge.running:
        return {"status": "already_running", "port": state.bridge.bridge_port}
    bridge = SafiyeBridge(req.bridge_port, req.burp_host, req.burp_port, state.packet_queue.put)
    try:
        await bridge.start()
        state.bridge = bridge
        return {"status": "ok", "port": req.bridge_port}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/bridge/stop")
async def bridge_stop():
    if state.bridge and state.bridge.running:
        await state.bridge.stop()
    state.bridge = None
    return {"status": "ok"}

# ── Named Pipe Scanner & Interactive Client ──────────────────────────────────

# (reason, category, interaction_hint)
# category: CRED | EXEC | INFO | REG | CUSTOM
_PIPE_KNOWN = {
    "lsarpc":   ("LSASS RPC - credentials and security policies",
                 "CRED",
                 "MSRPC only. Does not execute commands. Used for hash dumps and LSA policy queries."),
    "samr":     ("SAM Database - user/group enumeration, password hashes",
                 "CRED",
                 "MSRPC only. Does not execute commands. Enumerate local users and dump NTLM hashes."),
    "netlogon": ("Domain authentication pipe - NTLM relay target",
                 "CRED",
                 "MSRPC only. Does not execute commands. Target for Zerologon (CVE-2020-1472) and NTLM relay."),
    "lsass":    ("LSASS process pipe - credential store",
                 "CRED",
                 "Does not execute commands. Direct channel to LSASS for credential extraction."),
    "spoolss":  ("Print Spooler - PrintNightmare CVE-2021-1675",
                 "EXEC",
                 "Code execution via malicious driver load running as SYSTEM. Requires RPC exploit, not plain text."),
    "winspool": ("Print Spooler alt endpoint - PrintNightmare variant",
                 "EXEC",
                 "Same as spoolss. Secondary endpoint used in PrintNightmare chains."),
    "svcctl":   ("Service Control Manager - service control",
                 "EXEC",
                 "Code execution possible: CreateService + StartService = SYSTEM shell. Requires MSRPC, not plain text."),
    "atsvc":    ("Task Scheduler - scheduled task creation",
                 "EXEC",
                 "Code execution possible: create a task and trigger it to run as SYSTEM. Send MSRPC BIND first, then SchRpcRegisterTask."),
    "epmapper": ("RPC Endpoint Mapper - enumerate all RPC interfaces",
                 "INFO",
                 "Does not execute commands. Lists every registered RPC service on the system."),
    "ntsvcs":   ("Device Manager RPC - device and driver enumeration",
                 "INFO",
                 "Does not execute commands. Query installed devices and drivers."),
    "scerpc":   ("Security Config Engine RPC - security policy",
                 "INFO",
                 "Does not execute commands. Query security configuration and audit settings."),
    "wkssvc":   ("Workstation Service - domain info and session enumeration",
                 "INFO",
                 "Does not execute commands. Query active domain and logged-on user sessions."),
    "srvsvc":   ("Server Service - share and connection enumeration",
                 "INFO",
                 "Does not execute commands. List network shares and active connections."),
    "eventlog": ("Event Log - read and clear Windows event logs",
                 "INFO",
                 "Does not execute commands. Read or clear event logs remotely."),
    "winreg":   ("Remote Registry - read and write registry hives",
                 "REG",
                 "Does not execute commands. Read or write registry keys remotely."),
}
_PIPE_NOISE = ("mojo.", "crashpad", "chrome.", "firefox.", "discord.", "slack.")

# ── Named-pipe DACL analysis ────────────────────────────────────────────────
# A pipe's security descriptor is the real access-control boundary. A NULL DACL
# (everyone full control) or an ACE granting a low-privileged principal write /
# create-instance / modify rights is a classic local-privesc path that most
# scanners miss (e.g. an update service pipe that lets a normal user run an
# installer as SYSTEM). We read the DACL and score it.

_WK_SID_NAMES = {
    "S-1-1-0": "Everyone", "S-1-5-7": "Anonymous", "S-1-5-11": "Authenticated Users",
    "S-1-5-32-545": "BUILTIN\\Users", "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-544": "BUILTIN\\Administrators", "S-1-5-18": "SYSTEM",
    "S-1-15-2-1": "ALL APPLICATION PACKAGES", "S-1-15-2-2": "ALL RESTRICTED APP PACKAGES",
    "S-1-5-113": "Local account", "S-1-5-114": "Local account (admin)",
}
# Broad / low-privileged principals: a write-capable ACE for one of these is a
# finding. Feature-prefixed name so it can never be shadowed by another module-
# level symbol (see the icacls scanner's _ICACLS_LOWPRIV_SIDS).
_PIPE_LOWPRIV_SIDS = {
    "S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546",
    "S-1-15-2-1", "S-1-15-2-2", "S-1-5-113", "S-1-5-114",
}
# Access-mask bits that let a caller do damage on a pipe.
_MASK_DANGEROUS = (0x0002          # FILE_WRITE_DATA
                   | 0x0004        # FILE_CREATE_PIPE_INSTANCE (pipe squatting / impersonation)
                   | 0x00040000    # WRITE_DAC
                   | 0x00080000    # WRITE_OWNER
                   | 0x40000000    # GENERIC_WRITE
                   | 0x10000000    # GENERIC_ALL
                   | 0x02000000)   # MAXIMUM_ALLOWED
_MASK_READ = 0x0001 | 0x80000000   # FILE_READ_DATA | GENERIC_READ


def _wk_name(sid: str) -> str:
    return _WK_SID_NAMES.get(sid, sid or "?")


def _sid_to_str(psid) -> str:
    import ctypes
    adv, k32 = ctypes.windll.advapi32, ctypes.windll.kernel32
    p = ctypes.c_wchar_p()
    if adv.ConvertSidToStringSidW(psid, ctypes.byref(p)) and p.value:
        s = p.value
        k32.LocalFree(p)
        return s
    return ""


def _sd_to_sddl(pSD) -> str:
    import ctypes
    adv, k32 = ctypes.windll.advapi32, ctypes.windll.kernel32
    out = ctypes.c_wchar_p()
    length = ctypes.c_ulong(0)
    OWNER_SI, GROUP_SI, DACL_SI = 1, 2, 4
    if adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            pSD, 1, OWNER_SI | GROUP_SI | DACL_SI, ctypes.byref(out), ctypes.byref(length)) and out.value:
        s = out.value
        k32.LocalFree(out)
        return s
    return ""


def _unknown_sec(reason: str, risk: str = "UNKNOWN") -> dict:
    return {"security_readable": False, "risk": risk, "risk_reason": reason,
            "null_dacl": False, "owner": "", "sddl": "", "risky_aces": []}


def _pipe_security(name: str, handle=None) -> dict:
    """Read and score a named pipe's DACL. If `handle` (an already-open pipe
    handle, e.g. the access probe's) is given, the SD is read off it — no extra
    open. Otherwise one READ_CONTROL open is made (no retries / no WaitNamedPipe,
    so a full-system scan stays fast and never blocks). Risk is INFO..CRITICAL.
    NOTE: the analysis reflects the privilege Safiye runs at; run it as a normal
    user to judge exposure to a low-privileged attacker."""
    import ctypes

    class ACL(ctypes.Structure):
        _fields_ = [("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte),
                    ("AclSize", ctypes.c_ushort), ("AceCount", ctypes.c_ushort),
                    ("Sbz2", ctypes.c_ushort)]

    class ACE_HEADER(ctypes.Structure):
        _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte),
                    ("AceSize", ctypes.c_ushort)]

    class ALLOWED_ACE(ctypes.Structure):
        _fields_ = [("Header", ACE_HEADER), ("Mask", ctypes.c_uint32), ("SidStart", ctypes.c_uint32)]

    adv, k32 = ctypes.windll.advapi32, ctypes.windll.kernel32
    OWNER_SI, DACL_SI, SE_KERNEL_OBJECT = 1, 4, 6
    READ_CONTROL, FILE_SHARE_RW, OPEN_EXISTING = 0x00020000, 3, 3

    own_handle = handle is None
    if own_handle:
        h = k32.CreateFileW(f"\\\\.\\pipe\\{name}", READ_CONTROL, FILE_SHARE_RW, None, OPEN_EXISTING, 0, None)
        if h == -1:
            oerr = k32.GetLastError()
            if oerr == 5:                         # ACCESS_DENIED → not exposed to us (good)
                return _unknown_sec("not accessible at Safiye's privilege level (access denied) — not exposed to you.", "LOW")
            if oerr == 231:                       # PIPE_BUSY → don't block; report and move on
                return _unknown_sec("all pipe instances busy — retry the scan")
            return _unknown_sec(f"cannot open for READ_CONTROL (error {oerr})")
        hh = ctypes.c_void_p(h)
    else:
        hh = ctypes.c_void_p(handle)

    pOwner, pDacl, pSD = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    err = adv.GetSecurityInfo(hh, SE_KERNEL_OBJECT, OWNER_SI | DACL_SI,
                              ctypes.byref(pOwner), None, ctypes.byref(pDacl), None, ctypes.byref(pSD))
    if err != 0:
        if own_handle:
            k32.CloseHandle(hh)
        return _unknown_sec(f"GetSecurityInfo error {err}")

    out = {"security_readable": True, "null_dacl": False, "owner": "", "sddl": "",
           "risk": "INFO", "risk_reason": "", "risky_aces": []}
    try:
        out["owner"] = _wk_name(_sid_to_str(pOwner)) if pOwner.value else ""
        out["sddl"] = _sd_to_sddl(pSD)

        if not pDacl.value:                       # NULL DACL == everyone full control
            out["null_dacl"] = True
            out["risk"] = "CRITICAL"
            out["risk_reason"] = "NULL DACL — every user gets full control (create instances, read, write)."
            return out

        acl = ctypes.cast(pDacl, ctypes.POINTER(ACL)).contents
        worst, reasons = 0, []
        for i in range(acl.AceCount):
            pAce = ctypes.c_void_p()
            if not adv.GetAce(pDacl, i, ctypes.byref(pAce)):
                continue
            ace = ctypes.cast(pAce, ctypes.POINTER(ALLOWED_ACE)).contents
            if ace.Header.AceType != 0:           # only ACCESS_ALLOWED aces grant access
                continue
            sid = _sid_to_str(ctypes.c_void_p(pAce.value + 8))   # SID starts after 8-byte header+mask
            if sid not in _PIPE_LOWPRIV_SIDS:
                continue
            mask = ace.Mask & 0xFFFFFFFF
            out["risky_aces"].append({"sid": sid, "name": _wk_name(sid), "mask": f"0x{mask:08X}"})
            if mask & _MASK_DANGEROUS:
                worst = max(worst, 2)
                reasons.append(f"{_wk_name(sid)} may write/create-instance/modify (0x{mask:08X})")
            elif mask & _MASK_READ:
                worst = max(worst, 1)
                reasons.append(f"{_wk_name(sid)} has read access (0x{mask:08X})")

        if worst == 2:
            out["risk"], out["risk_reason"] = "HIGH", "; ".join(reasons)
        elif worst == 1:
            out["risk"], out["risk_reason"] = "MEDIUM", "; ".join(reasons)
        else:
            out["risk"], out["risk_reason"] = "LOW", "DACL present; no broad low-privilege write/create access."
    except Exception as exc:
        out["risk"], out["risk_reason"] = "UNKNOWN", f"DACL parse error: {exc}"
    finally:
        if pSD.value:
            k32.LocalFree(pSD)
        if own_handle:
            k32.CloseHandle(hh)
    return out


def _scan_one_pipe(name: str) -> dict:
    import ctypes
    k32 = ctypes.windll.kernel32
    # Access probe. If it opens, we reuse THIS handle to read the DACL (no second
    # open) — GENERIC_READ|WRITE includes READ_CONTROL. This keeps the scan fast
    # and avoids connecting to extra pipes just to read their security.
    h = k32.CreateFileW(f"\\\\.\\pipe\\{name}", 0xC0000000, 3, None, 3, 0, None)
    sec = None
    if h != -1:
        accessible, busy = True, False
        try:
            sec = _pipe_security(name, handle=h)
        except Exception as exc:
            sec = _unknown_sec(f"DACL error: {exc}")
        k32.CloseHandle(h)
    else:
        err = k32.GetLastError()
        accessible = (err == 231)  # ERROR_PIPE_BUSY
        busy = accessible
        if err == 5:
            # R|W denied but a read-only ACE may still expose it — one cheap
            # READ_CONTROL open (no retry/wait) settles it (LOW / MEDIUM).
            try:
                sec = _pipe_security(name)
            except Exception as exc:
                sec = _unknown_sec(f"DACL error: {exc}")
        elif err == 231:
            sec = _unknown_sec("pipe busy — DACL not read")
        else:
            sec = _unknown_sec(f"not opened (error {err})")
    lower = name.lower()
    interesting, reason, category, hint = False, "", "CUSTOM", ""
    for key, (r, cat, h_txt) in _PIPE_KNOWN.items():
        if key in lower:
            interesting, reason, category, hint = True, r, cat, h_txt
            break
    if not interesting and accessible and not any(n in lower for n in _PIPE_NOISE):
        interesting  = True
        reason       = "App-specific IPC pipe"
        category     = "CUSTOM"
        hint         = "Unknown protocol. Try plain text first; if no response, switch to HEX mode and inspect binary traffic."

    # A weak DACL is always worth surfacing, even on an otherwise-boring pipe.
    if sec and sec.get("risk") in ("CRITICAL", "HIGH"):
        interesting = True
        _dacl_note = ("NULL DACL — everyone full control" if sec.get("null_dacl")
                      else f"Weak DACL: {sec.get('risk_reason', '')}")
        reason = f"⚠ {_dacl_note}" + (f"  |  {reason}" if reason else "")

    result = {"name": name, "accessible": accessible, "busy": busy,
              "interesting": interesting, "reason": reason,
              "category": category, "hint": hint}
    result.update(sec or {})
    return result

@app.post("/api/pipes/scan")
async def pipes_scan():
    import os
    try:
        names = sorted(os.listdir(r"\\.\pipe\\"))
    except Exception as e:
        return {"pipes": [], "error": str(e)}
    pipes = await asyncio.to_thread(lambda: [_scan_one_pipe(n) for n in names])
    for i, p in enumerate(pipes, 1):
        p["index"] = i

    # Surface weak-DACL pipes in the Vulnerabilities tab (merge, don't clobber).
    findings = []
    for p in pipes:
        if p.get("risk") in ("CRITICAL", "HIGH", "MEDIUM"):
            findings.append(_finding(
                p["risk"], f"Weak named-pipe DACL — {p.get('name','?')}",
                ("NULL DACL — every user has full control of this pipe. "
                 if p.get("null_dacl") else "Pipe DACL grants a low-privileged principal access. ")
                + (p.get("risk_reason") or ""),
                evidence=f"\\\\.\\pipe\\{p.get('name','')} | owner={p.get('owner','?')} | {p.get('sddl','')}",
                verification_steps=["Connect to the pipe from a low-privileged context.",
                                    "Send a crafted command and observe whether a privileged action results."],
                exploitation_notes="A writable/create-instance pipe can be squatted or driven to run privileged actions as the server."))
    _set_vuln_source("dacl", findings)
    await broadcast_message({"type": "vuln_findings", "findings": state.last_vuln_analysis})
    return {"pipes": pipes}

class PipeConnectReq(BaseModel):
    name: str

class PipeSendReq(BaseModel):
    pipe_id: str
    data: str
    fmt: str = "utf8"

class PipeIdReq(BaseModel):
    pipe_id: str

@app.post("/api/pipe/connect")
async def pipe_connect(req: PipeConnectReq):
    import ctypes
    k32 = ctypes.windll.kernel32
    path = req.name if req.name.startswith("\\\\") else f"\\\\.\\pipe\\{req.name}"
    h = k32.CreateFileW(path, 0xC0000000, 3, None, 3, 0, None)
    if h == -1:
        err = k32.GetLastError()
        return {"status": "error", "message": f"CreateFileW failed (error {err})"}
    state._pipe_id_seq += 1
    pid = f"pipe_{state._pipe_id_seq}"
    state.open_pipes[pid] = {"handle": int(h), "name": req.name}
    return {"status": "ok", "pipe_id": pid}

@app.post("/api/pipe/send")
async def pipe_send(req: PipeSendReq):
    import ctypes
    info = state.open_pipes.get(req.pipe_id)
    if not info:
        return {"status": "error", "message": "Not connected"}
    try:
        data = bytes.fromhex(req.data.replace(" ", "")) if req.fmt == "hex" else req.data.encode("utf-8", errors="replace")
    except Exception as e:
        return {"status": "error", "message": f"Data error: {e}"}
    written = ctypes.c_ulong(0)
    ok = ctypes.windll.kernel32.WriteFile(info["handle"], data, len(data), ctypes.byref(written), None)
    if not ok:
        return {"status": "error", "message": f"WriteFile failed (error {ctypes.windll.kernel32.GetLastError()})"}
    return {"status": "ok", "bytes_written": written.value}

@app.post("/api/pipe/recv")
async def pipe_recv(req: PipeIdReq):
    import ctypes
    info = state.open_pipes.get(req.pipe_id)
    if not info:
        return {"status": "error", "message": "Not connected"}
    k32 = ctypes.windll.kernel32
    h = info["handle"]
    avail = ctypes.c_ulong(0)
    k32.PeekNamedPipe(h, None, 0, None, ctypes.byref(avail), None)
    if avail.value == 0:
        return {"status": "ok", "data": "", "data_hex": "", "bytes": 0}
    buf = ctypes.create_string_buffer(min(avail.value, 65536))
    read = ctypes.c_ulong(0)
    k32.ReadFile(h, buf, len(buf), ctypes.byref(read), None)
    raw = bytes(buf.raw[:read.value])
    return {"status": "ok", "data": raw.decode("utf-8", errors="replace"),
            "data_hex": raw.hex().upper(), "bytes": read.value}

@app.post("/api/pipe/close")
async def pipe_close(req: PipeIdReq):
    import ctypes
    info = state.open_pipes.pop(req.pipe_id, None)
    if info:
        try: ctypes.windll.kernel32.CloseHandle(info["handle"])
        except: pass
    return {"status": "ok"}


# ── PE / binary protection analysis ─────────────────────────────────────────
# Read exploit-mitigation flags straight out of a module's PE header (no runtime
# hooking) and check its Authenticode signature. Missing ASLR/DEP/CFG make memory
# bugs far more exploitable; an unsigned app binary can be swapped or planted.

# DllCharacteristics bits
_DLLC_HIGH_ENTROPY = 0x0020
_DLLC_DYNAMIC_BASE = 0x0040   # ASLR
_DLLC_FORCE_INTEG  = 0x0080
_DLLC_NX_COMPAT    = 0x0100   # DEP
_DLLC_NO_SEH       = 0x0400
_DLLC_GUARD_CF     = 0x4000   # CFG
_FILE_RELOCS_STRIPPED = 0x0001  # in FileHeader.Characteristics — kills ASLR
_MACHINE = {0x014c: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x01c4: "ARM"}
_SYS_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\", "\\windows\\assembly\\")


def _authenticode(path: str) -> str:
    """'valid' (embedded OR catalog signed & trusted), 'unsigned' (in neither), or
    'invalid' (signed but bad/untrusted/tampered). Catalog verification matters:
    many legitimate binaries (.NET, LOB apps, OS components outside System32) are
    catalog-signed and an embedded-only check would call them unsigned."""
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                    ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]

    class WTFI(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

    class WTCI(ctypes.Structure):   # WINTRUST_CATALOG_INFO
        _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD),
                    ("pcwszCatalogFilePath", wintypes.LPCWSTR), ("pcwszMemberTag", wintypes.LPCWSTR),
                    ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE),
                    ("pbCalculatedFileHash", ctypes.c_void_p), ("cbCalculatedFileHash", wintypes.DWORD),
                    ("pcCatalogContext", ctypes.c_void_p), ("hCatAdmin", ctypes.c_void_p)]

    class WTD(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                    ("pInfo", ctypes.c_void_p), ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPWSTR),
                    ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    # WINTRUST_ACTION_GENERIC_VERIFY_V2 {00AAC56B-CD44-11D0-8CC2-00C04FC295EE}
    GUID_V2 = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    wt = ctypes.windll.wintrust
    wt.WinVerifyTrust.restype = ctypes.c_long
    wt.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p   # HCATINFO — must not truncate on x64

    def _verify(union_choice, pinfo):
        wd = WTD()
        wd.cbStruct = ctypes.sizeof(WTD)
        wd.dwUIChoice = 2            # WTD_UI_NONE
        wd.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
        wd.dwUnionChoice = union_choice
        wd.pInfo = ctypes.cast(pinfo, ctypes.c_void_p)
        wd.dwStateAction = 1        # WTD_STATEACTION_VERIFY
        wd.dwProvFlags = 0x10       # WTD_REVOCATION_CHECK_NONE
        r = wt.WinVerifyTrust(None, ctypes.byref(GUID_V2), ctypes.byref(wd)) & 0xFFFFFFFF
        wd.dwStateAction = 2        # WTD_STATEACTION_CLOSE
        wt.WinVerifyTrust(None, ctypes.byref(GUID_V2), ctypes.byref(wd))
        return r

    try:
        fi = WTFI(ctypes.sizeof(WTFI), path, None, None)
        r = _verify(1, ctypes.byref(fi))           # WTD_CHOICE_FILE (embedded)
        if r == 0:
            return "valid"
        if r != 0x800B0100:                        # signed but bad (not TRUST_E_NOSIGNATURE)
            return "invalid"
        # No embedded signature — check catalogs (SHA-256, then SHA-1 fallback).
        k32 = ctypes.windll.kernel32
        hCatAdmin = ctypes.c_void_p()
        # AcquireContext2 (SHA-256) is Win8+; guard the attribute so ctypes lazy
        # symbol lookup doesn't AttributeError on Win7 and short-circuit the v1
        # (SHA-1) fallback before we reach it.
        acquired = False
        if hasattr(wt, "CryptCATAdminAcquireContext2"):
            acquired = bool(wt.CryptCATAdminAcquireContext2(
                ctypes.byref(hCatAdmin), None, ctypes.c_wchar_p("SHA256"), None, 0))
        if not acquired:
            if not wt.CryptCATAdminAcquireContext(ctypes.byref(hCatAdmin), None, 0):
                return "unsigned"
        hFile = k32.CreateFileW(path, 0x80000000, 1, None, 3, 0, None)   # GENERIC_READ
        if hFile == -1:
            wt.CryptCATAdminReleaseContext(hCatAdmin, 0)
            return "unsigned"
        hFileP = ctypes.c_void_p(hFile)
        result = "unsigned"
        try:
            use2 = hasattr(wt, "CryptCATAdminCalcHashFromFileHandle2")
            cb = wintypes.DWORD(0)
            if use2:
                wt.CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFileP, ctypes.byref(cb), None, 0)
            else:
                wt.CryptCATAdminCalcHashFromFileHandle(hFileP, ctypes.byref(cb), None, 0)
            if cb.value:
                buf = (ctypes.c_ubyte * cb.value)()
                if use2:
                    wt.CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFileP, ctypes.byref(cb), buf, 0)
                else:
                    wt.CryptCATAdminCalcHashFromFileHandle(hFileP, ctypes.byref(cb), buf, 0)
                hCat = wt.CryptCATAdminEnumCatalogFromHash(hCatAdmin, buf, cb.value, 0, None)
                if hCat:
                    hCatP = ctypes.c_void_p(hCat)

                    class CATINFO(ctypes.Structure):
                        _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", ctypes.c_wchar * 260)]

                    catinfo = CATINFO()
                    catinfo.cbStruct = ctypes.sizeof(CATINFO)
                    if wt.CryptCATCatalogInfoFromContext(hCatP, ctypes.byref(catinfo), 0):
                        tag = "".join("%02X" % b for b in buf)
                        ci = WTCI()
                        ci.cbStruct = ctypes.sizeof(WTCI)
                        ci.pcwszCatalogFilePath = catinfo.wszCatalogFile
                        ci.pcwszMemberTag = ctypes.c_wchar_p(tag)
                        ci.pcwszMemberFilePath = path
                        ci.hMemberFile = hFileP
                        ci.pbCalculatedFileHash = ctypes.cast(buf, ctypes.c_void_p)
                        ci.cbCalculatedFileHash = cb.value
                        ci.hCatAdmin = hCatAdmin
                        result = "valid" if _verify(2, ctypes.byref(ci)) == 0 else "unsigned"
                    wt.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatP, 0)
        finally:
            k32.CloseHandle(hFileP)
            wt.CryptCATAdminReleaseContext(hCatAdmin, 0)
        return result
    except Exception as exc:
        return f"unknown ({exc})"


def _pe_protections(path: str) -> dict:
    import struct
    res = {"path": path, "name": os.path.basename(path), "ok": False, "risk": "UNKNOWN",
           "risk_reason": "", "arch": "", "dotnet": False,
           "aslr": False, "dep": False, "cfg": False, "high_entropy": False, "seh": "",
           "signature": "", "missing": []}
    try:
        with open(path, "rb") as f:
            dos = f.read(64)
            if len(dos) < 64 or dos[:2] != b"MZ":
                res["risk_reason"] = "not a PE file"
                return res
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
            f.seek(e_lfanew)
            head = f.read(24 + 256)             # PE sig + FileHeader + optional-header prefix
        if head[:4] != b"PE\x00\x00" or len(head) < 24 + 96:
            res["risk_reason"] = "not a PE file"
            return res
        machine = struct.unpack_from("<H", head, 4)[0]
        characteristics = struct.unpack_from("<H", head, 4 + 18)[0]
        opt = head[24:]
        magic = struct.unpack_from("<H", opt, 0)[0]
        dllchar = struct.unpack_from("<H", opt, 0x46)[0]
        is64 = (magic == 0x20b)
        datadir_off = 112 if is64 else 96
        numrva_off = 108 if is64 else 92
        num_rva = struct.unpack_from("<I", opt, numrva_off)[0] if len(opt) >= numrva_off + 4 else 0
        clr_rva = 0
        # Only read the CLR data directory (index 14) if the header actually
        # declares that many directories — otherwise we'd read section-header junk.
        if num_rva > 14 and len(opt) >= datadir_off + 15 * 8:
            clr_rva = struct.unpack_from("<I", opt, datadir_off + 14 * 8)[0]
    except Exception as exc:
        res["risk_reason"] = f"read error: {exc}"
        return res

    res["ok"] = True
    res["arch"] = _MACHINE.get(machine, f"0x{machine:04x}")
    res["dotnet"] = clr_rva != 0
    res["aslr"] = bool(dllchar & _DLLC_DYNAMIC_BASE) and not (characteristics & _FILE_RELOCS_STRIPPED)
    res["dep"] = bool(dllchar & _DLLC_NX_COMPAT)
    res["cfg"] = bool(dllchar & _DLLC_GUARD_CF)
    res["high_entropy"] = bool(dllchar & _DLLC_HIGH_ENTROPY)
    # SEH status (honest tri-state, not a bool). x64 uses table-based SEH so it is
    # inherently safe ("n/a"). On x86, NO_SEH means the image declares no handlers
    # (safe from SEH overwrite → "no-SEH"); otherwise real SafeSEH lives in the
    # Load Config SEHandlerTable which we don't parse yet, so we say "unknown"
    # rather than falsely claiming SafeSEH.
    if is64:
        res["seh"] = "n/a"
    elif dllchar & _DLLC_NO_SEH:
        res["seh"] = "no-SEH"
    else:
        res["seh"] = "unknown"

    sig = _authenticode(path)
    in_sysdir = any(s in path.lower() for s in _SYS_DIRS)
    # Catalog-signed system binaries report "unsigned" for an embedded check, so
    # don't treat that as a finding for files under the Windows dirs.
    if sig == "unsigned" and in_sysdir:
        res["signature"] = "catalog/system"
        sig_bad = False
    elif sig == "unsigned":
        res["signature"] = "UNSIGNED"
        sig_bad = True
    elif sig == "invalid":
        res["signature"] = "INVALID"
        sig_bad = True
    elif sig == "valid":
        res["signature"] = "signed"
        sig_bad = False
    else:
        res["signature"] = sig
        sig_bad = False

    missing = []
    if not res["aslr"]: missing.append("ASLR")
    if not res["dep"]:  missing.append("DEP")
    if not res["cfg"]:  missing.append("CFG")
    res["missing"] = missing

    reasons = []
    if res["dotnet"]:
        # Managed assembly: memory safety is CLR/JIT-mediated and CFG on pure IL
        # is not meaningful, so missing native flags are informational — NOT a
        # HIGH. Signature (tamper) risk still applies to managed binaries, which
        # is the finding that actually matters for a .NET thick client.
        reasons.append("managed; native flags CLR-mediated" + (f" ({'/'.join(missing)} off)" if missing else ""))
        if sig == "invalid":
            risk = "HIGH"; reasons.append("invalid signature")
        elif sig_bad:
            risk = "MEDIUM"; reasons.append("unsigned assembly")
        else:
            risk = "INFO"
    else:
        if missing: reasons.append("no " + "/".join(missing))
        if sig_bad: reasons.append("invalid signature" if sig == "invalid" else "unsigned binary")
        if sig == "invalid":
            risk = "HIGH"
        elif (not res["aslr"]) and (not res["dep"]):
            risk = "HIGH" if sig_bad else "MEDIUM"
        elif (not res["aslr"]) or (not res["dep"]) or sig_bad:
            risk = "MEDIUM"
        elif not res["cfg"]:
            risk = "LOW"
        else:
            risk = "INFO"
    res["risk"] = risk
    res["risk_reason"] = "; ".join(reasons) if reasons else "ASLR + DEP + CFG present."
    return res


def _collect_pe_files(directory: str, recursive: bool, cap: int = 400) -> list:
    exts = (".exe", ".dll", ".ocx", ".sys", ".cpl")
    out = []
    try:
        if recursive:
            for root, _dirs, files in os.walk(directory):
                for fn in files:
                    if fn.lower().endswith(exts):
                        out.append(os.path.join(root, fn))
                        if len(out) >= cap:
                            return out
        else:
            for fn in sorted(os.listdir(directory)):
                full = os.path.join(directory, fn)
                if os.path.isfile(full) and fn.lower().endswith(exts):
                    out.append(full)
                    if len(out) >= cap:
                        break
    except Exception:
        pass
    return out


class PeScanReq(BaseModel):
    path: str = ""
    paths: list = None
    recursive: bool = False


@app.post("/api/pe_scan")
async def pe_scan(req: PeScanReq):
    """Analyze PE exploit-mitigation flags + Authenticode signature for a file, a
    directory of binaries, or an explicit list of module paths."""
    targets = []
    if req.paths:
        for p in req.paths:
            rp = _resolve_existing(_clean_path(p)) or _clean_path(p)
            if rp:
                targets.append(rp)
    elif req.path:
        rp = _resolve_existing(_clean_path(req.path)) or _clean_path(req.path)
        if rp and os.path.isdir(rp):
            targets = _collect_pe_files(rp, req.recursive)
        elif rp:
            targets = [rp]
            d = os.path.dirname(rp)          # also scan the app's sibling binaries
            if d:
                targets += [x for x in _collect_pe_files(d, req.recursive) if x.lower() != rp.lower()]
    # de-dup preserving order, cap the work
    seen, uniq = set(), []
    for t in targets:
        k = t.lower()
        if k not in seen:
            seen.add(k); uniq.append(t)
    uniq = uniq[:400]
    results = await asyncio.to_thread(lambda: [_pe_protections(t) for t in uniq])
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "UNKNOWN": 4}
    results.sort(key=lambda r: order.get(r.get("risk"), 4))

    # Surface the risky modules in the Vulnerabilities tab (merge, don't clobber).
    findings = []
    for r in results:
        if r.get("risk") in ("HIGH", "MEDIUM"):
            findings.append(_finding(
                r["risk"], f"Weak binary protections — {r.get('name', '?')}",
                f"{r.get('arch','?')} {'.NET ' if r.get('dotnet') else ''}module: {r.get('risk_reason','')}.",
                evidence=f"{r.get('path', r.get('name',''))} | sig={r.get('signature','?')} "
                         f"ASLR={r.get('aslr')} DEP={r.get('dep')} CFG={r.get('cfg')}",
                verification_steps=["Confirm the file is an app binary (not a system/catalog-signed component).",
                                    "For unsigned binaries, test DLL planting / binary replacement."],
                exploitation_notes="Missing ASLR/DEP makes memory bugs exploitable; an unsigned binary can be swapped or planted."))
    _set_vuln_source("pe", findings)
    await broadcast_message({"type": "vuln_findings", "findings": state.last_vuln_analysis})
    return {"results": results, "count": len(results)}


# ── COM/DCOM + RPC endpoint enumeration ─────────────────────────────────────
# RPC: list what the local endpoint mapper advertises (recon; network-reachable
# ncacn_ip_tcp interfaces widen the attack surface). DCOM: read each AppID's
# Launch/Access permission SD and flag ones that let a low-privileged principal
# REMOTELY activate/launch (the DCOM lateral-movement class) — local-only rights
# are normal for many services and are NOT flagged.

# COM access rights (in a Launch/Access permission DACL)
_COM_EXEC, _COM_EXEC_LOCAL, _COM_EXEC_REMOTE, _COM_ACT_LOCAL, _COM_ACT_REMOTE = 1, 2, 4, 8, 16
_COM_REMOTE = _COM_EXEC_REMOTE | _COM_ACT_REMOTE
_COM_RIGHT_NAMES = [("EXEC", 1), ("EXEC_LOCAL", 2), ("EXEC_REMOTE", 4), ("ACT_LOCAL", 8), ("ACT_REMOTE", 16)]


def _rpc_enum(limit: int = 1000) -> dict:
    import ctypes
    from ctypes import wintypes
    rpc = ctypes.windll.rpcrt4

    class UUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class RPC_IF_ID(ctypes.Structure):
        _fields_ = [("Uuid", UUID), ("VersMajor", ctypes.c_ushort), ("VersMinor", ctypes.c_ushort)]

    def _ustr(u):
        return ("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" %
                (u.Data1, u.Data2, u.Data3, u.Data4[0], u.Data4[1], u.Data4[2],
                 u.Data4[3], u.Data4[4], u.Data4[5], u.Data4[6], u.Data4[7]))

    inq = ctypes.c_void_p()
    if rpc.RpcMgmtEpEltInqBegin(None, 0, None, 0, None, ctypes.byref(inq)) != 0:  # RPC_C_EP_ALL_ELTS
        return {"ok": False, "endpoints": [], "by_protseq": {}, "count": 0}
    out = []
    try:
        while len(out) < limit:
            ifid, binding, obj, annot = RPC_IF_ID(), ctypes.c_void_p(), UUID(), ctypes.c_void_p()
            if rpc.RpcMgmtEpEltInqNextW(inq, ctypes.byref(ifid), ctypes.byref(binding),
                                        ctypes.byref(obj), ctypes.byref(annot)) != 0:
                break
            protseq = ""
            if binding.value:
                sb = ctypes.c_void_p()
                if rpc.RpcBindingToStringBindingW(binding, ctypes.byref(sb)) == 0 and sb.value:
                    protseq = ctypes.wstring_at(sb.value)
                    rpc.RpcStringFreeW(ctypes.byref(sb))
                rpc.RpcBindingFree(ctypes.byref(binding))
            a = ctypes.wstring_at(annot.value) if annot.value else ""
            if annot.value:
                rpc.RpcStringFreeW(ctypes.byref(annot))
            out.append({"uuid": _ustr(ifid.Uuid), "version": f"{ifid.VersMajor}.{ifid.VersMinor}",
                        "binding": protseq, "annotation": a,
                        "protseq": protseq.split(":")[0] if protseq else ""})
    finally:
        rpc.RpcMgmtEpEltInqDone(ctypes.byref(inq))
    by = {}
    for e in out:
        by[e["protseq"] or "?"] = by.get(e["protseq"] or "?", 0) + 1
    return {"ok": True, "endpoints": out, "by_protseq": by, "count": len(out)}


def _analyze_com_sd(blob: bytes):
    """Return (null_dacl, [(sid, mask)]) for low-priv ACEs in a COM permission SD."""
    import ctypes
    from ctypes import wintypes

    class ACL(ctypes.Structure):
        _fields_ = [("Rev", ctypes.c_ubyte), ("S1", ctypes.c_ubyte), ("Sz", ctypes.c_ushort),
                    ("Cnt", ctypes.c_ushort), ("S2", ctypes.c_ushort)]

    class ACEH(ctypes.Structure):
        _fields_ = [("T", ctypes.c_ubyte), ("F", ctypes.c_ubyte), ("Sz", ctypes.c_ushort)]

    class AACE(ctypes.Structure):
        _fields_ = [("H", ACEH), ("Mask", ctypes.c_uint32), ("Sid", ctypes.c_uint32)]

    adv = ctypes.windll.advapi32
    buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
    pres, pD, dfl = wintypes.BOOL(), ctypes.c_void_p(), wintypes.BOOL()
    if not adv.GetSecurityDescriptorDacl(ctypes.byref(buf), ctypes.byref(pres), ctypes.byref(pD), ctypes.byref(dfl)):
        return (False, [])
    if not pres.value or not pD.value:
        return (True, [])
    acl = ctypes.cast(pD, ctypes.POINTER(ACL)).contents
    risky = []
    for i in range(acl.Cnt):
        pA = ctypes.c_void_p()
        if not adv.GetAce(pD, i, ctypes.byref(pA)):
            continue
        ace = ctypes.cast(pA, ctypes.POINTER(AACE)).contents
        if ace.H.T != 0:
            continue
        sid = _sid_to_str(ctypes.c_void_p(pA.value + 8))
        if sid in _PIPE_LOWPRIV_SIDS:
            risky.append((sid, ace.Mask & 0xFFFFFFFF))
    return (False, risky)


def _dcom_enum(limit: int = 4000) -> dict:
    """Enumerate HKCR\\AppID\\* and flag AppIDs whose Launch/Access permission lets a
    low-priv principal remotely activate/launch (or has a NULL DACL)."""
    import winreg
    scanned = 0
    findings = []
    try:
        root = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "AppID")
    except OSError:
        return {"ok": False, "findings": [], "scanned": 0}
    idx = 0
    while scanned < limit:
        try:
            name = winreg.EnumKey(root, idx); idx += 1
        except OSError:
            break
        if not name.startswith("{"):
            continue
        scanned += 1
        try:
            sub = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "AppID\\" + name)
        except OSError:
            continue
        friendly = ""
        try:
            friendly, _ = winreg.QueryValueEx(sub, None)
        except OSError:
            pass
        agg = {}           # sid -> mask (OR across both permissions)
        null_dacl = False
        perms_seen = []
        for val in ("LaunchPermission", "AccessPermission"):
            try:
                blob, _ = winreg.QueryValueEx(sub, val)
            except OSError:
                continue
            perms_seen.append(val)
            nd, risky = _analyze_com_sd(bytes(blob))
            if nd:
                null_dacl = True
            for sid, mask in risky:
                agg[sid] = agg.get(sid, 0) | mask
        # Decide severity: only REMOTE low-priv (or null DACL) is a finding.
        remote_princ = []
        for sid, mask in agg.items():
            if mask & _COM_REMOTE:
                remote_princ.append((sid, mask))
        if not (null_dacl or remote_princ):
            continue
        if null_dacl:
            sev = "HIGH"
        elif any(sid in ("S-1-1-0", "S-1-5-7") for sid, _ in remote_princ):
            sev = "HIGH"        # Everyone / Anonymous remote
        elif any(sid in ("S-1-5-11", "S-1-5-32-545") for sid, _ in remote_princ):
            sev = "MEDIUM"      # Authenticated Users / Users remote
        else:
            sev = "LOW"         # AppContainers etc.
        princ = []
        for sid, mask in remote_princ:
            rights = [n for n, b in _COM_RIGHT_NAMES if mask & b]
            princ.append({"sid": sid, "name": _wk_name(sid), "rights": rights})
        findings.append({"appid": name, "name": friendly or name, "permissions": perms_seen,
                         "null_dacl": null_dacl, "severity": sev, "principals": princ})
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 3))
    return {"ok": True, "findings": findings, "scanned": scanned}


@app.post("/api/com_rpc_scan")
async def com_rpc_scan():
    """Enumerate RPC endpoints + analyze DCOM AppID permissions; feed weak-DCOM
    findings into the Vulnerabilities tab."""
    rpc = await asyncio.to_thread(_rpc_enum)
    dcom = await asyncio.to_thread(_dcom_enum)

    findings = []
    for d in dcom.get("findings", []):
        who = "; ".join(f"{p['name']} ({','.join(p['rights'])})" for p in d.get("principals", []))
        desc = ("NULL DACL on this DCOM permission — every user can activate/launch it. "
                if d.get("null_dacl")
                else f"A low-privileged principal can REMOTELY activate/launch this DCOM object: {who}.")
        findings.append(_finding(
            d["severity"], f"Weak DCOM permission — {d.get('name', d['appid'])}",
            desc + " Verify against the machine-wide DCOM Launch/Access restrictions.",
            evidence=f"AppID {d['appid']} | {'/'.join(d.get('permissions', []))} | {who or 'NULL DACL'}",
            verification_steps=["Confirm with dcomcnfg / OleView the effective Launch & Access permission.",
                                "Check the machine-wide DCOM restriction (it may further gate remote activation).",
                                "As a low-priv user, attempt remote activation of the CLSID."],
            exploitation_notes="Remote DCOM activation by a low-privileged principal enables lateral movement "
                               "(e.g., MMC20/ShellWindows-style objects) if not gated by machine restrictions."))
    _set_vuln_source("comrpc", findings)
    await broadcast_message({"type": "vuln_findings", "findings": state.last_vuln_analysis})
    return {"rpc": rpc, "dcom": dcom}


# ── Active TLS certificate-validation probe ─────────────────────────────────
# Connects OUTBOUND to an operator-specified host:port and reports the endpoint's
# certificate trust posture (trusted / self-signed / expired / hostname mismatch
# / untrusted root) plus the negotiated protocol & cipher. Outbound and used only
# on an explicitly supplied, authorized target — never auto-connects anywhere.

def _parse_der_cert(der: bytes) -> dict:
    """Best-effort cert detail via the cryptography lib; {} if unavailable."""
    try:
        import datetime
        from cryptography import x509
        from cryptography.x509.oid import NameOID
    except Exception:
        return {}
    try:
        c = x509.load_der_x509_certificate(der)

        def _cn(name):
            a = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            return a[0].value if a else name.rfc4514_string()

        try:
            na = c.not_valid_after_utc
            nb = c.not_valid_before_utc
            now = datetime.datetime.now(datetime.timezone.utc)
        except Exception:                       # older cryptography
            na = c.not_valid_after; nb = c.not_valid_before
            now = datetime.datetime.utcnow()
        sans = []
        try:
            ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [v for v in ext.value.get_values_for_type(x509.DNSName)]
        except Exception:
            pass
        return {"subject_cn": _cn(c.subject), "issuer_cn": _cn(c.issuer),
                "not_before": str(nb), "not_after": str(na),
                "expired": bool(now > na or now < nb),
                "self_signed": c.subject == c.issuer,
                "sig_alg": (c.signature_hash_algorithm.name if c.signature_hash_algorithm else ""),
                "sans": sans[:10]}
    except Exception:
        return {}


def _tls_probe(host: str, port: int, server_hostname: str = None, timeout: float = 6.0) -> dict:
    import ssl, socket, hashlib
    host = (host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    sni = (server_hostname or host).strip() or None
    res = {"host": host, "port": port, "sni": sni, "ok": False, "trusted": None,
           "protocol": "", "cipher": "", "issues": [], "cert": {}, "sha256": "",
           "severity": "INFO", "risk_reason": ""}

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=sni) as ss:
                res["ok"] = True
                res["trusted"] = True
                res["protocol"] = ss.version()
                c = ss.cipher(); res["cipher"] = c[0] if c else ""
                der = ss.getpeercert(binary_form=True)
                if der:
                    res["sha256"] = hashlib.sha256(der).hexdigest()
                    res["cert"] = _parse_der_cert(der)
    except ssl.SSLCertVerificationError as e:
        res["ok"] = True
        res["trusted"] = False
        res["issues"].append(getattr(e, "verify_message", None) or str(e))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        res["risk_reason"] = f"connect / handshake failed: {e}"
        return res

    if res["trusted"] is False:                 # untrusted → lenient fetch for details
        l = ssl.create_default_context()
        l.check_hostname = False
        l.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                with l.wrap_socket(s, server_hostname=sni) as ss:
                    res["protocol"] = ss.version()
                    c = ss.cipher(); res["cipher"] = c[0] if c else ""
                    der = ss.getpeercert(binary_form=True)
                    if der:
                        res["sha256"] = hashlib.sha256(der).hexdigest()
                        res["cert"] = _parse_der_cert(der)
        except Exception:
            pass

    issues = res["issues"]
    proto = res["protocol"] or ""
    cert = res["cert"]
    if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        issues.append(f"weak protocol {proto}")
    if cert.get("self_signed"):
        issues.append("self-signed certificate")
    if cert.get("expired"):
        issues.append("certificate expired")
    if (cert.get("sig_alg") or "").lower() in ("md5", "sha1"):
        issues.append(f"weak signature ({cert.get('sig_alg')})")

    sev = "INFO"
    if res["trusted"] is False:
        sev = "MEDIUM"                           # untrusted (self-signed/expired/mismatch/…)
    if any("weak protocol" in i for i in issues):
        sev = "MEDIUM"
    if any("weak signature" in i for i in issues):
        sev = "HIGH"
    res["severity"] = sev
    res["issues"] = list(dict.fromkeys(issues))
    res["risk_reason"] = "; ".join(res["issues"]) if res["issues"] else "valid, trusted certificate"
    return res


class TlsProbeReq(BaseModel):
    host: str
    port: int = 443
    server_hostname: str = ""


@app.post("/api/tls_probe")
async def tls_probe(req: TlsProbeReq):
    """Probe an operator-authorized TLS endpoint's certificate posture. Outbound —
    only connects to the host:port the operator supplies."""
    host = (req.host or "").strip()
    if not host:
        return {"ok": False, "risk_reason": "no host given"}
    res = await asyncio.to_thread(_tls_probe, host, int(req.port), (req.server_hostname or "").strip() or None)

    if res.get("ok") and (res.get("trusted") is False or res.get("severity") in ("MEDIUM", "HIGH")):
        cert = res.get("cert", {})
        _set_vuln_source("tls", [_finding(
            res["severity"], f"Weak TLS endpoint — {host}:{req.port}",
            f"The TLS service presents a certificate with issues: {res['risk_reason']}. "
            "A client that does not strictly validate it can be MITM'd.",
            evidence=f"{host}:{req.port} | proto={res.get('protocol','')} cipher={res.get('cipher','')} "
                     f"| subject={cert.get('subject_cn','')} issuer={cert.get('issuer_cn','')} "
                     f"| sha256={res.get('sha256','')[:32]}",
            verification_steps=["Confirm the certificate chain in a browser / openssl s_client.",
                                "Check whether the client app pins or strictly validates the certificate."],
            exploitation_notes="If the client accepts this certificate, an on-path attacker can intercept the TLS session.")])
        await broadcast_message({"type": "vuln_findings", "findings": state.last_vuln_analysis})
    return res



# ═══════════════════════════════════════════════════════════════════════════
# Local Privilege-Escalation checks (Tier-1 #3) + Managed Secret Scanner
# (todo.txt) + Vulnerabilities merge path.  Lane owner: safiyemonitor-08.
# ═══════════════════════════════════════════════════════════════════════════

# Low-privilege principals whose write access to a service binary / install dir
# / unquoted-path parent lets a standard user escalate. Matched against icacls
# output by localized name AND well-known SID (localization-proof).
_LOWPRIV_PRINCIPALS = (
    "everyone", "authenticated users", "users", "builtin\\users",
    "interactive", "domain users", "todos", "herkes", "kullanıcılar",
    "kimliği doğrulanmış",
)
# Feature-prefixed to avoid colliding with the pipe-DACL _LOWPRIV_SIDS (uppercase
# SID set) defined earlier at module level — a bare _LOWPRIV_SIDS here would shadow
# it and silently kill pipe weak-DACL detection.
_ICACLS_LOWPRIV_SIDS = ("s-1-1-0", "s-1-5-11", "s-1-5-32-545", "s-1-5-4")
# icacls rights tokens that grant write-data / modify / full (i.e. can create or
# replace a file). (AD)=append/create-subdir alone is intentionally NOT here — it
# does not allow planting a file, and C:\ root grants it to everyone.
_WRITE_RIGHTS = ("(F)", "(M)", "(W)", "(WD)")
_ICACLS_RIGHTS_RE = re.compile(r':((?:\([^)]*\))+)\s*$')

# DLLs commonly abused for search-order / phantom-DLL hijacking when an app's own
# directory is writable and the DLL is not already sitting next to the exe.
_HIJACKABLE_DLLS = (
    "version.dll", "dwmapi.dll", "uxtheme.dll", "profapi.dll", "cryptbase.dll",
    "wtsapi32.dll", "dbghelp.dll", "textshaping.dll", "winmm.dll", "propsys.dll",
    "edputil.dll", "windowscodecs.dll", "netutils.dll", "wldp.dll",
)
_UPDATE_URL_RE = re.compile(r'http://[^\s"\'<>]+', re.I)


def _icacls_writers(path: str) -> list:
    """Return [{'principal','rights'}] for LOW-PRIV principals that hold
    write/modify/full on `path`, by parsing icacls. Read-only, no side effects.
    Empty list = no weak ACE (or icacls unavailable)."""
    try:
        cp = subprocess.run(["icacls", path], capture_output=True, text=True,
                            timeout=15, encoding="utf-8", errors="replace")
    except Exception:
        return []
    writers = []
    for raw in (cp.stdout or "").splitlines():
        line = raw.rstrip()
        m = _ICACLS_RIGHTS_RE.search(line)     # rights are the trailing (..)(..) groups
        if not m:
            continue
        rights = m.group(1)
        account = line[:m.start()]
        if account.lower().startswith(path.lower()):   # first line carries the queried path
            account = account[len(path):]
        account = account.strip()
        low = account.lower()
        is_lowpriv = any(p in low for p in _LOWPRIV_PRINCIPALS) or any(s in low for s in _ICACLS_LOWPRIV_SIDS)
        if not is_lowpriv:
            continue
        if any(tok in rights.upper() for tok in _WRITE_RIGHTS):
            writers.append({"principal": account, "rights": rights})
    return writers


def _privesc_item(category, risk, title, target, detail, writers=None, remediation=""):
    return {"category": category, "risk": risk, "title": title, "target": target,
            "detail": detail, "principals": writers or [], "remediation": remediation}


def _iter_services():
    """Yield (service_name, expanded_image_path) from HKLM Services. Read-only;
    works for a standard user."""
    import winreg
    try:
        base = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
    except OSError:
        return
    i = 0
    while True:
        try:
            name = winreg.EnumKey(base, i); i += 1
        except OSError:
            break
        try:
            k = winreg.OpenKey(base, name)
            img, _ = winreg.QueryValueEx(k, "ImagePath")
            winreg.CloseKey(k)
        except OSError:
            continue
        if img:
            yield name, os.path.expandvars(str(img))


def _exe_from_imagepath(image_path: str):
    """Extract the executable path from a service ImagePath (strip args). Handles
    quoted and unquoted forms. Returns (exe_path, was_quoted)."""
    s = image_path.strip().lstrip("\\??\\")
    if s.startswith('"'):
        end = s.find('"', 1)
        return (s[1:end] if end != -1 else s[1:], True)
    low = s.lower()
    idx = low.find(".exe")
    if idx != -1:
        return (s[:idx + 4], False)
    return (s.split(" ")[0], False)   # driver .sys / no .exe


def _unquoted_parents(exe_path: str) -> list:
    """For an unquoted service path with spaces, return the hijackable prefixes
    (e.g. C:\\Program.exe) whose PARENT directory is writable by a low-priv
    principal — i.e. the real escalation condition, not just 'has a space'."""
    parts = exe_path.split(" ")
    cands, acc = [], ""
    for i, seg in enumerate(parts[:-1]):
        acc = seg if i == 0 else acc + " " + seg
        prefix_exe = acc + ".exe"
        parent = os.path.dirname(prefix_exe)
        if parent and os.path.isdir(parent):
            w = _icacls_writers(parent)
            if w:
                cands.append({"planted": prefix_exe, "dir": parent, "writers": w})
    return cands


def _scan_insecure_update(directory: str, cap_files: int = 200) -> list:
    """Flag cleartext-HTTP update/config URLs in config/text/binary files — an
    insecure update channel a network attacker can MITM."""
    out, n = [], 0
    exts = (".config", ".json", ".xml", ".ini", ".txt", ".yml", ".yaml", ".exe", ".dll")
    try:
        entries = os.listdir(directory)
    except OSError:
        return out
    for fn in entries:
        if n >= cap_files:
            break
        fp = os.path.join(directory, fn)
        if not os.path.isfile(fp) or os.path.splitext(fn)[1].lower() not in exts:
            continue
        n += 1
        try:
            with open(fp, "rb") as f:
                blob = f.read(1_500_000)
        except OSError:
            continue
        text = blob.decode("utf-8", errors="ignore")
        for m in set(_UPDATE_URL_RE.findall(text)):
            low = m.lower()
            if any(k in low for k in ("update", "version", "download", "upgrade", "patch", "setup", "manifest")):
                out.append(_privesc_item(
                    "insecure_update_url", "MEDIUM",
                    "Insecure (plaintext HTTP) update/config URL",
                    fp,
                    f"Cleartext HTTP endpoint referenced in {fn}: {m[:200]} — a network attacker can MITM the "
                    "update/config channel to deliver a malicious payload.",
                    remediation="Switch to HTTPS with certificate/signature validation."))
    return out


def _run_privesc_scan(target_dir: str, scan_services: bool, max_services: int) -> list:
    findings = []

    # ── 1. Service-based privesc (system-wide, read-only) ────────────────────
    if scan_services:
        count = 0
        for name, img in _iter_services():
            if count >= max_services:
                break
            count += 1
            exe, quoted = _exe_from_imagepath(img)
            if not exe.lower().endswith(".exe"):
                continue                                   # drivers / svchost-hosted
            low = exe.lower()
            is_system = low.startswith("c:\\windows\\") or "\\system32\\" in low or "\\syswow64\\" in low
            # unquoted path with spaces → planting candidate (parent must be writable)
            if not quoted and " " in exe:
                for c in _unquoted_parents(exe):
                    findings.append(_privesc_item(
                        "unquoted_service_path", "HIGH",
                        f"Unquoted service path — service '{name}'",
                        c["planted"],
                        f"Service '{name}' ImagePath is unquoted ({img!r}). A standard user can plant "
                        f"{os.path.basename(c['planted'])} in a writable parent and Windows will run it as the "
                        "service account.",
                        writers=c["writers"],
                        remediation="Quote the ImagePath, or remove low-priv write access from the parent directory."))
            # writable service binary / its directory (skip system binaries)
            if os.path.isfile(exe) and not is_system:
                w_bin = _icacls_writers(exe)
                if w_bin:
                    findings.append(_privesc_item(
                        "writable_service_binary", "HIGH",
                        f"Writable service binary — service '{name}'",
                        exe,
                        f"The executable for service '{name}' is writable by a low-privileged principal; "
                        "replacing it yields code execution as the service account.",
                        writers=w_bin,
                        remediation="Restrict the binary's ACL to Administrators/SYSTEM only."))
                else:
                    d = os.path.dirname(exe)
                    w_dir = _icacls_writers(d) if d else []
                    if w_dir:
                        findings.append(_privesc_item(
                            "writable_service_dir", "MEDIUM",
                            f"Writable service directory — service '{name}'",
                            d,
                            f"The install directory of service '{name}' is writable by a low-priv principal "
                            "(enables DLL planting / binary swap).",
                            writers=w_dir,
                            remediation="Restrict the install directory ACL."))

    # ── 2. Target install-dir checks (DLL hijack / writable / insecure update) ─
    if target_dir:
        rp = _resolve_existing(target_dir) or _clean_path(target_dir)
        d = rp if (rp and os.path.isdir(rp)) else (os.path.dirname(rp) if rp else "")
        if d and os.path.isdir(d):
            w_dir = _icacls_writers(d)
            if w_dir:
                findings.append(_privesc_item(
                    "writable_install_dir", "MEDIUM",
                    "Writable application directory",
                    d,
                    "The application directory is writable by a low-privileged principal — enables binary "
                    "replacement and DLL search-order hijacking against anyone who runs it.",
                    writers=w_dir,
                    remediation="Remove write/modify for Users/Authenticated Users/Everyone."))
                try:
                    present = {f.lower() for f in os.listdir(d)}
                except OSError:
                    present = set()
                for dll in _HIJACKABLE_DLLS:
                    if dll not in present:
                        findings.append(_privesc_item(
                            "dll_hijack_candidate", "HIGH",
                            f"DLL planting candidate — {dll}",
                            os.path.join(d, dll),
                            f"'{dll}' is commonly search-order-loaded, is absent from the writable app directory, "
                            "and could be planted there to hijack the process.",
                            writers=w_dir,
                            remediation="Fix the directory ACL; ship a signed copy; use SetDefaultDllDirectories."))
            findings += _scan_insecure_update(d)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: order.get(f.get("risk"), 4))
    return findings


class PrivescReq(BaseModel):
    target_dir: str = ""
    scan_services: bool = True
    max_services: int = 1500

@app.post("/api/privesc_scan")
async def privesc_scan(req: PrivescReq):
    """Local privilege-escalation surface: unquoted service paths, writable
    service binaries/dirs, DLL-planting candidates, writable install dirs,
    insecure HTTP update channels."""
    findings = await asyncio.to_thread(_run_privesc_scan, req.target_dir, req.scan_services, req.max_services)
    counts = {}
    for f in findings:
        counts[f["risk"]] = counts.get(f["risk"], 0) + 1
    return {"findings": findings, "count": len(findings), "counts": counts}


# ── Managed Secret Scanner (todo.txt) ────────────────────────────────────────
def _run_managed_secret_scan(assembly_path: str, reveal: bool, deep: bool = False) -> dict:
    ps = os.path.join(BASE_DIR, "helpers", "managed_secret_scan.ps1")
    if not os.path.exists(ps):
        return {"status": "error", "message": f"helper missing: {ps}"}
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
           "-File", ps, "-AssemblyPath", assembly_path]
    if deep:
        cmd.append("-Deep")          # DEEP tier runs the target's static constructors
    if reveal:
        cmd.append("-Reveal")
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=45,
                            encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "reflection scan timed out (obfuscated/hanging static initializer?)"}
    except Exception as e:
        return {"status": "error", "message": f"failed to launch helper: {e}"}
    raw = (cp.stdout or "").strip()
    if not raw:
        return {"status": "error", "message": (cp.stderr or "no output from helper").strip()[:400]}
    try:
        data = json.loads(raw)
    except Exception:
        return {"status": "error", "message": f"could not parse helper output: {raw[:300]}"}
    if data.get("error"):
        return {"status": "error", "message": data["error"], "assembly_path": data.get("assembly_path")}
    fnd = data.get("findings") or []
    if isinstance(fnd, dict):           # PS emits a bare object for a single finding
        fnd = [fnd]
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    fnd.sort(key=lambda x: order.get(x.get("severity", "MEDIUM"), 3))
    return {"status": "ok", "assembly_path": data.get("assembly_path"),
            "assembly_name": data.get("assembly_name"), "type_count": data.get("type_count", 0),
            "mode": data.get("mode", "safe"),
            "reveal": data.get("reveal", False), "findings": fnd, "count": len(fnd)}


# ── Universal (native) on-disk secret scanner ────────────────────────────────
# Reads raw file bytes and runs the SAME secret regexes over ASCII + UTF-16LE
# strings. READ-ONLY: unlike .NET deep reflection it never executes target code,
# so it is safe on ANY binary — C/C++/Delphi/Go/Rust as well as .NET. This is the
# universal base; .NET reflection stays the bonus tier for managed assemblies.
_RE_AWS = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
_RE_B64HEX = re.compile(r'^[A-Za-z0-9+/=_-]{16,}$')
# Turkish credential terms the English _RE_STR_CRED misses (thick-client targets
# here are often Turkish). Python re.I is Unicode-based, so it is NOT subject to
# the tr-TR .NET IgnoreCase trap — 'Sifre' matches correctly.
_RE_TR_CRED = re.compile(r'(sifre|parola|kripto|gizli|anahtar|kullanici)\s*[=:]\s*["\']?\S{3,}', re.I)

def _pe_sections(blob: bytes):
    """[(name, raw_start, raw_end)] for a PE's raw sections, to attribute a file
    offset to .rdata/.data. Empty on any parse issue (offset stays un-attributed)."""
    import struct
    try:
        if blob[:2] != b"MZ":
            return []
        e = struct.unpack_from("<I", blob, 0x3C)[0]
        if blob[e:e+4] != b"PE\x00\x00":
            return []
        nsec = struct.unpack_from("<H", blob, e + 4 + 2)[0]
        sizeopt = struct.unpack_from("<H", blob, e + 4 + 16)[0]
        tbl = e + 24 + sizeopt
        out = []
        for i in range(min(nsec, 96)):
            off = tbl + i * 40
            if off + 40 > len(blob):
                break
            name = blob[off:off+8].rstrip(b"\x00").decode("ascii", "replace")
            raw_size = struct.unpack_from("<I", blob, off + 16)[0]
            raw_ptr  = struct.unpack_from("<I", blob, off + 20)[0]
            if raw_ptr and raw_size:
                out.append((name, raw_ptr, raw_ptr + raw_size))
        return out
    except Exception:
        return []

def _ns_section_of(sections, off):
    for name, s, e in sections:
        if s <= off < e:
            return name
    return ""

def _ns_shannon(s: str) -> float:
    import math
    from collections import Counter
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())

def _ns_mask(v: str) -> str:
    n = len(v)
    if n == 0:
        return ""
    if n <= 6:
        return v[:1] + "****"
    return v[:4] + "*" * min(n - 6, 12) + v[-2:]

def _ns_iter_runs(blob: bytes):
    """Yield (offset, enc, text) for printable ASCII (>=6) and UTF-16LE (>=6) runs.
    UTF-16 is scanned at both parities so a wide string at any offset is caught."""
    n = len(blob)
    start = -1
    for i in range(n):
        c = blob[i]
        if 32 <= c <= 126:
            if start < 0:
                start = i
        else:
            if start >= 0 and i - start >= 6:
                yield (start, "ascii", blob[start:i].decode("ascii", "replace"))
            start = -1
    if start >= 0 and n - start >= 6:
        yield (start, "ascii", blob[start:n].decode("ascii", "replace"))
    for parity in (0, 1):
        start = -1
        j = parity
        while j + 1 < n:
            if blob[j+1] == 0 and 32 <= blob[j] <= 126:
                if start < 0:
                    start = j
            else:
                if start >= 0 and (j - start) // 2 >= 6:
                    yield (start, "utf16", blob[start:j:2].decode("ascii", "replace"))
                start = -1
            j += 2
        if start >= 0 and (n - start) // 2 >= 6:
            yield (start, "utf16", blob[start:n:2].decode("ascii", "replace"))

def _native_secret_scan(path: str, reveal: bool = False, cap: int = 64 * 1024 * 1024) -> dict:
    """Read-only strings-based secret scan of any file. Values masked (length +
    SHA-256) unless reveal=true; deduped by SHA-256; capped at 500 findings."""
    import hashlib
    try:
        with open(path, "rb") as f:
            blob = f.read(cap)
    except OSError as exc:
        return {"status": "error", "message": str(exc), "findings": [], "count": 0}
    # Same classification the managed classifier uses (keys/secrets/connstr/token=HIGH).
    cats = [
        ("private-key",       _RE_PRIVKEY,  "HIGH",   "private_key"),
        ("connection-string", _RE_CONNSTR,  "HIGH",   "connection_string"),
        ("aws-access-key",    _RE_AWS,      "HIGH",   "hardcoded_token"),
        ("jwt",               _RE_JWT,      "HIGH",   "hardcoded_token"),
        ("credential",        _RE_STR_CRED, "HIGH",   "hardcoded_secret"),
        ("credential-tr",     _RE_TR_CRED,  "HIGH",   "hardcoded_secret"),
        ("basic-auth",        _RE_BASIC,    "MEDIUM", "hardcoded_secret"),
        ("weak-crypto",       _RE_WEAKCRYP, "LOW",    "weak_crypto"),
    ]
    sections = _pe_sections(blob)
    findings, seen, string_bytes = [], set(), 0
    for off, enc, text in _ns_iter_runs(blob):
        string_bytes += len(text)
        probe = text[:8192]
        hit = None
        for cat, rgx, sev, label in cats:
            m = rgx.search(probe)
            if m:
                hit = (cat, sev, label, m.group(0)); break
        if not hit:
            for tok in probe.split():                     # shape-only: long high-entropy blob
                if len(tok) >= 16 and _RE_B64HEX.match(tok) and _ns_shannon(tok) >= 3.2:
                    hit = ("high-entropy-blob", "MEDIUM", "high_entropy_value", tok); break
        if not hit:
            continue
        cat, sev, label, val = hit
        val = val[:512]
        sha = hashlib.sha256(val.encode("utf-8", "replace")).hexdigest()
        if sha in seen:
            continue
        seen.add(sha)
        item = {"offset": off, "enc": enc, "category": cat, "risk_label": label,
                "severity": sev, "length": len(val), "sha256": sha, "masked": _ns_mask(val),
                "section": _ns_section_of(sections, off)}
        if reveal:
            item["value"] = val
        findings.append(item)
        if len(findings) >= 500:
            break
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda x: order.get(x["severity"], 3))
    packed = bool(sections) and len(blob) > 50000 and string_bytes < len(blob) * 0.02
    return {"status": "ok", "findings": findings, "count": len(findings),
            "scanned_bytes": len(blob), "string_bytes": string_bytes,
            "is_pe": bool(sections) or blob[:2] == b"MZ", "packed": packed}


class ManagedSecretReq(BaseModel):
    path: str = ""
    reveal: bool = False
    deep: bool = False

@app.post("/api/managed_secret_scan")
async def managed_secret_scan(req: ManagedSecretReq):
    """Reflection-scan a managed .NET assembly for embedded secret-like static
    fields/properties (crypto keys, IVs, passwords, connection strings, tokens).

    Auto-detects the target: the native strings scan (read-only, runs NO target
    code) ALWAYS runs and works on any binary. If the file is a managed .NET
    assembly (PE CLR directory present), the reflection tier is ALSO offered —
    SAFE (default, metadata-only, zero exec) or DEEP (deep=true, reads runtime
    static values and TRIGGERS the target's static constructors — opt-in).
    Values are masked (length + SHA-256) unless reveal=true."""
    rp = _resolve_existing(_clean_path(req.path)) or _clean_path(req.path)
    if not rp or not os.path.isfile(rp):
        return {"status": "error", "message": f"file not found: {req.path}"}
    pe = await asyncio.to_thread(_pe_protections, rp)
    is_dotnet = bool(pe.get("dotnet"))
    native = await asyncio.to_thread(_native_secret_scan, rp, req.reveal)
    out = {"status": "ok", "path": rp, "is_dotnet": is_dotnet, "arch": pe.get("arch", ""),
           "native": native}
    if is_dotnet:                                   # reflection is the .NET bonus tier
        out["managed"] = await asyncio.to_thread(_run_managed_secret_scan, rp, req.reveal, req.deep)
    return out


class MemCredReq(BaseModel):
    phase: str = "before"      # "before" | "after" (run 'after' once logged out in the app)

@app.post("/api/memory_cred_scan")
async def memory_cred_scan(req: MemCredReq):
    """Scan the hooked process's memory for credential-like material (masked +
    fingerprinted in the Frida hook — raw secrets never cross the bus). phase=before
    records the fingerprints; phase=after (run after logging out in the target app)
    flags any fingerprint still present as a secret the app failed to clear on logout."""
    if not state.is_hooking or not state.frida_script:
        return {"status": "error", "message": "no active hook — spawn/attach a process first"}
    try:
        raw = await asyncio.to_thread(lambda: state.frida_script.exports_sync.scanmemorycreds())
    except Exception as e:
        return {"status": "error", "message": f"memory scan failed: {e}"}
    if isinstance(raw, dict):
        findings = raw.get("findings", []) or []
        scanned = raw.get("scanned_bytes", 0); truncated = bool(raw.get("truncated"))
    else:
        findings = raw or []; scanned = 0; truncated = False
    phase = "after" if req.phase == "after" else "before"
    before = set(state.memcred_before_fps or [])
    out = []
    for f in findings:
        it = dict(f); fp = it.get("fp")
        if phase == "after" and fp in before:
            it["status"] = "NOT CLEARED (still in memory after logout)"; it["severity"] = "HIGH"
        else:
            it["status"] = "present"; it["severity"] = "MEDIUM"
        out.append(it)
    if phase == "before":
        state.memcred_before_fps = [f.get("fp") for f in findings]
    return {"status": "ok", "phase": phase, "findings": out, "count": len(out),
            "scanned_bytes": scanned, "truncated": truncated}


# ── Source-keyed Vulnerabilities store ───────────────────────────────────────
# The three detectors (AI, rule scan, runtime) plus the Privesc / Managed-Secret
# scanners used to each do `state.last_vuln_analysis = findings`, clobbering one
# another. Instead, every producer owns a NAMED SLICE; setting a slice replaces
# only that producer's findings and rebuilds the merged view, deduping across
# slices by (title, target/evidence) so two distinct same-titled findings survive.
_VULN_SOURCE_ORDER = ["ai", "rule", "runtime", "privesc", "secret", "pe", "dacl", "comrpc", "tls", "memcreds", "scanner", "import"]

def _vuln_dedupe_key(f: dict):
    anchor = (f.get("target") or f.get("evidence") or "")
    return ((f.get("title") or "").strip().lower(), str(anchor)[:160].strip().lower())

def _rebuild_vuln() -> list:
    srcs = state.vuln_sources or {}
    keys = [s for s in _VULN_SOURCE_ORDER if s in srcs] + [s for s in srcs if s not in _VULN_SOURCE_ORDER]
    seen, merged = {}, []
    for s in keys:
        for f in srcs.get(s, []):
            k = _vuln_dedupe_key(f)
            if k in seen:
                seen[k].update(f)          # later slice augments the earlier one
            else:
                nf = dict(f); seen[k] = nf; merged.append(nf)
    merged.sort(key=lambda x: _SEV_ORDER.get(x.get("severity", "INFO"), 4))
    state.last_vuln_analysis = merged
    return merged

def _set_vuln_source(source: str, findings: list) -> list:
    """Replace `source`'s slice and return the rebuilt merged findings list."""
    if state.vuln_sources is None:
        state.vuln_sources = {}
    state.vuln_sources[source] = list(findings or [])
    return _rebuild_vuln()

@app.post("/api/vuln_add")
async def vuln_add(request: Request):
    """Add findings (standard finding shape) to the Vulnerabilities tab. Each call
    REPLACES its named source slice and merges — so the Privesc / Managed-Secret
    'Send to Vulnerabilities' actions coexist with AI/rule findings instead of
    erasing them."""
    body = await request.json()
    findings = body if isinstance(body, list) else body.get("findings", [])
    source = (body.get("source") if isinstance(body, dict) else None) or "scanner"
    if not isinstance(findings, list) or not findings:
        return {"status": "error", "message": "expected a non-empty JSON array of findings"}
    merged = _set_vuln_source(source, findings)
    await broadcast_message({"type": "vuln_analysis_log",
                             "message": f"Added {len(findings)} '{source}' finding(s) to Vulnerabilities ({len(merged)} total)."})
    await broadcast_message({"type": "vuln_findings", "findings": merged})
    return {"status": "ok", "added": len(findings), "total": len(merged)}


@app.get("/api/bridge/status")
async def bridge_status():
    if state.bridge and state.bridge.running:
        return {"running": True, "port": state.bridge.bridge_port,
                "burp": f"{state.bridge.burp_host}:{state.bridge.burp_port}"}
    return {"running": False}

@app.post("/api/start_hook")
async def start_hook(req: HookRequest):
    if state.is_hooking: return {"status": "error"}
    scripts = req.target_scripts if req.target_scripts else [req.target_script]
    threading.Thread(target=frida_worker_thread, args=(req.target_exe, scripts, req.target_args), daemon=True).start()
    return {"status": "ok"}

@app.post("/api/attach_hook")
async def attach_hook(req: AttachRequest):
    if state.is_hooking:
        return {"status": "error", "message": "already hooking — stop the current hook first"}
    scripts = req.target_scripts if req.target_scripts else ([req.target_script] if req.target_script else [])
    if not scripts:
        return {"status": "error", "message": "add at least one Frida script"}
    if not (req.target or "").strip():
        return {"status": "error", "message": "enter a PID or process name to attach to"}
    threading.Thread(target=frida_attach_worker_thread, args=(req.target, scripts), daemon=True).start()
    return {"status": "ok"}

@app.post("/api/stop_hook")
async def stop_hook():
    try:
        for s in (state.frida_scripts or ([state.frida_script] if state.frida_script else [])):
            try: s.unload()
            except: pass
        if state.frida_session: state.frida_session.detach()
    except: pass
    state.is_hooking = False
    state.frida_script = None
    state.frida_scripts = []
    await broadcast_message({"type": "status", "message": "Hook Stopped."})
    return {"status": "ok"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # HTTP middleware does not run for WebSockets, so enforce the same checks here
    # BEFORE accepting: Host allowlist (anti-rebinding), Origin allowlist (blocks a
    # cross-site page from opening ws:// to us), and the per-session token.
    host = websocket.headers.get("host", "")
    origin = websocket.headers.get("origin", "")
    token = websocket.query_params.get("token", "")
    if _HOST_CHECK and host not in _ALLOWED_HOSTS:
        await websocket.close(code=4403); return
    if origin and origin not in _ALLOWED_ORIGINS:   # empty Origin = non-browser local client
        await websocket.close(code=4403); return
    if not _token_ok(token):
        await websocket.close(code=4401); return
    await websocket.accept()
    state.connected_clients.add(websocket)
    # Immediate proof-of-life in the operator's System Output Log the moment the
    # UI connects, so it's never mysteriously blank before a hook is started.
    logger.info(f"Operator UI connected — System Output Log live ({len(state.connected_clients)} client(s)).")

    # Replay previous session to the newly connected client
    try:
        if state.session_events:
            await websocket.send_json({"type": "session_replay", "events": state.session_events})
        for snap in state.session_snapshot.values():
            await websocket.send_json(snap)
        if state.last_vuln_analysis:
            await websocket.send_json({"type": "vuln_findings", "findings": state.last_vuln_analysis})
    except Exception as _e:
        logger.warning(f"[WS] Replay error: {_e}")

    loop = asyncio.get_running_loop()
    try:
        while True:
            data = await websocket.receive_text()
            cmd = json.loads(data)
            action = cmd.get("action")
            
            if action == "dump_memory":
                if state.frida_script:
                    def do_dump():
                        try:
                            res = state.frida_script.exports_sync.dumpstrings()
                            asyncio.run_coroutine_threadsafe(broadcast_message({"type": "memory_dump", "data": res}), loop)
                        except Exception as e: logger.error(f"Dump error: {e}")
                    threading.Thread(target=do_dump, daemon=True).start()
            
            elif action == "get_static_strings":
                raw_path = cmd.get("path")
                path = _resolve_existing(raw_path)
                if not path:
                    await websocket.send_json({
                        "type": "static_strings_error",
                        "message": f"Static strings: target binary not found ({raw_path or 'empty'}). Set the Target Executable first.",
                    })
                else:
                    def do_static():
                        try:
                            import re
                            with open(path, "rb") as f: content = f.read()
                            strs = re.findall(rb"[ -~]{5,}", content)
                            res = [{"type": "Static", "val": s.decode('ascii', errors='ignore')} for s in strs]
                            asyncio.run_coroutine_threadsafe(broadcast_message({"type": "static_strings", "data": res}), loop)
                        except Exception as e:
                            logger.error(f"Static error: {e}")
                            asyncio.run_coroutine_threadsafe(broadcast_message({"type": "static_strings_error", "message": f"Static strings failed: {e}"}), loop)
                    threading.Thread(target=do_static, daemon=True).start()

            elif action == "toggle_intercept":
                val = cmd.get("value", False)
                logger.info(f"[INTERCEPT] Toggling mode to: {val}")
                state.intercept_mode = val
                if state.frida_script: 
                    try:
                        state.frida_script.exports_sync.setintercept(state.intercept_mode)
                        logger.info("[INTERCEPT] Frida script updated successfully.")
                    except Exception as e:
                        logger.error(f"[INTERCEPT] Failed to update Frida script: {e}")
            
            elif action == "submit_action":
                pkg_id = cmd.get('id')
                decision = cmd.get('decision')
                logger.info(f"[INTERCEPT] Submitting action for packet {pkg_id}: {decision}")
                
                if decision == "curl_forward":
                    # Perform out-of-band request via requests (Safiye cURL Mode)
                    raw_content = cmd.get("modified_data", "")
                    socket_id = cmd.get("socket_id")
                    inject_hex = None
                    try:
                        method, url, headers, body = _parse_raw_http_request(raw_content)

                        logger.info(f"[CURL MODE] Sending {method} to {url}")
                        import requests as _req
                        # Disable automatic decompression so we can re-emit the exact bytes the
                        # client expects to read back (Content-Encoding gzip/deflate stays valid).
                        sess = _req.Session()
                        r = sess.request(method, url, headers=headers, data=body, timeout=10, stream=True, allow_redirects=False)
                        raw_body = r.raw.read(decode_content=False)

                        # Build a syntactically-correct raw HTTP/1.1 response that the client can parse.
                        version = "1.1"
                        try:
                            if r.raw.version == 10: version = "1.0"
                        except Exception:
                            pass
                        reason = r.reason or ""
                        resp_head = f"HTTP/{version} {r.status_code} {reason}\r\n"
                        for k, v in r.headers.items():
                            resp_head += f"{k}: {v}\r\n"
                        # Force connection close so the client doesn't expect more data on this socket.
                        if "connection" not in {k.lower() for k in r.headers.keys()}:
                            resp_head += "Connection: close\r\n"
                        resp_head += "\r\n"
                        raw_resp_bytes = resp_head.encode("latin-1", errors="replace") + raw_body
                        inject_hex = raw_resp_bytes.hex()
                        logger.info(f"[CURL MODE] Built raw HTTP response: {len(raw_resp_bytes)} bytes (status={r.status_code}). Will inject into socket={socket_id}.")

                        # Show the response in the UI as well (decoded for readability)
                        try:
                            preview = raw_resp_bytes.decode("utf-8", errors="replace")
                        except Exception:
                            preview = f"<{len(raw_resp_bytes)} binary bytes>"
                        await websocket.send_json({"type": "intercept_curl_response", "data": preview})
                    except Exception as e:
                        logger.error(f"[CURL MODE] Error: {e}")
                        await websocket.send_json({"type": "intercept_curl_response", "data": f"Error: {e}"})

                    # Tell Frida: drop the original send AND inject this response into the next recv()
                    if state.frida_script:
                        post_msg = {"type": f"action_{pkg_id}", "action": "drop"}
                        if inject_hex and socket_id is not None:
                            post_msg["inject_recv_hex"] = inject_hex
                            post_msg["socket_id"] = int(socket_id)
                        state.frida_script.post(post_msg)
                
                elif state.frida_script:
                    # Original forward/drop logic
                    mhex = cmd.get("modified_hex")
                    mhex_len = len(mhex) // 2 if isinstance(mhex, str) else 0
                    logger.info(f"[INTERCEPT] -> Frida post id={pkg_id} action={decision} modified_hex_bytes={mhex_len}")
                    state.frida_script.post({
                        "type": f"action_{pkg_id}",
                        "action": decision,
                        "modified_hex": mhex
                    })
            
            elif action == "repeater_send":
                sid = str(cmd.get("socket", ""))
                payload = str(cmd.get("data", ""))
                is_hex = bool(cmd.get("is_hex", False))
                if sid == "HTTP":
                    import requests as _req
                    try:
                        method, url, headers, body = _parse_raw_http_request(payload)
                        r = _req.request(method, url, headers=headers, data=body, timeout=10, allow_redirects=False)
                        await websocket.send_json({"type": "repeater_response", "data": r.text})
                    except Exception as e: await websocket.send_json({"type": "repeater_response", "data": str(e)})
                elif state.frida_script:
                    try:
                        import asyncio as _aio
                        loop = _aio.get_running_loop()
                        res = await loop.run_in_executor(
                            None,
                            lambda: state.frida_script.exports_sync.repeatersend(sid, payload, is_hex)
                        )
                        await websocket.send_json({"type": "repeater_response", "data": f"{res} — waiting for TCP response..."})
                    except Exception as e: await websocket.send_json({"type": "repeater_response", "data": str(e)})

            elif action == "repeater_tcp_send":
                # TCP Repeater: open a fresh connection to the target and replay.
                dest = str(cmd.get("dest", ""))
                payload_str = str(cmd.get("data", ""))
                is_hex = bool(cmd.get("is_hex", False))
                tab_id = cmd.get("tab_id")
                # TLS: explicit flag from the UI ("tls"), else None → auto by port.
                use_tls = cmd.get("tls", None)
                if use_tls is not None:
                    use_tls = bool(use_tls)
                sni_hint = cmd.get("server_hostname") or None
                host, port, payload, err = None, 0, b"", None
                try:
                    host, _port_s = dest.rsplit(":", 1)
                    port = int(_port_s)
                except Exception:
                    err = f"invalid target '{dest}' (expected host:port)"
                if err is None:
                    try:
                        if is_hex:
                            payload = bytes.fromhex(re.sub(r"\s+", "", payload_str))
                        else:
                            payload = payload_str.encode("utf-8", errors="replace")
                    except Exception as e:
                        err = f"payload error: {e}"
                if err is not None:
                    await websocket.send_json({"type": "repeater_tcp_result", "tab_id": tab_id,
                                               "ok": False, "status": err, "data": "", "data_hex": ""})
                else:
                    # For TLS to a bare IP, take SNI from the request's Host header.
                    sni = sni_hint or _extract_host_header(payload)
                    loop = asyncio.get_running_loop()
                    ok, status, resp = await loop.run_in_executor(
                        None, lambda: _tcp_replay(host, port, payload,
                                                  use_tls=use_tls, server_hostname=sni))
                    logger.info(f"[TCP_REPEATER] {dest}: {status}")
                    await websocket.send_json({
                        "type": "repeater_tcp_result",
                        "tab_id": tab_id,
                        "ok": ok,
                        "status": status,
                        "data": resp.decode("utf-8", errors="replace"),
                        "data_hex": resp.hex(),
                    })

            elif action == "repeater_curl_send":
                # Out-of-band HTTP request from the Repeater pane. Parses a raw HTTP
                # request, sends it via `requests`, and returns a Burp-style response.
                raw_content = str(cmd.get("data", ""))
                try:
                    method, url, headers, body = _parse_raw_http_request(raw_content, cmd.get("scheme"))
                    logger.info(f"[REPEATER cURL] {method} {url}")
                    import requests as _req
                    r = _req.request(method, url, headers=headers, data=body, timeout=10, allow_redirects=False)
                    res_text = f"HTTP/1.1 {r.status_code} {r.reason or ''}\r\n"
                    for k, v in r.headers.items():
                        res_text += f"{k}: {v}\r\n"
                    res_text += "\r\n" + r.text
                    await websocket.send_json({"type": "repeater_response", "data": res_text})
                except Exception as e:
                    logger.error(f"[REPEATER cURL] Error: {e}")
                    await websocket.send_json({"type": "repeater_response", "data": f"Error: {e}"})

            elif action == "faker_add":
                if not state.frida_script:
                    await websocket.send_json({"type": "faker_result", "op": "add", "id": cmd.get("id"), "result": "error:no active hook"})
                else:
                    rid = cmd.get("id"); mod = cmd.get("module", ""); sym = cmd.get("symbol", "")
                    off = cmd.get("offset", ""); fmode = cmd.get("mode", "return"); val = str(cmd.get("value", "1"))
                    def do_faker_add(rid=rid, mod=mod, sym=sym, off=off, fmode=fmode, val=val):
                        try:
                            res = state.frida_script.exports_sync.fakeradd(rid, mod, sym, off, fmode, val)
                        except Exception as e:
                            res = f"error:{e}"
                        asyncio.run_coroutine_threadsafe(broadcast_message({
                            "type": "faker_result", "op": "add", "id": rid, "module": mod, "symbol": sym,
                            "offset": off, "mode": fmode, "value": val, "result": res}), loop)
                    threading.Thread(target=do_faker_add, daemon=True).start()

            elif action == "faker_remove":
                if state.frida_script:
                    rid = cmd.get("id")
                    def do_faker_remove(rid=rid):
                        try:
                            res = state.frida_script.exports_sync.fakerremove(rid)
                        except Exception as e:
                            res = f"error:{e}"
                        asyncio.run_coroutine_threadsafe(broadcast_message({"type": "faker_result", "op": "remove", "id": rid, "result": res}), loop)
                    threading.Thread(target=do_faker_remove, daemon=True).start()

            elif action == "faker_list":
                if state.frida_script:
                    def do_faker_list():
                        try:
                            res = state.frida_script.exports_sync.fakerlist()
                        except Exception as e:
                            logger.error(f"faker_list error: {e}"); res = []
                        asyncio.run_coroutine_threadsafe(broadcast_message({"type": "faker_list", "rules": res}), loop)
                    threading.Thread(target=do_faker_list, daemon=True).start()

            elif action == "faker_search":
                if state.frida_script:
                    mod = cmd.get("module", ""); q = cmd.get("query", "")
                    def do_faker_search(mod=mod, q=q):
                        try:
                            res = state.frida_script.exports_sync.fakersearch(mod, q, 100)
                        except Exception as e:
                            logger.error(f"faker_search error: {e}"); res = []
                        asyncio.run_coroutine_threadsafe(broadcast_message({"type": "faker_search", "module": mod, "query": q, "results": res}), loop)
                    threading.Thread(target=do_faker_search, daemon=True).start()

    except WebSocketDisconnect:
        state.connected_clients.remove(websocket)

@app.get("/api/mcp_status")
async def get_mcp_status():
    """Returns MCP server connectivity status based on last observed call."""
    age = time.time() - state.mcp_last_seen if state.mcp_last_seen else None
    connected = age is not None and age < 120
    return {
        "connected": connected,
        "last_seen_seconds_ago": round(age) if age is not None else None,
    }


@app.get("/api/vuln_store")
async def get_vuln_store():
    """Return latest AI vulnerability analysis results (consumed by MCP server)."""
    state.mcp_last_seen = time.time()
    return {"findings": state.last_vuln_analysis or [], "is_hooking": state.is_hooking}


def _mcp_status_note() -> str:
    age = time.time() - state.mcp_last_seen if state.mcp_last_seen else None
    if age is None:
        return "MCP server has never connected. Start mcp_server.py for Claude Desktop integration."
    if age < 120:
        return f"MCP server connected (last seen {round(age)}s ago)."
    return (
        f"MCP server has not connected in {round(age)}s. "
        "Ensure mcp_server.py is running and configured in Claude Desktop."
    )


_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def _looks_like_tls(raw: bytes) -> bool:
    """TLS record framing: content type 0x14-0x17 + version 0x03,0x00-0x04.
    Encrypted records are random bytes — never scan them for magic bytes."""
    return len(raw) >= 3 and 0x14 <= raw[0] <= 0x17 and raw[1] == 0x03 and raw[2] <= 0x04


def _http_body_start(raw: bytes) -> int:
    i = raw.find(b"\r\n\r\n", 0, 4096)
    return i + 4 if i != -1 else -1


def _dest_port(dest: str):
    """Parse the numeric port from a 'host:port' / '[v6]:port' destination.
    Returns None for non-socket destinations like 'SChannel (secur32.dll)'."""
    try:
        return int(str(dest).rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return None


def _deser_at(raw: bytes, p: int):
    """Full, specific serialization signatures anchored exactly at position p —
    no 2-byte prefixes at arbitrary offsets (which match random data constantly)."""
    n = len(raw)
    if p < 0 or p + 2 > n:
        return None
    if p + 4 <= n and raw[p] == 0xAC and raw[p + 1] == 0xED and raw[p + 2] == 0x00 and raw[p + 3] == 0x05:
        return "Java Serialization"
    if p + 9 <= n and raw[p:p + 9] == b"\x00\x01\x00\x00\x00\xff\xff\xff\xff":
        return ".NET BinaryFormatter"
    # pickle PROTO 0x80 + version 2/3/4, and a STOP '.' as the final byte
    if raw[p] == 0x80 and raw[p + 1] in (0x02, 0x03, 0x04) and raw[n - 1] == 0x2E:
        return "Python Pickle"
    # PHP: O:<len>:"   → 4F 3A <ascii digits> 3A 22
    if raw[p] == 0x4F and raw[p + 1] == 0x3A:
        q, d = p + 2, 0
        while q < n and 0x30 <= raw[q] <= 0x39:
            q += 1
            d += 1
        if d > 0 and q + 1 < n and raw[q] == 0x3A and raw[q + 1] == 0x22:
            return "PHP Serialized Object"
    return None


def _detect_deser(raw: bytes):
    """(fmt, offset) for a real serialized object at the payload start or HTTP
    body start; (None, -1) otherwise. Skips TLS ciphertext."""
    if not raw or len(raw) < 4 or _looks_like_tls(raw):
        return (None, -1)
    positions = [0]
    b = _http_body_start(raw)
    if b > 0:
        positions.append(b)
    for p in positions:
        fmt = _deser_at(raw, p)
        if fmt:
            return (fmt, p)
    return (None, -1)
_RE_CRED      = re.compile(r'(password|passwd|pwd|secret|apikey|api_key)\s*[=:]\s*\S{3,}', re.I)
_RE_JWT       = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
_RE_BASIC     = re.compile(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', re.I)
_RE_XXE       = re.compile(r'<!ENTITY|SYSTEM\s+"file://', re.I)
_RE_DLL_PATH  = re.compile(r'(\\temp\\|\\tmp\\|\\appdata\\|\\users\\public\\|%temp%|%appdata%)', re.I)
_RE_DLL_UNC   = re.compile(r'^\\\\')
_HIJACK_DLLS  = {"version.dll","cryptbase.dll","dwmapi.dll","wtsapi32.dll","profapi.dll","mfc42.dll","dwrite.dll","usp10.dll"}
_RE_REG_SEC   = re.compile(r'(password|passwd|pwd|secret|credential|apikey|api_key|token)', re.I)
_RE_REG_RUN   = re.compile(r'(\\run\\|\\runonce\\|currentversion\\run)', re.I)
_RE_REG_LSA   = re.compile(r'(\\lsa\\|\\sam\\|system\\currentcontrolset\\control\\lsa)', re.I)
_RE_FILE_SENS = re.compile(r'(\\sam$|ntds\.dit|id_rsa|\.pfx|\.key$|web\.config|\.pem$|shadow$|\.kdbx|credentials\.xml)', re.I)
_RE_FILE_SYS  = re.compile(r'(\\system32\\|\\syswow64\\)', re.I)
_RE_STR_CRED  = re.compile(r'(password|passwd|pwd|secret|apikey|api_key)\s*[=:]\s*["\']?\S{3,}', re.I)
_RE_PRIVKEY   = re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----')
_RE_CONNSTR   = re.compile(r'(server=.*password=|jdbc:[a-z]+://|mongodb\+srv://|Data Source=.*Password=)', re.I)
_RE_WEAKCRYP  = re.compile(r'\b(md5|des|rc4|3des|des-cbc)\b', re.I)
_RE_HEXKEY    = re.compile(r'^[0-9a-fA-F]{32,64}$')

# ── Inbound / response detectors (server -> client) ─────────────────────────────
_RE_STACK     = re.compile(
    r'(Traceback \(most recent call last\)'
    r'|System\.[A-Za-z][\w.]*Exception'
    r'|java\.(?:lang|util|io|net|sql)\.[A-Za-z]+Exception'
    r'|\bat [\w.$<>+]+\.[\w<>$]+\([^)]*\)'
    r'|(?:Fatal error|Parse error):.{0,80} on line \d+'
    r'|Microsoft\.[A-Za-z][\w.]*Exception'
    r'|Uncaught \w*(?:Error|Exception))', re.I)
_RE_DBERR     = re.compile(
    r'(ORA-\d{5}'
    r'|SQLSTATE\['
    r'|Unclosed quotation mark'
    r'|You have an error in your SQL syntax'
    r'|Microsoft OLE DB Provider'
    r'|System\.Data\.SqlClient\.SqlException'
    r'|(?:MySql|Sql|Pdo)Exception'
    r'|PostgreSQL.{0,20}ERROR'
    r'|SQLite(?:\.Interop)? error'
    r'|Warning: (?:mysqli?|pg|oci|sqlsrv)_)', re.I)
_RE_INTPATH   = re.compile(
    r'([A-Za-z]:\\(?:Users|Windows|inetpub|wwwroot|Temp|Program Files)\\[^\s<>|"]{0,80}'
    r'|\\\\[\w.-]+\\[\w$.-]+'
    r'|/(?:home|var/www|usr/local|opt)/[\w./-]{2,80})')
_RE_PRIVIP    = re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b')
_RE_SETCOOKIE = re.compile(r'(?im)^\s*set-cookie:\s*([^\r\n]+)')
_RE_SESSCOOKIE = re.compile(r'(sess|session|auth|jwt|sid|token|login|remember|asp\.net)', re.I)
_RE_CARD      = re.compile(r'(?<!\d)(?:\d[ -]?){13,19}(?!\d)')


def _luhn_ok(number: str) -> bool:
    """Validate a candidate card number with the Luhn checksum to cut false positives."""
    digits = [int(c) for c in number if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _finding(severity, title, description, evidence="", verification_steps=None, exploitation_notes=""):
    return {
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence[:300] if evidence else "",
        "verification_steps": verification_steps or [],
        "exploitation_notes": exploitation_notes,
    }


# ── LOLBin / command-injection detection over captured process spawns ─────────
_LOLBINS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
            "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe",
            "installutil.exe", "regasm.exe", "regsvcs.exe", "wmic.exe", "forfiles.exe",
            "schtasks.exe", "curl.exe", "hh.exe", "msxsl.exe"}
_PS_SUSP    = re.compile(r"(?:-enc(?:odedcommand)?\b|-e[cn]?\s|-w\s+hidden|-windowstyle\s+hidden|-nop\b|-noprofile\b|iex\b|invoke-expression|downloadstring|downloadfile|frombase64string|-executionpolicy\s+bypass|-ep\s+bypass)", re.I)
_SHELL_META = re.compile(r"[&|;`]|\$\(|%comspec%|&&|\|\|")
_DL_SUSP    = re.compile(r"https?://|-urlcache|/transfer|scrobj\.dll|javascript:|vbscript:", re.I)


def _lolbin_rules(process_events, findings):
    """FP-tight: only flag a spawned LOLBin when a suspicious signal is present —
    suspicious PowerShell flags, shell metacharacters, a download, a remote/scriptlet
    payload, or elevation. A bare LOLBin spawn with benign args is not a finding."""
    for pe in process_events:
        exe  = (pe.get("exe") or "").strip()
        args = (pe.get("args") or "")
        elevated = bool(pe.get("elevated"))
        caller = pe.get("caller_mod") or "unknown"
        base = os.path.basename(exe.strip('"')).lower() if exe else ""
        low_args = args.lower()
        # LOLBins are often invoked WITHOUT the .exe suffix ("cmd /c", "powershell -enc"),
        # so match the exe basename, the first arg token (bare or .exe), and \name.exe in args.
        first_tok = low_args.split(None, 1)[0].strip('"') if low_args.strip() else ""
        first_base = os.path.basename(first_tok)
        first_exe = first_base if first_base.endswith(".exe") else (first_base + ".exe")
        if base in _LOLBINS:
            lolbin = base
        elif first_exe in _LOLBINS:
            lolbin = first_exe
        else:
            lolbin = next((b for b in _LOLBINS if ("\\" + b in low_args or " " + b + " " in low_args)), "")
        if not lolbin:
            continue
        reasons, sev = [], None
        if lolbin in ("powershell.exe", "pwsh.exe") and _PS_SUSP.search(args):
            sev = "HIGH"; reasons.append("suspicious PowerShell flags (encoded/hidden/noprofile/IEX/download)")
        if lolbin in ("certutil.exe", "bitsadmin.exe", "curl.exe") and _DL_SUSP.search(low_args):
            sev = "HIGH"; reasons.append("download via LOLBin")
        if lolbin in ("regsvr32.exe", "rundll32.exe", "mshta.exe", "msxsl.exe") and (_URL_RE.search(args) or _DL_SUSP.search(low_args)):
            sev = "HIGH"; reasons.append("remote/scriptlet payload via " + lolbin)
        if _SHELL_META.search(args):
            # A lone metacharacter (legit compound commands like `a.exe && b.bat`) is
            # LOW; it is upgraded below when elevated or combined with another signal.
            sev = sev or "LOW"; reasons.append("shell metacharacters in arguments (possible command injection)")
        if elevated and reasons:
            reasons.append("spawned elevated"); sev = "HIGH"
        if not reasons:
            continue   # bare LOLBin spawn, benign args -> not a finding (FP control)
        findings.append(_finding(
            sev,
            f"LOLBin/command-injection: {lolbin}",
            f"The application spawned {lolbin} via {pe.get('api','?')} (caller: {caller}). " + "; ".join(reasons) + ".",
            evidence=f"{exe} {args}"[:280],
            verification_steps=["Check whether the command line incorporates untrusted/user input.",
                                "Reproduce the spawn; attempt to inject arguments."],
            exploitation_notes="If any part of the command line derives from attacker-controlled input this is command injection -> code execution as the app (or elevated)."))


def run_rule_scan(data: dict) -> list:
    findings = []

    tcp_packets     = data.get("tcp_packets", [])[:50]
    dll_events      = data.get("dll_events", [])[:100]
    registry_events = data.get("registry_events", [])[:100]
    file_events     = data.get("file_events", [])[:100]
    memory_strings  = data.get("memory_strings", [])[:200]
    static_strings  = data.get("static_strings", [])[:200]
    crypto_events   = data.get("crypto_events", [])[:100]
    process_events  = data.get("process_events", [])[:100]

    # ── Windows crypto boundary (DPAPI / CNG / CryptoAPI) ───────────────────────
    _dpapi_lm = False
    _crypto_cred_samples = []
    for ce in crypto_events:
        op    = (ce.get("op") or "")
        api   = (ce.get("api") or "")
        cbody = (ce.get("body") or "")[:512]
        if ce.get("dpapi_local_machine"):
            _dpapi_lm = True
        # Recovered plaintext (decrypt/unprotect) frequently exposes stored secrets.
        if op in ("decrypt", "unprotect") and cbody:
            m = _RE_STR_CRED.search(cbody) or _RE_CRED.search(cbody)
            if m and len(_crypto_cred_samples) < 5:
                _crypto_cred_samples.append(f"{api}: {m.group(0)[:120]}")
    if _dpapi_lm:
        findings.append(_finding(
            "MEDIUM", "Insecure DPAPI Scope (LOCAL_MACHINE)",
            "The application protects data with DPAPI using the CRYPTPROTECT_LOCAL_MACHINE flag. "
            "Any user or process on the same host can call CryptUnprotectData to recover the plaintext, "
            "so this offers no protection against a local attacker.",
            evidence="CryptProtectData / CryptProtectMemory called with LOCAL_MACHINE scope (see the Crypto tab).",
            verification_steps=["Open the Crypto tab and inspect the protected blobs.", "Recover the plaintext locally with a DPAPI tool to confirm."],
            exploitation_notes="A local attacker or malware running as any user can decrypt LOCAL_MACHINE DPAPI blobs without the user's password.",
        ))
    for sample in _crypto_cred_samples:
        findings.append(_finding(
            "HIGH", "Secret Recovered at Crypto Boundary",
            "Plaintext recovered from a decrypt / unprotect call contains credential-like material. "
            "This secret is handled in cleartext inside the process even though it is stored or transmitted encrypted.",
            evidence=sample,
            verification_steps=["Open the Crypto tab and locate the decrypt/unprotect event.", "Confirm the value is a live credential or token."],
            exploitation_notes="Extract the secret from the Crypto tab or process memory and reuse it directly.",
        ))

    # ── Network Traffic ────────────────────────────────────────────────────────
    for pkt in tcp_packets:
        body     = (pkt.get("body") or "")[:1024]
        dest     = pkt.get("dest", "unknown")
        hex_str  = (pkt.get("body_hex") or "").replace(" ", "")

        # Deserialization: full signatures anchored at the payload / HTTP-body
        # start, TLS ciphertext skipped — see _detect_deser. (Supplements the
        # real-time Frida check.)
        if hex_str:
            h = hex_str[:65536]
            if len(h) % 2:
                h = h[:-1]
            try:
                raw = bytes.fromhex(h)
            except ValueError:
                raw = b""
            fmt, off = _detect_deser(raw)
            if fmt:
                findings.append(_finding(
                    "CRITICAL", f"Insecure Deserialization — {fmt}",
                    f"A {fmt} object was recognized at the {'HTTP body' if off else 'payload'} start of "
                    "outbound traffic. If untrusted data is deserialized with this format, remote code "
                    "execution may be possible.",
                    evidence=f"Destination: {dest}  |  offset {off}  |  {hex_str[:32]}",
                    verification_steps=["Capture the full payload.", "Attempt deserialization with a crafted gadget chain."],
                    exploitation_notes="Use ysoserial / ysoserial.net with matching gadget chain.",
                ))

        # Plain HTTP. body starting with an HTTP verb == cleartext on the wire.
        # Guard against the old ':80' substring bug (matched :8080 etc.) with a
        # real port parse, and skip SChannel/OpenSSL plaintext (dest has no
        # numeric port) and :443 so we don't flag encrypted traffic as cleartext.
        is_http = body.startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HTTP/"))
        _port = _dest_port(dest)
        if is_http and _port is not None and _port != 443:
            findings.append(_finding(
                "HIGH", "Unencrypted HTTP Traffic",
                "Application communicates over plain HTTP. Credentials and tokens are visible to network observers.",
                evidence=f"Destination: {dest}",
                verification_steps=["Intercept with Safiye Intercept tab.", "Look for credentials or session tokens in the body."],
                exploitation_notes="Position yourself as MITM on the local network and capture the traffic with Wireshark.",
            ))

        # SQL injection pattern in body
        m = _RE_SQLI.search(body)
        if m:
            findings.append(_finding(
                "CRITICAL", "SQL Injection Pattern in Outgoing Traffic",
                "A payload containing SQL injection syntax was observed leaving the process. "
                "If this reaches a database without parameterization, full data exfiltration or RCE via xp_cmdshell is possible.",
                evidence=m.group(0)[:200],
                verification_steps=["Replay the request via Repeater tab.", "Confirm reflection or error-based disclosure."],
                exploitation_notes="Use sqlmap against the identified endpoint with the captured cookie/token.",
            ))

        # Cleartext credentials in body
        m = _RE_CRED.search(body)
        if m:
            findings.append(_finding(
                "HIGH", "Cleartext Credentials in Network Packet",
                "A credential-like key=value pair was found in plaintext traffic.",
                evidence=m.group(0)[:200],
                verification_steps=["Open Intercept tab and confirm the value.", "Test with modified credentials to verify authentication bypass."],
                exploitation_notes="Steal session or replay the request with stolen credentials.",
            ))

        # HTTP Basic Auth
        m = _RE_BASIC.search(body)
        if m:
            try:
                decoded = base64.b64decode(m.group(1) + "==").decode(errors="replace")
            except Exception:
                decoded = m.group(1)
            findings.append(_finding(
                "HIGH", "HTTP Basic Authentication Credentials Exposed",
                "HTTP Basic Auth encodes credentials in Base64 — trivially reversible. "
                "Transmitting over plaintext HTTP makes them immediately readable.",
                evidence=f"Decoded: {decoded[:100]}",
                verification_steps=["Confirm the decoded value contains real credentials.", "Test authentication with decoded credentials."],
                exploitation_notes="Decode Base64 and use credentials directly.",
            ))

        # JWT token
        m = _RE_JWT.search(body)
        if m:
            token = m.group(0)
            try:
                header_b64 = token.split(".")[0]
                header = json.loads(base64.b64decode(header_b64 + "==").decode(errors="replace"))
                alg = header.get("alg", "")
                if alg.lower() in ("none", ""):
                    findings.append(_finding(
                        "CRITICAL", "JWT with Algorithm 'none' (Signature Bypass)",
                        "A JWT with alg:none was detected. This means the signature is not verified — any payload can be forged.",
                        evidence=f"Header: {json.dumps(header)}",
                        verification_steps=["Craft a JWT with a modified payload and alg:none.", "Send it to the server and observe if it is accepted."],
                        exploitation_notes="Use jwt_tool or manually craft: base64(header) + '.' + base64(payload) + '.'",
                    ))
                else:
                    findings.append(_finding(
                        "INFO", f"JWT Token in Network Traffic (alg={alg})",
                        "A JWT token is transmitted in cleartext. If intercepted, it can be replayed until it expires.",
                        evidence=token[:120],
                    ))
            except Exception:
                findings.append(_finding("INFO", "JWT Token Detected in Traffic", "", evidence=token[:120]))

        # XXE
        if _RE_XXE.search(body):
            findings.append(_finding(
                "CRITICAL", "XXE (XML External Entity) Pattern Detected",
                "An XML payload containing ENTITY or SYSTEM keywords was observed. "
                "If parsed by a vulnerable XML processor, this can read local files or trigger SSRF.",
                evidence=body[:200],
                verification_steps=["Confirm the XML is parsed server-side.", "Try reading /etc/passwd or C:\\Windows\\win.ini via SYSTEM entity."],
                exploitation_notes="Use a Burp Collaborator/interactsh payload to confirm out-of-band XXE.",
            ))

    # ── Inbound / Response Scanning (server -> client) ──────────────────────────
    # Everything above scans OUTBOUND requests. Server responses carry half the
    # signal — errors, stack traces, leaked paths, PII, weak cookies — so scan
    # inbound bodies too (all inbound directions contain "Incoming"). Cap each rule
    # so one chatty endpoint cannot flood the findings list.
    _resp_caps = {}
    def _resp_ok(rule, limit=3):
        _resp_caps[rule] = _resp_caps.get(rule, 0) + 1
        return _resp_caps[rule] <= limit

    for pkt in tcp_packets:
        if "Incoming" not in (pkt.get("direction") or ""):
            continue
        body = (pkt.get("body") or "")[:1024]
        if not body:
            continue
        dest = pkt.get("dest", "unknown")

        # Verbose error / stack trace leak
        m = _RE_STACK.search(body)
        if m and _resp_ok("stack"):
            findings.append(_finding(
                "MEDIUM", "Verbose Error / Stack Trace in Response",
                "The server returned a framework stack trace or verbose error. These leak internal class "
                "names, file paths, component versions and query fragments that make further attacks easier.",
                evidence=f"From {dest}: {m.group(0)[:200]}",
                verification_steps=["Trigger the error deliberately with malformed input and capture the full trace.", "Record the leaked framework/version and file paths."],
                exploitation_notes="Fingerprint the stack from the trace; pair the leaked query/path with targeted injection.",
            ))

        # Database error message (corroborates SQL injection)
        m = _RE_DBERR.search(body)
        if m and _resp_ok("dberr"):
            findings.append(_finding(
                "HIGH", "Database Error Message in Response",
                "A raw database error was returned to the client. This confirms unsanitized input reaches the "
                "database and is a strong error-based SQL injection signal.",
                evidence=f"From {dest}: {m.group(0)[:200]}",
                verification_steps=["Correlate with the outgoing request that triggered it.", "Replay via the Repeater tab with SQL metacharacters and watch the error change."],
                exploitation_notes="Run sqlmap (error-based) against the identified endpoint.",
            ))

        # Insecure Set-Cookie flags on session/auth cookies
        for cm in _RE_SETCOOKIE.finditer(body):
            cookie = cm.group(1)
            name = cookie.split("=", 1)[0].strip()
            low = cookie.lower()
            if not _RE_SESSCOOKIE.search(name):
                continue
            missing = [flag for flag, kw in (("Secure", "secure"), ("HttpOnly", "httponly")) if kw not in low]
            if missing and _resp_ok("cookie"):
                findings.append(_finding(
                    "MEDIUM", "Insecure Session Cookie Flags",
                    f"Session/auth cookie '{name}' is set without {', '.join(missing)}. Missing Secure lets it "
                    "leak over any plaintext channel; missing HttpOnly exposes it to theft via XSS.",
                    evidence=f"From {dest}: {cookie[:180]}",
                    verification_steps=["Confirm the cookie carries the session/auth state.", "Check whether it is ever sent over a plaintext channel."],
                    exploitation_notes="Steal via XSS (no HttpOnly) or network capture (no Secure) and replay the session.",
                ))

        # Payment card data (Luhn-validated PAN) returned to the client
        for cardm in _RE_CARD.finditer(body):
            if _luhn_ok(cardm.group(0)) and _resp_ok("pan", 2):
                digits = "".join(c for c in cardm.group(0) if c.isdigit())
                masked = digits[:6] + "*" * max(0, len(digits) - 10) + digits[-4:]
                findings.append(_finding(
                    "HIGH", "Payment Card Data (PAN) in Response",
                    "A Luhn-valid primary account number was returned to the client. Card data in responses is "
                    "a PCI-DSS concern and often signals over-broad data exposure or broken object-level auth.",
                    evidence=f"From {dest}: {masked}",
                    verification_steps=["Confirm it is a live PAN, not test data.", "Check whether this endpoint should return card data at all, and for other users."],
                    exploitation_notes="Test broken object-level authorization — can another user's PAN be retrieved by changing an id?",
                ))
                break

        # Internal path / private IP disclosure
        pm = _RE_INTPATH.search(body)
        ipm = _RE_PRIVIP.search(body)
        if (pm or ipm) and _resp_ok("intdisc"):
            leak = pm.group(0) if pm else ipm.group(0)
            findings.append(_finding(
                "LOW", "Internal Path or Private IP Disclosed in Response",
                "The response exposes an internal filesystem path or private IP address, revealing server "
                "layout and network topology useful for traversal, SSRF and lateral movement.",
                evidence=f"From {dest}: {leak[:200]}",
                verification_steps=["Collect every disclosed path/host.", "Use them to refine traversal / SSRF / lateral-movement attempts."],
                exploitation_notes="Feed disclosed internal hosts into SSRF payloads; use paths as traversal targets.",
            ))

    # ── DLL Events ─────────────────────────────────────────────────────────────
    for e in dll_events:
        dll_name = (e.get("dllName") or e.get("target") or "").replace("/", "\\")
        dll_lower = dll_name.lower()
        base = dll_lower.split("\\")[-1]

        if _RE_DLL_UNC.match(dll_name):
            findings.append(_finding(
                "CRITICAL", "DLL Loaded via UNC Network Path",
                "A DLL was loaded from a UNC (\\\\server\\share) path. "
                "An attacker controlling the network share can serve a malicious DLL.",
                evidence=dll_name[:250],
                verification_steps=["Confirm the UNC path is reachable.", "Replace the DLL on the share with a PoC that spawns calc.exe."],
                exploitation_notes="Host a Responder server to intercept NTLM auth, or serve a malicious DLL directly.",
            ))
        elif _RE_DLL_PATH.search(dll_lower):
            findings.append(_finding(
                "HIGH", "DLL Loaded from User-Writable Directory",
                "A DLL was loaded from a user-writable location (Temp, AppData, etc.). "
                "A low-privileged attacker can plant a malicious DLL here before the application loads it.",
                evidence=dll_name[:250],
                verification_steps=["Verify the directory is writable by non-admin users.", "Place a test DLL (spawning calc.exe) and relaunch the application."],
                exploitation_notes="Drop malicious DLL before application launch for privilege escalation or persistence.",
            ))

        # Hijack risk only when a known-target DLL is loaded by BARE NAME — i.e.
        # resolved through the DLL search order, where a planted copy earlier in
        # the order wins. A full System32 path is the normal case (no finding);
        # a full user-writable / UNC path already has its own finding above, so
        # we don't double-report it here.
        if base in _HIJACK_DLLS and "\\" not in dll_name:
            findings.append(_finding(
                "MEDIUM", f"Known DLL Hijack Target Loaded: {base}",
                f"{base} is a commonly hijacked DLL and was loaded by bare name, so it resolves through "
                "the DLL search order — a planted copy earlier in the order would take precedence.",
                evidence=dll_name[:250],
                verification_steps=["Check DLL search order with Process Monitor.", "Place a same-named DLL in the application directory and observe loading."],
                exploitation_notes="Use ProcMon filter 'NAME NOT FOUND' for DLL loads to find hijack candidates.",
            ))

    # ── Registry Operations ────────────────────────────────────────────────────
    for e in registry_events:
        target = (e.get("target") or "")
        target_low = target.lower()

        if _RE_REG_LSA.search(target_low):
            findings.append(_finding(
                "CRITICAL", "LSA / SAM Registry Key Access Detected",
                "The process accessed the LSA or SAM registry hive — regions that store credential material. "
                "This may indicate credential dumping (mimikatz-style).",
                evidence=target[:250],
                verification_steps=["Cross-reference with process name.", "Check if LSASS memory was also read."],
                exploitation_notes="If running as SYSTEM, the SAM hive can be backed up to extract NTLM hashes offline.",
            ))
        elif _RE_REG_RUN.search(target_low):
            findings.append(_finding(
                "HIGH", "Persistence via AutoRun Registry Key",
                "Write access to a Run/RunOnce key detected. This is a classic persistence mechanism.",
                evidence=target[:250],
                verification_steps=["Check the key value that was written.", "Confirm it points to a file you can inspect."],
                exploitation_notes="Malware commonly abuses Run keys for persistence after reboot.",
            ))
        elif _RE_REG_SEC.search(target_low):
            findings.append(_finding(
                "HIGH", "Sensitive Keyword in Registry Key Path",
                "A registry key containing 'password', 'secret', 'token', or similar was accessed. "
                "Credentials stored in the registry are readable by any process running as the same user.",
                evidence=target[:250],
                verification_steps=["Read the key value with reg query.", "Determine if the stored data is cleartext."],
                exploitation_notes="reg query HKCU /f password /t REG_SZ /s",
            ))

    # ── File Operations ────────────────────────────────────────────────────────
    for e in file_events:
        target = (e.get("target") or "")
        api    = (e.get("api") or "").lower()

        if _RE_FILE_SENS.search(target):
            findings.append(_finding(
                "CRITICAL", "Access to Sensitive System File",
                "The process accessed a file known to contain credential or key material.",
                evidence=f"{e.get('api','?')} → {target[:200]}",
                verification_steps=["Verify the file was read (not just opened).", "Inspect what the process did with the data."],
                exploitation_notes="If reading SAM/NTDS.dit: copy to attacker machine and crack offline with secretsdump.",
            ))

        if _RE_FILE_SYS.search(target) and any(x in api for x in ("write", "createfile")):
            findings.append(_finding(
                "HIGH", "Write to System32 / SysWOW64 from User Process",
                "Writing to system directories from a non-OS process may indicate DLL planting or privilege escalation.",
                evidence=f"{e.get('api','?')} → {target[:200]}",
                verification_steps=["Confirm the written file type.", "Check if any service or privileged process loads it."],
                exploitation_notes="Plant a malicious DLL that matches a service's expected DLL name.",
            ))

    # ── Static + Memory Strings ────────────────────────────────────────────────
    seen = set()
    for s in (list(static_strings) + list(memory_strings)):
        val = (s.get("val") or "").strip()
        if not val or len(val) < 5:
            continue

        m = _RE_STR_CRED.search(val)
        if m and "hardcoded_cred" not in seen:
            seen.add("hardcoded_cred")
            findings.append(_finding(
                "CRITICAL", "Hardcoded Credential Found in Binary / Memory",
                "A plaintext credential was found embedded in the binary or process memory.",
                evidence=val[:300],
                verification_steps=["Confirm the string is a real credential by attempting authentication.", "Search the entire binary for similar patterns."],
                exploitation_notes="Use the credential directly or search for reuse across other services.",
            ))

        if _RE_PRIVKEY.search(val) and "private_key" not in seen:
            seen.add("private_key")
            findings.append(_finding(
                "CRITICAL", "Private Key String Embedded in Binary / Memory",
                "A PEM private key was found in the process. If extracted, an attacker can impersonate the owner.",
                evidence=val[:200],
                verification_steps=["Extract the full key block.", "Attempt to load it and sign test data."],
                exploitation_notes="openssl rsa -in key.pem -check",
            ))

        m = _RE_CONNSTR.search(val)
        if m and "connstr" not in seen:
            seen.add("connstr")
            findings.append(_finding(
                "HIGH", "Database Connection String with Credentials",
                "A database connection string containing inline credentials was found.",
                evidence=val[:300],
                verification_steps=["Extract host, username, and password from the string.", "Attempt a direct database connection."],
                exploitation_notes="Use the extracted credentials with sqlcmd, psql, or the appropriate client.",
            ))

        if _RE_WEAKCRYP.search(val):
            findings.append(_finding(
                "MEDIUM", f"Weak Cryptographic Algorithm Reference",
                "A string referencing a broken/deprecated algorithm (MD5, DES, RC4, 3DES) was found.",
                evidence=val[:100],
                verification_steps=["Locate the call site in the binary.", "Confirm it is used for security-sensitive operations (not checksums)."],
                exploitation_notes="Brute-force or use precomputed rainbow tables against MD5/DES ciphertexts.",
            ))

        if _RE_HEXKEY.match(val) and "hexkey" not in seen:
            seen.add("hexkey")
            findings.append(_finding(
                "MEDIUM", "Possible Hardcoded Cryptographic Key (Hex String)",
                f"A {len(val)//2}-byte hex string was found. Length matches AES-128/192/256 key sizes.",
                evidence=val[:64],
                verification_steps=["Context-search the binary around this string.", "Check if used as AES/DES key material."],
                exploitation_notes="If confirmed as a static key, decrypt all ciphertexts that use this key.",
            ))

    # Collapse duplicates that repeat across packets/events (same title+evidence),
    # e.g. the same JWT or credential seen on 50 keep-alive requests.
    _uniq, _seen = [], set()
    for f in findings:
        key = (f.get("title"), f.get("evidence"))
        if key in _seen:
            continue
        _seen.add(key)
        _uniq.append(f)
    findings = _uniq

    if not findings:
        findings.append(_finding(
            "INFO", "No Rule-Based Findings",
            "No rule violations were detected in the captured session data. "
            "Collect more traffic (longer hook session, more HTTP requests) and retry.",
        ))

    _lolbin_rules(process_events, findings)   # LOLBin / command-injection over captured spawns

    findings.sort(key=lambda x: _SEV_ORDER.get(x.get("severity", "INFO"), 4))
    return findings


@app.post("/api/rule_scan")
async def rule_scan(request: Request):
    """Run deterministic rule-based vulnerability scan — no AI required."""
    try:
        data = await request.json()
        await broadcast_message({"type": "vuln_analysis_log", "message": "Rule-based scan started..."})

        findings = await asyncio.to_thread(run_rule_scan, data)

        merged = _set_vuln_source("rule", findings)   # merge into the shared store
        await broadcast_message({"type": "vuln_analysis_log", "message": f"Rule scan complete — {len(findings)} finding(s)."})
        await broadcast_message({"type": "vuln_findings", "findings": merged})
        return {"status": "ok", "count": len(findings)}
    except Exception as exc:
        logger.exception("[RULE_SCAN] Error")
        await broadcast_message({"type": "vuln_analysis_log", "message": f"Rule scan error: {exc}"})
        return {"status": "error", "error": str(exc)}


_URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.I)
_IP_RE  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_HTTP_VERBS = ("GET ", "POST ", "PUT ", "DELETE", "PATCH", "HEAD ", "OPTIONS", "HTTP/")


def _decode_packet_line(p: dict) -> str:
    """One concise, decoded line per packet: protocol-aware, not raw repr()."""
    head = f"[{p.get('direction','?')}] {p.get('dest','?')} {p.get('size',0)}B"
    body = p.get("body") or ""
    hexs = (p.get("body_hex") or "").replace(" ", "")
    if hexs:                                  # deserialization at payload / HTTP-body start
        h = hexs[:65536]
        if len(h) % 2:
            h = h[:-1]
        try:
            raw = bytes.fromhex(h)
        except ValueError:
            raw = b""
        fmt, _off = _detect_deser(raw)
        if fmt:
            head += f" !DESERIALIZATION:{fmt}"
    bs = body.lstrip()
    if bs[:8].upper().startswith(_HTTP_VERBS):
        lines = bs.splitlines()
        host = next((ln.split(":", 1)[1].strip() for ln in lines if ln.lower().startswith("host:")), "")
        head += f" HTTP: {lines[0][:120]}" + (f"  Host={host}" if host else "")
        if _RE_SQLI.search(body):
            head += " !SQLi-in-body"
        return head
    printable = sum(1 for c in body if 32 <= ord(c) < 127)
    if body and printable / max(1, len(body)) > 0.85:
        if _RE_SQLI.search(body):
            head += " !SQLi-in-body"
        return head + " text=" + body[:200].replace("\n", "\\n")
    return head + " hex=" + hexs[:48] + ("..." if len(hexs) > 48 else "")


def _curate_strings(strings: list) -> dict:
    """Keep only security-interesting strings, categorised; count the rest as noise."""
    cats = [
        ("private-key", _RE_PRIVKEY), ("connection-string", _RE_CONNSTR),
        ("credential", _RE_STR_CRED), ("jwt", _RE_JWT), ("basic-auth", _RE_BASIC),
        ("weak-crypto", _RE_WEAKCRYP), ("possible-aes-key", _RE_HEXKEY),
    ]
    prio = {"private-key": 0, "connection-string": 1, "credential": 2, "jwt": 3,
            "basic-auth": 4, "possible-aes-key": 5, "weak-crypto": 6, "url": 7, "ip": 8}
    items, omitted, seen = [], 0, set()
    for s in strings:
        val = (s.get("val") or "").strip()
        if len(val) < 5:
            continue
        cat = next((name for name, rgx in cats if rgx.search(val)), None)
        if not cat:
            if _URL_RE.search(val):
                cat = "url"
            elif _IP_RE.search(val):
                cat = "ip"
        if cat:
            if val in seen:
                continue
            seen.add(val)
            items.append((cat, val))
        else:
            omitted += 1
    items.sort(key=lambda kv: prio.get(kv[0], 9))
    return {"items": items, "omitted": omitted}


def _build_capture_text(data: dict) -> str:
    """Build an LLM-optimised analysis context: a structured, de-noised, decoded
    view that leads with deterministic findings so the AI corroborates and
    expands rather than starting cold and drowning in raw strings."""
    tcp   = data.get("tcp_packets", [])
    dll   = data.get("dll_events", [])
    reg   = data.get("registry_events", [])
    files = data.get("file_events", [])
    mem   = data.get("memory_strings", [])
    stat  = data.get("static_strings", [])

    out = ["# SAFIYE RUNTIME CAPTURE — AI ANALYSIS CONTEXT",
           f"Counts: {len(tcp)} packets | {len(dll)} DLL | "
           f"{len(reg)} registry | {len(files)} file | {len(mem)} mem strings | {len(stat)} static strings"]

    # Deterministic pre-analysis as hints (highest-value addition).
    try:
        hints = [h for h in run_rule_scan(data) if h.get("severity") != "INFO"]
    except Exception:
        hints = []
    if hints:
        out.append("\n## Automated pre-analysis (deterministic rule scan)")
        out.append("These were flagged by Safiye's own rules. Confirm, deduplicate, and EXPAND on them; "
                   "look for issues the rules cannot catch. Do not simply repeat them.")
        for h in hints[:25]:
            out.append(f"  [{h.get('severity')}] {h.get('title')} :: {(h.get('evidence') or '')[:160]}")

    if tcp:
        out.append("\n## Network traffic (decoded, deduplicated)")
        seen, shown = set(), 0
        for p in tcp:
            key = (p.get("direction"), p.get("dest"), (p.get("body") or "")[:120], (p.get("body_hex") or "")[:40])
            if key in seen:
                continue
            seen.add(key)
            if shown >= 40:
                out.append(f"  (+{len(tcp) - shown} more / duplicate packets omitted)")
                break
            shown += 1
            out.append("  " + _decode_packet_line(p))

    fails = []
    seen_dll = set()
    for e in dll:
        if e.get("isFailed") or "NOT FOUND" in str(e.get("status", "")):
            t = e.get("dllName", e.get("target", "?"))
            if t in seen_dll:
                continue
            seen_dll.add(t)
            fails.append(f"  {e.get('api','?')} -> {t} [{e.get('status','?')}]")
    if fails:
        out.append("\n## DLL load failures (possible hijack candidates)")
        out.extend(fails[:40])

    sens_reg = [e for e in reg if _RE_REG_SEC.search(str(e.get("target", "")))
                or _RE_REG_RUN.search(str(e.get("target", ""))) or _RE_REG_LSA.search(str(e.get("target", "")))]
    if sens_reg:
        out.append("\n## Sensitive registry operations")
        for e in sens_reg[:30]:
            out.append(f"  {e.get('api','?')} -> {e.get('target','?')} [{e.get('status','?')}]")

    sens_file = [e for e in files if _RE_FILE_SENS.search(str(e.get("target", "")))]
    if sens_file:
        out.append("\n## Sensitive file operations")
        for e in sens_file[:30]:
            out.append(f"  {e.get('api','?')} -> {e.get('target','?')}")

    curated = _curate_strings(list(stat) + list(mem))
    if curated["items"]:
        out.append(f"\n## Interesting strings (curated; {curated['omitted']} noise strings omitted)")
        for cat, val in curated["items"][:60]:
            out.append(f"  [{cat}] {val[:200]}")
    elif (stat or mem):
        out.append(f"\n## Strings: {curated['omitted']} captured, none matched secret/URL/IP patterns.")

    return "\n".join(out) if len(out) > 2 else "No data captured yet."


@app.post("/api/analyze_vulnerabilities")
async def analyze_vulnerabilities(request: Request):
    """Queue capture data for MCP-based AI analysis."""
    try:
        data = await request.json()
        captured = _build_capture_text(data)
        state.pending_analysis_data = {"raw": data, "formatted": captured, "queued_at": time.time()}

        age = time.time() - state.mcp_last_seen if state.mcp_last_seen else None
        mcp_connected = age is not None and age < 120

        await broadcast_message({"type": "vuln_analysis_log",
                                  "message": f"Capture data queued ({len(captured):,} chars)."})

        if not mcp_connected:
            await broadcast_message({"type": "vuln_analysis_log",
                                      "message": "MCP not connected — click 'Analyze with AI' and follow the setup steps."})

        return {"status": "queued", "chars": len(captured)}

    except Exception as exc:
        logger.exception("[ANALYZE] Queue error")
        await broadcast_message({"type": "vuln_analysis_log", "message": f"Error queuing data: {exc}"})
        return {"status": "error", "error": str(exc)}


@app.get("/api/config")
async def get_config():
    cfg = _load_config()
    return {"api_key_set": bool(cfg.get("api_key"))}


@app.post("/api/config")
async def save_config(request: Request):
    try:
        body = await request.json()
        api_key = body.get("api_key", "").strip()
        if not api_key:
            return {"status": "error", "error": "Empty key"}
        cfg = _load_config()
        cfg["api_key"] = api_key
        _save_config(cfg)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/mcp_log")
async def mcp_log(request: Request):
    """Receives progress log messages from the MCP server and broadcasts them to the UI."""
    try:
        body = await request.json()
        msg = body.get("message", "").strip()
        if msg:
            await broadcast_message({"type": "vuln_analysis_log", "message": f"[AI] {msg}"})
        return {"status": "ok"}
    except Exception:
        return {"status": "error"}


@app.get("/api/pending_analysis")
async def get_pending_analysis():
    """
    Returns the queued capture data + analysis instructions for the connected AI.
    Called by the MCP server's get_capture_data tool.
    """
    state.mcp_last_seen = time.time()
    if not state.pending_analysis_data:
        return {
            "available": False,
            "message": "No analysis pending. Click 'Analyze with AI' in Safiye first.",
        }

    age = round(time.time() - state.pending_analysis_data["queued_at"])
    formatted = state.pending_analysis_data["formatted"]

    raw        = state.pending_analysis_data.get("raw", {})
    tcp_count  = len(raw.get("tcp_packets", []))
    dll_count  = len(raw.get("dll_events", []))
    reg_count  = len(raw.get("registry_events", []))
    file_count = len(raw.get("file_events", []))
    mem_count  = len(raw.get("memory_strings", []))
    str_count  = len(raw.get("static_strings", []))

    instruction = (
        "You are an expert penetration tester and runtime security analyst.\n"
        "The following data was captured by Safiye, a Windows runtime instrumentation tool (Frida-based).\n\n"
        "PROGRESS REPORTING — IMPORTANT:\n"
        "Throughout your analysis, call the log_progress tool to report what you are doing.\n"
        "Call it at the START of each section and whenever you find something notable.\n"
        "Use plain text with no emojis and no markdown. Include counts. Examples:\n"
        f"  log_progress('Starting network traffic analysis — {tcp_count} packets')\n"
        f"  log_progress('Checking DLL load events for hijacking candidates — {dll_count} events')\n"
        f"  log_progress('Reviewing registry operations — {reg_count} events')\n"
        f"  log_progress('Scanning file operations — {file_count} events')\n"
        f"  log_progress('Analyzing {mem_count} memory strings and {str_count} static strings')\n"
        "  log_progress('Found 2 critical issues, preparing final report')\n"
        "  log_progress('Compiling all findings, calling submit_findings now')\n\n"
        "VULNERABILITIES TO LOOK FOR:\n"
        "- Insecure deserialization (magic bytes: Java 0xACED, .NET BinaryFormatter, Python Pickle, PHP O:)\n"
        "- DLL hijacking (user-writable paths, UNC paths, known hijack targets)\n"
        "- Cleartext credentials or API keys in traffic or memory\n"
        "- SQL injection patterns in HTTP bodies\n"
        "- Weak cryptography (MD5, DES, RC4, hardcoded keys)\n"
        "- Sensitive file/registry access (SAM, LSA, AutoRun keys)\n"
        "- Private keys or connection strings in binary/memory strings\n\n"
        "When done, call submit_findings with a JSON array. Each item must have:\n"
        "  severity: CRITICAL | HIGH | MEDIUM | LOW | INFO\n"
        "  title: short specific title\n"
        "  description: why it is a vulnerability and its impact\n"
        "  evidence: exact snippet from the captured data\n"
        "  verification_steps: list of steps to confirm\n"
        "  exploitation_notes: how a pentester would exploit this\n\n"
        f"=== CAPTURED RUNTIME DATA (queued {age}s ago, "
        f"{tcp_count} packets / {dll_count} DLL / {reg_count} reg / {file_count} file / {mem_count} mem strings) ===\n\n"
        f"{formatted}"
    )

    await broadcast_message({
        "type": "vuln_analysis_log",
        "message": f"AI connected — retrieved {len(formatted):,} chars of capture data. Analysis underway..."
    })
    return {"available": True, "instruction": instruction, "chars": len(formatted)}


@app.post("/api/submit_findings")
async def submit_findings(request: Request):
    """Receives the AI's structured vulnerability findings and broadcasts them to the UI."""
    state.mcp_last_seen = time.time()
    try:
        body = await request.json()
        findings = body if isinstance(body, list) else body.get("findings", [])
        if not isinstance(findings, list):
            return {"status": "error", "error": "Expected a JSON array of findings."}

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: sev_order.get(x.get("severity", "INFO"), 4))

        await broadcast_message({
            "type": "vuln_analysis_log",
            "message": f"Receiving {len(findings)} finding(s) from AI — applying to Vulnerabilities tab..."
        })

        merged = _set_vuln_source("ai", findings)   # merge into the shared store
        state.pending_analysis_data = None  # clear queue after submission
        await broadcast_message({"type": "vuln_analysis_log", "message": f"AI analysis received — {len(findings)} finding(s)."})
        await broadcast_message({"type": "vuln_findings", "findings": merged})
        logger.info(f"[SUBMIT_FINDINGS] {len(findings)} findings received from AI.")
        return {"status": "ok", "count": len(findings)}

    except Exception as exc:
        logger.exception("[SUBMIT_FINDINGS] Error")
        return {"status": "error", "error": str(exc)}


@app.get("/api/export_session")
async def export_session():
    """Export full session state as a JSON snapshot (downloaded by the browser)."""
    from datetime import datetime
    return {
        "version": 1,
        "saved_at": datetime.now().isoformat(),
        "session_events":   state.session_events,
        "session_snapshot": state.session_snapshot,
        "vuln_findings":    state.last_vuln_analysis or [],
    }


@app.post("/api/import_session")
async def import_session(request: Request):
    """Restore a previously exported session snapshot."""
    try:
        data = await request.json()
        if data.get("version") != 1:
            return {"status": "error", "error": "Unsupported session file version."}

        state.session_events   = data.get("session_events", [])
        state.session_snapshot = data.get("session_snapshot", {})
        findings = data.get("vuln_findings") or []
        state.vuln_sources = {}                       # a restored session replaces the whole view
        state.last_vuln_analysis = _set_vuln_source("import", findings) if findings else None
        state.pending_analysis_data = None

        # Notify all connected clients to reload
        await broadcast_message({"type": "session_cleared"})
        if state.session_events:
            await broadcast_message({"type": "session_replay", "events": state.session_events})
        for snap in state.session_snapshot.values():
            await broadcast_message(snap)
        if state.last_vuln_analysis:
            await broadcast_message({"type": "vuln_findings", "findings": state.last_vuln_analysis})

        logger.info(f"[IMPORT_SESSION] Restored {len(state.session_events)} events, {len(findings)} findings.")
        return {"status": "ok", "events": len(state.session_events), "findings": len(findings)}
    except Exception as exc:
        logger.exception("[IMPORT_SESSION] Error")
        return {"status": "error", "error": str(exc)}


@app.post("/api/new_session")
async def new_session():
    """Clear all captured session data and start fresh."""
    state.session_events.clear()
    state.session_snapshot.clear()
    state.last_vuln_analysis = None
    state.vuln_sources = {}
    state.memcred_before_fps = None
    state.pending_analysis_data = None
    await broadcast_message({"type": "session_cleared"})
    logger.info("[NEW_SESSION] Session cleared by user request.")
    return {"status": "ok"}


if __name__ == "__main__":
    logger.info(f"Safiye starting on http://{SAFIYE_HOST}:{SAFIYE_PORT}  "
                f"(auth: per-session token{'' if _HOST_CHECK else ', host-check relaxed'}; "
                f"open the URL in a browser — the token is injected automatically). "
                f"Set SAFIYE_HOST=0.0.0.0 for remote access (opt-in).")
    uvicorn.run(app, host=SAFIYE_HOST, port=SAFIYE_PORT)
