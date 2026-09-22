<p align="center">
  <img src="assets/safiye-readme-banner.png" alt="Safiye, the green-eyed calico mascot, stretching out beside a laptop" width="100%">
</p>

<p align="center">
  Runtime security analysis for Windows desktop apps, with live traffic, runtime monitors, and AI-assisted findings.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.10%20to%203.12-brightgreen.svg" alt="Python">
  <img src="https://img.shields.io/badge/frida-16.6.4-orange.svg" alt="Frida">
  <img src="https://img.shields.io/badge/platform-Windows-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/AI-MCP%20native-9b59b6.svg" alt="MCP">
</p>

# Safiye

Safiye is a runtime security analysis tool for Windows thick-client (desktop) applications. It injects a [Frida](https://frida.re) agent into the target process and shows what it sees (network traffic, files, registry, DLLs, memory, IPC) in a browser UI, so you don't need a traditional debugger. It also speaks the Model Context Protocol (MCP), which lets an AI assistant read the captured data and write findings back into the tool.

<p align="center">
  <img src="assets/screenshots/workspace-03-history.png" alt="A running SafiyeReadmeDemo session with loopback HTTP traffic and the side-by-side payload inspector" width="100%">
  <br><em>Live session context, grouped navigation, and a resizable traffic inspector.</em>
</p>

---

## Features

- **Focused workspace.** Graphite theme, tools grouped under Traffic / Runtime / Findings, a dedicated Session setup dialog, and a persistent target / PID / recording-status bar. Switch between stacked and side-by-side traffic inspection, resize the inspector, collapse the console, and reduce motion.
- **Finding review.** A list-and-detail view keeps evidence next to each finding. Track review status independently of severity and preserve those decisions with Save session / Load session.
- **Spawn or attach.** Launch the target and hook it from the first instruction, or attach to a process that is already running by PID or name.
- **Network capture.** Hooks `ws2_32` (`send`, `recv`, `WSASend`, `WSARecv`, `connect`), the AFD NT layer, OpenSSL, and SChannel/SSPI (`EncryptMessage`/`DecryptMessage`, so .NET `SslStream`, WinHTTP and LDAPS plaintext is captured before encryption), and de-duplicates the result.
- **Intercept and Trap.** Hold outgoing packets, edit them in UTF-8 or HEX, then forward or drop them. You can also inject your own responses.
- **Repeater.** Replay any packet. There are two send modes:
  - *Send (new TCP)* opens a fresh connection to the target and replays the bytes, so it works even after the original socket has closed.
  - *Send (live socket)* injects into the original connection while it is still open.
  - *Load payload file* imports a raw blob (for example a serialized deserialization payload) and sends it over the wire as HEX.
- **Runtime monitors.** Registry, file system, and DLL load events. Failed loads on writable paths are flagged as hijack candidates.
- **Memory and Strings.** Dump readable memory and pull live strings, and scan the binary for hardcoded secrets.
- **Named pipes.** Enumerate Windows named pipes and read each pipe's DACL — a NULL DACL or one that lets a low-privileged principal write / create instances (a classic local-privesc path scanners miss) is flagged, and you can connect and send/fuzz from the UI.
- **PE protection analysis.** Read each module's PE header for exploit-mitigation flags (ASLR, DEP/NX, CFG, SEH) and verify its Authenticode signature — both embedded and **catalog** signed — so unprotected or genuinely unsigned application binaries stand out. .NET assemblies are scored as managed (native-flag gaps are not treated as high-risk).
- **COM/DCOM and RPC enumeration.** List the local RPC endpoint mapper (network-reachable `ncacn_ip_tcp` interfaces are highlighted) and analyze every DCOM AppID's Launch/Access permission, flagging the ones that let a low-privileged principal **remotely** activate/launch (the DCOM lateral-movement class); local-only rights are treated as normal.
- **Local privilege-escalation checks.** DLL-hijack candidates, unquoted service paths, writable install-directory / service ACLs, and insecure (HTTP / unsigned) update mechanisms.
- **Managed Secret Scanner.** Load a .NET assembly with reflection in a short-lived helper and read its static string/`byte[]`/`char[]` members, flagging embedded crypto keys/IVs, passphrases, connection strings and tokens. Values are masked (length + SHA-256) unless you explicitly reveal them.
- **Active TLS probe.** Connect to an operator-supplied, authorized endpoint and report its certificate posture — self-signed, expired, hostname mismatch, untrusted root, or weak protocol/signature — along with the negotiated protocol and cipher. Outbound only to the host:port you enter; it never auto-connects anywhere.
- **Crypto capture.** Hooks the Windows crypto stack — DPAPI (`CryptProtectData`/`CryptUnprotectData`), CNG/BCrypt, and legacy CryptoAPI — to reveal application-layer plaintext before it is encrypted and secrets after they are decrypted, data that never appears on the wire in cleartext. Insecure DPAPI scope (`LOCAL_MACHINE`) and credential-like recovered plaintext are flagged.
- **Function Faker.** Force any function's return value at runtime, or just trace its calls — point it at a module and export (or a module+offset) and, for example, make `IsLicenseValid` return `1` or `IsDebuggerPresent` return `0`. Live license, auth, and anti-debug bypass without patching the binary; every call is logged with its original and forced return.
- **Vulnerability detection.** Insecure deserialization (Java, .NET, Python pickle, PHP — anchored, full-signature matching so random/TLS bytes don't false-positive), DLL hijacking, SQL-injection and LOLBin / command-injection patterns in outgoing bodies, plus **response-side** checks on decrypted inbound traffic — framework stack traces, database error messages, insecure session-cookie flags, Luhn-validated card data (masked), and internal path / private-IP disclosure. The rule scanner is deterministic and needs no AI. Every detector (rules, AI, PE, pipe-DACL, DCOM, TLS, privesc, secrets) writes into one source-keyed store, so findings from different scanners merge in the Vulnerabilities tab instead of overwriting each other.
- **AI analysis (MCP).** Claude, or any MCP client, can read a cleaned-up, decoded view of the capture and submit findings back into the Vulnerabilities tab.
- **Local-only by default.** The server binds to `127.0.0.1` and gates its `/api` and WebSocket endpoints behind a per-session token (auto-injected into the UI) with a Host/Origin allowlist. Remote access is opt-in — bind with `SAFIYE_HOST=0.0.0.0` and allowlist the host via `SAFIYE_ALLOWED_HOSTS`.

> The project is named after my cat, Safiye. The welcome illustration is based on her calico markings. The walking mascot is currently shelved; its source and artwork are preserved.

---

## Screenshots

These are real UI captures from **SafiyeReadmeDemo.exe**, a local documentation target launched through **Session setup → Start Spawn**. Its traffic stays on `127.0.0.1`; the embedded `DEMO_ONLY_NOT_A_REAL_PASSWORD` value is an inert test fixture, not a working credential. No external application was tested and no exploit was run.

The findings shown are actual outputs of the rule and PE scanners on this sample, **not verified vulnerabilities**. For example, a dummy password string can receive a high severity label even though it cannot authenticate anywhere. The local demo environment, test sources, compiled executables, and raw session dumps are not included in the repository.

<p align="center">
  <img src="assets/screenshots/workspace-06-findings.png" alt="All findings with a demo-only hardcoded credential selected, its evidence, and In review status" width="100%">
  <br><em>All findings: severity filters, evidence, and a separate review decision. This capture uses local rule analysis, not AI.</em>
</p>

<details>
<summary>Session setup, static strings, and DLL events</summary>

<p align="center">
  <img src="assets/screenshots/workspace-02-session.png" alt="Session setup dialog configured to launch the local documentation demo" width="100%">
  <br><em>Session setup keeps target selection and script configuration out of the main workspace.</em>
</p>

<p align="center">
  <img src="assets/screenshots/workspace-04-strings.png" alt="Static strings extracted from the demo executable, including an explicitly fake password fixture" width="100%">
  <br><em>Strings: inspect the executable's embedded text without a memory dump.</em>
</p>

<p align="center">
  <img src="assets/screenshots/workspace-05-modules.png" alt="DLL and Modules showing actual Windows library load and file-access events from the demo process" width="100%">
  <br><em>DLL &amp; Modules: runtime load events and a separate PE protection scan.</em>
</p>

</details>

The module event table is not a complete inventory of already-loaded DLLs. It shows observed load/file-access events; a failed lookup or a DLL name match alone does not prove a hijacking vulnerability.

---

## Architecture

<p align="center">
  <img src="assets/architecture.png" alt="Architecture: the Frida agent sends events to the Safiye server, which connects to the browser UI and an optional AI assistant through the MCP server" width="100%">
</p>

The Frida agent inside the target streams events to the Safiye server (FastAPI with a WebSocket hub), which pushes them live to the browser UI. For AI analysis, a separate MCP server bridges Claude to the server's REST API.

---

## Installation

### Requirements

- Windows 10 or 11 (x64)
- Python 3.10 to 3.12 (the pinned `frida==16.6.4` has no wheels for 3.13+)
- Administrator privileges, since Frida needs them to spawn, attach, and hook

### Setup

```bash
git clone https://github.com/ErenCanOzmn/SafiyeMonitor.git
cd SafiyeMonitor
pip install -r requirements.txt
python src/safiye_server_prod.py
```

Then open http://localhost:5000 in your browser. Run the terminal as Administrator, otherwise hooking fails with "failed to start hook".

---

## Usage

1. **Target.** Open **Session setup** in the top bar. Enter the target `.exe`, or select **PID Attach** for an existing process. Keep `hooks/safiye_frida_script.js` as the default script, then click **Start Spawn** or **Attach to PID**. The top bar shows the active target, PID, connection state and elapsed time.
2. **Watch traffic.** Outgoing and incoming packets show up in **History** in real time. Click one to inspect the raw payload (UTF-8 or HEX).
3. **Intercept.** Flip the Trap toggle to hold packets, edit them, then forward or drop.
4. **Repeat.** Right-click a packet, choose **Send to Repeater**, tweak it, and replay with **Send (new TCP)**.
5. **Review.** Tools are grouped under **Traffic**, **Runtime**, and **Findings** in the left navigation. Open **All findings** to inspect results and their evidence. Review status is separate from severity.
6. **Save.** Use **Save session** to export captured data and your finding review decisions to JSON; **Load session** restores them. Unsaved review decisions are local to the open page.

The History inspector supports stacked and side-by-side layouts. Drag its divider, or focus it and use the arrow keys, to resize it. The console can be collapsed. Layout, console visibility and **Reduce motion** preferences are saved in this browser. Reduced motion also respects the operating system preference until you choose an override.

---

## AI Analysis (MCP)

Safiye ships an MCP server that connects an AI assistant to live capture data.

| Tool | Description |
|---|---|
| `get_session_status` | Hook state, target info, packet counts |
| `get_capture_data` | The cleaned-up, decoded capture context for analysis |
| `get_vulnerability_report` | Current findings in the Vulnerabilities tab |
| `submit_findings` | Write AI-generated findings back into the UI |
| `log_progress` | Append a line to the System Output Log |

Register the MCP server with your Claude Code config (or `claude mcp add`):

```json
{
  "mcpServers": {
    "safiye": {
      "command": "python",
      "args": ["C:/path/to/SafiyeMonitor/src/mcp_server.py"]
    }
  }
}
```

With a process hooked, ask the assistant to analyze the capture. It calls `get_capture_data`, reasons over the cleaned-up context (which leads with the deterministic rule-scan findings as hints), and calls `submit_findings` to fill the Vulnerabilities tab. No API key or external service is needed when you run through Claude Code locally.

> Optional: the **Analyze with AI** button can also call the Anthropic API directly. To use it, set the `ANTHROPIC_API_KEY` environment variable, or copy `safiye_config.example.json` to `safiye_config.json` and add your key there (that file is gitignored). The MCP workflow above needs neither.

---

## Project structure

```
src/
  safiye_server_prod.py   FastAPI backend, WebSocket hub, Frida session manager
  mcp_server.py           MCP stdio bridge for AI integration
  templates/index.html    Single-page UI
  static/js/app.js        Frontend logic and WebSocket client
  static/js/workspace.js  Navigation, session UI, panels and finding review
  static/js/catwalk.js    Shelved walking mascot (not loaded by the UI)
  static/css/style.css    UI stylesheet
  static/css/workspace.css Workspace theme and responsive layout
hooks/
  safiye_frida_script.js  Frida instrumentation injected into the target
assets/screenshots/      README screenshots of the current workspace
requirements.txt
```

---

## Disclaimer

Safiye is for authorized security testing, CTF, and research only. Only use it against applications and systems you have explicit permission to test. The author is not responsible for misuse.

## License

MIT
