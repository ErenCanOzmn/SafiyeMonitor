# Safiye — Thick Client Pentest & Runtime Analysis Platform

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)
![Frida](https://img.shields.io/badge/Frida-16.0%2B-orange.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)

Safiye is an all-in-one runtime security analysis platform for thick client applications on Windows. It combines Frida-based dynamic instrumentation with a browser-based interface, giving security researchers live visibility into network traffic, memory, system calls, and database queries — with no need for a traditional debugger.

---

## Features

### Process Targeting

- **Spawn mode:** Safiye launches the target executable and hooks it from the first instruction, capturing everything from startup.
- **Attach mode:** Attach to a running process by PID or process name at any time during execution.

---

### Network Traffic — History Tab

Every outgoing and incoming packet captured by the Frida hooks appears in the History tab in real time.

- Hooks `ws2_32.dll` (`send`, `recv`, `WSASend`, `WSARecv`) and the AFD NT layer.
- Displays destination IP and port, payload size, and direction for every packet.
- Raw payload is available for inspection per packet.
- Packets can be sent to the Repeater for replay or saved to session history.
- Session history can be exported to a file and reloaded in a later session.

---

### Intercept & Trap Mode

Enables man-in-the-middle interception of outgoing packets at the socket level.

- When active, each outgoing packet is held and presented in the UI before it is sent.
- The researcher can inspect the raw payload, modify it in-place, and then forward or drop the packet.
- Modified bytes are written back into the original buffer so the application is unaware of the change.
- Injected recv responses can be queued so the application receives a fully synthetic server response.

---

### Repeater Tab

Replay any captured packet with modifications.

- Load any packet from History into the Repeater.
- Edit headers, body, or destination before sending.
- View the server response alongside the original for comparison.

---

### DNS Monitor

- Captures all DNS resolution calls made by the hooked process.
- Displays queried hostnames and resolved addresses in real time.
- Useful for discovering hidden endpoints, analytics calls, and license server lookups.

---

### Registry Monitor

- Hooks `RegOpenKeyEx`, `RegCreateKeyEx`, and `RegSetValueEx` at both the Win32 and NT (`NtSetValueKey`) layers.
- Records every registry key read, created, or written by the process.
- Highlights keys outside of standard Microsoft namespaces as potentially interesting.

---

### File System Monitor

- Hooks `CreateFileW` to capture every file open attempt.
- Flags sensitive extensions: `.config`, `.json`, `.ini`, `.db`, `.sqlite`, `.log`, `.dll`.
- Useful for finding configuration files, credential stores, and DLL load paths.

---

### DLL Monitor

- Tracks every `LoadLibrary` call (`LoadLibraryA`, `LoadLibraryW`, `LoadLibraryExA`, `LoadLibraryExW`).
- Distinguishes successful loads from "Name Not Found" failures.
- Failed loads on writable paths indicate DLL hijacking vectors for local privilege escalation.

---

### Memory Analysis — Memory Tab

- Dumps all readable memory regions of the running process on demand.
- Extracts printable ASCII strings longer than a configurable threshold.
- Useful for finding credentials, tokens, and configuration values that only appear in memory at runtime.

---

### Static String Analysis — Strings Tab

- Scans binary and readable sections for hardcoded strings.
- Applies pattern matching to identify API keys, passwords, connection strings, private keys, and IP addresses.
- Results are categorized by type and can be exported to CSV.

---

### SQL Monitor Tab

- Hooks SQLite calls at the native level via `winsqlite3.dll` exports (`sqlite3_exec`, `sqlite3_prepare_v2`, `sqlite3_prepare16_v2`).
- Covers both dynamically loaded SQLite DLLs and statically linked copies detected by scanning process modules.
- Captures ODBC calls (`SQLExecDirectW/A`, `SQLPrepareW/A`) from `odbc32.dll` and SQL Server native client variants.
- Each intercepted query is displayed with its type (SELECT, INSERT, UPDATE, DELETE, DDL), driver, API function, and execution status.
- Queries matching SQL injection patterns (UNION SELECT, OR 1=1, DROP TABLE, stacked statements, xp_cmdshell) are automatically flagged and highlighted.
- Filter by query type, driver, or free-text search. Results exportable to CSV.
- Note: ODBC/TDS/SNI capture for encrypted SQL Server connections is under active development.

---

### Named Pipes — Pipelist Tab

- Lists all active Windows named pipes on the system on demand.
- Displays full pipe paths (`\\.\pipe\<name>`).
- Useful for identifying inter-process communication channels, privilege escalation paths (e.g. token impersonation via named pipe servers), and hidden service endpoints.

---

### Vulnerability Detection Engine

Runs automatically in the background while hooking is active. Findings appear in the Vulnerabilities tab.

- **Insecure Deserialization:** Detects Java, Python Pickle (v2/v3/v4), .NET BinaryFormatter, and PHP serialized object magic bytes in live network traffic.
- **DLL Hijacking:** Flags failed DLL loads on attacker-writable paths as exploitable hijack vectors.
- **SQL Injection:** Identifies injection patterns in intercepted SQL queries.
- A rule-based scanner can also be run manually against accumulated traffic data.

---

## AI-Powered Analysis — MCP Integration

Safiye includes a Model Context Protocol (MCP) server that connects an AI assistant directly to live pentest data inside the tool.

### What MCP enables

Claude (or any MCP-compatible AI) can call Safiye's MCP tools to read captured data, analyze it for vulnerabilities, and write findings back into the Vulnerabilities tab — all from within a Claude Code session running alongside Safiye.

### Available MCP tools

| Tool | Description |
|---|---|
| `get_session_status` | Returns current hook state, target process info, and packet counts. |
| `get_capture_data` | Returns captured network packets, memory strings, SQL queries, and static analysis results. |
| `get_vulnerability_report` | Returns all findings currently in the Vulnerabilities tab. |
| `submit_findings` | Writes AI-generated vulnerability findings into the Vulnerabilities tab. |
| `log_progress` | Appends a message to the System Output Log visible in the UI. |

### How to set it up

**1. Install and start Safiye:**

```
pip install -r requirements.txt
python src/safiye_server_prod.py
```

Open `http://localhost:5000` in a browser.

**2. Register the MCP server with Claude Code:**

Add the following to your Claude Code MCP configuration (`.claude/mcp_settings.json` or via `claude mcp add`):

```json
{
  "mcpServers": {
    "safiye": {
      "command": "python",
      "args": ["C:/path/to/Safiye/src/mcp_server.py"]
    }
  }
}
```

**3. Hook a target process in Safiye.**

**4. Open a Claude Code session** in the same environment and ask Claude to analyze your data:

```
Analyze the captured traffic from the hooked application. Look for authentication issues,
hardcoded credentials, insecure deserialization, and SQL injection patterns.
Submit any findings back to Safiye.
```

Claude will call `get_capture_data`, reason over the results, and call `submit_findings` to populate the Vulnerabilities tab automatically. No API key or external service is required — Claude Code running locally handles everything. MCP connection status is shown live in the Safiye UI.

---

## Installation

### Requirements

- Windows 10 or 11 (x64)
- Python 3.10 or later
- Frida 16.0 or later
- Administrator privileges (required for process attachment and low-level hooking)

### Setup

```
git clone https://github.com/ErenCanOzmn/SafiyeMonitor.git
cd SafiyeMonitor
pip install -r requirements.txt
python src/safiye_server_prod.py
```

Navigate to `http://localhost:5000`.

---

## Project Structure

```
src/
  safiye_server_prod.py   — FastAPI backend, WebSocket hub, Frida session manager
  mcp_server.py           — MCP stdio bridge for AI assistant integration
  templates/index.html    — Single-page UI
  static/css/style.css    — UI stylesheet
  static/js/app.js        — Frontend logic and WebSocket client

hooks/
  safiye_frida_script.js  — Frida instrumentation script injected into the target process

requirements.txt
```

---

## Disclaimer

Safiye is intended for authorized security testing, CTF competitions, and professional research only. Only use this tool against applications and systems you have explicit permission to test. The author is not responsible for any misuse.

---

## License

MIT License
