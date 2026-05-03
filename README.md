# Safiye - Next-Gen Windows Thick Client Pentest Tool

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)
![Frida](https://img.shields.io/badge/Frida-16.0%2B-orange.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)

> **"Read the traffic, dump the memory, break the logic."**

Safiye is a professional, all-in-one security analysis and reverse engineering platform designed specifically for Windows desktop applications (Thick Clients). Powered by the Frida instrumentation engine and a modern FastAPI web interface, Safiye allows you to intercept low-level API calls, manipulate network traffic in real-time, and perform deep memory analysis without ever touching a debugger.

---

## Key Features

*   **Real-Time Traffic Interception (Intercept & Trap):**
    *   Hook standard ws2_32.dll (send/recv) and WinHTTP/WinINet APIs.
    *   **Trap Mode:** Pause packets in mid-air, modify their content, and forward or drop them.
*   **Deep Memory Analysis:**
    *   **Live Memory Dump:** Extract all readable ASCII/UTF-16 strings from the process RAM.
    *   **Hardcoded Secret Detection:** Automatically find passwords, keys, and endpoints hidden in the binary.
*   **Vulnerability Detection Engine:**
    *   **Insecure Deserialization:** Real-time detection of Java, Python Pickle, .NET BinaryFormatter, and PHP magic bytes in traffic.
    *   **DLL Hijacking Monitor:** Identify "Name Not Found" library calls to find easy local privilege escalation vectors.
*   **Database & System Monitoring:**
    *   **SQL Intercept:** Low-level hooking of MS-SQL (TDS Protocol) queries.
    *   **File & Registry Monitor:** Procmon-style real-time logging of sensitive system interactions.
*   **AI-Powered Analysis (MCP Support):**
    *   Built-in Model Context Protocol (MCP) server to let AI models (like Claude or Gemini) analyze your pentest data automatically.

---

## Installation

### Prerequisites
*   Windows OS
*   Python 3.10+
*   Frida installed on the system.

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Safiye.git
   cd Safiye
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage Guide

### 1. Starting the Interface
Run the main production server:
```bash
python src/safiye_server_prod.py
```
Open your browser and navigate to http://localhost:5000.

### 2. Targeting a Process
*   **Spawn:** Enter the full path to an .exe and click Start Spawn. Safiye will launch the app and hook it from the first instruction.
*   **Attach:** Enter a PID or Process Name and click Reattach to hook a currently running application.

### 3. Exploiting with Repeater & Intercept
*   Right-click any captured packet in the History tab to send it to the Repeater.
*   Enable RPC Trapping to manually modify outgoing requests before they reach the server.

---

## AI Analysis with MCP

Safiye includes a first-of-its-kind Model Context Protocol (MCP) Server. This allows security researchers to connect their AI assistants directly to the live pentest data.

**How to use MCP:**
1. Start the Safiye main server.
2. In a separate terminal, run the MCP bridge:
   ```bash
   python src/mcp_server.py
   ```
3. Point your MCP-compatible AI (e.g., Claude Desktop) to this server.
4. **Ask the AI:** "Analyze the latest memory dump for potential API keys" or "Check if this app is vulnerable to DLL Hijacking based on its logs."

---

## Project Structure

*   `src/`: Core Python server, Web UI (HTML/CSS/JS), and MCP bridge.
*   `hooks/`: Advanced Frida JavaScript injection scripts.
*   `docs/`: Detailed architecture and pentest checklists.

---

## Disclaimer
Safiye is intended for legal security testing, educational purposes, and professional research only. The author is not responsible for any misuse or damage caused by this tool. Always obtain explicit permission before testing any software you do not own.

---

**Eren Can Özmen**

---

## License
This project is licensed under the MIT License - see the LICENSE file for details.
