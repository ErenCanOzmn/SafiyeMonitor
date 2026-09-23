// ── Bind/auth hardening: per-session token plumbing (safiyemonitor-08) ───────
// The server injects window.SAFIYE_TOKEN into <head> at serve time. We attach it
// to every same-origin /api request as X-Safiye-Token (a custom header ⇒ a
// cross-origin caller triggers a CORS preflight the server refuses ⇒ browser-based
// SSRF and LAN callers are blocked) and to the WebSocket via query string.
// Backward-compatible: if no token has been injected, no header is added.
(function () {
    // Token is injected by the server as <meta name="safiye-token"> (a meta tag,
    // not an inline script, so the script-src 'self' CSP doesn't block it).
    let _cached = null;
    function tok() {
        if (_cached !== null) return _cached;
        try {
            const m = document.querySelector('meta[name="safiye-token"]');
            _cached = (m && m.getAttribute("content")) || window.SAFIYE_TOKEN || "";
        } catch (e) { _cached = ""; }
        return _cached;
    }
    window.__safiyeToken = tok;
    const _origFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {
        try {
            const t = tok();
            if (t && typeof input === "string" &&
                (input.startsWith("/api/") || input.startsWith("api/") ||
                 input.startsWith(window.location.origin + "/api/"))) {
                init = init ? Object.assign({}, init) : {};
                const h = new Headers(init.headers || {});
                if (!h.has("X-Safiye-Token")) h.set("X-Safiye-Token", t);
                init.headers = h;
            }
        } catch (e) {}
        return _origFetch(input, init);
    };
})();

document.addEventListener("DOMContentLoaded", () => {
    // UI Elements
    const btnStart = document.getElementById("btnStart");
    const btnAttach = document.getElementById("btnAttach");
    const btnStop = document.getElementById("btnStop");
    const btnBrowseExe = document.getElementById("btnBrowseExe");
    const trapToggle = document.getElementById("trapToggle");
    const statusText = document.getElementById("statusText");
    const targetExeStr = document.getElementById("targetExe");
    const targetArgsStr = document.getElementById("targetArgs");
    const targetPidStr = document.getElementById("targetPid");
    const modeSpawn = document.getElementById("modeSpawn");
    const modePid = document.getElementById("modePid");
    const spawnFields = document.getElementById("spawnFields");
    const pidField = document.getElementById("pidField");
    const argsField = document.getElementById("argsField");

    // ── Multi-script management ───────────────────────────────────────────────
    function getScriptPaths() {
        return Array.from(document.querySelectorAll(".script-input"))
            .map(i => i.value.trim()).filter(Boolean);
    }
    function _updateRemoveBtns() {
        const rows = document.querySelectorAll(".script-row");
        rows.forEach(r => { const b = r.querySelector(".remove-script-btn"); if (b) b.disabled = rows.length <= 1; });
    }
    function addScriptRow(val) {
        const c = document.getElementById("scriptsContainer");
        if (!c) return;
        const row = document.createElement("div");
        row.className = "script-row";
        row.style.cssText = "display:flex; gap:8px; margin-bottom:4px;";
        const inp = document.createElement("input");
        inp.type = "text"; inp.className = "script-input";
        inp.placeholder = "path\\to\\script.js"; inp.style.flex = "1";
        if (val) inp.value = val;
        const bBtn = document.createElement("button");
        bBtn.className = "btn btn-neutral browse-script-btn";
        bBtn.style.cssText = "flex:0 0 auto; padding:8px 10px;";
        bBtn.title = "Browse for a script"; bBtn.textContent = "Browse";
        const rBtn = document.createElement("button");
        rBtn.className = "btn btn-neutral remove-script-btn";
        rBtn.style.cssText = "flex:0 0 auto; padding:8px 10px;";
        rBtn.title = "Remove"; rBtn.textContent = "✕";
        row.appendChild(inp); row.appendChild(bBtn); row.appendChild(rBtn);
        c.appendChild(row);
        _updateRemoveBtns();
    }
    addScriptRow("hooks\\safiye_frida_script.js");
    const btnAddScript = document.getElementById("btnAddScript");
    if (btnAddScript) btnAddScript.onclick = () => addScriptRow("");
    const _scriptsContainer = document.getElementById("scriptsContainer");
    if (_scriptsContainer) {
        _scriptsContainer.addEventListener("click", async (e) => {
            const row = e.target.closest(".script-row");
            if (!row) return;
            if (e.target.classList.contains("browse-script-btn")) {
                const r = await fetch("/api/browse_file");
                const d = await r.json();
                if (d.path) row.querySelector(".script-input").value = d.path;
            } else if (e.target.classList.contains("remove-script-btn")) {
                if (document.querySelectorAll(".script-row").length > 1) {
                    row.remove(); _updateRemoveBtns();
                }
            }
        });
    }

    const tblHistory = document.querySelector("#tblHistory tbody");
    const tblRegistry = document.querySelector("#tblRegistry tbody");
    const tblFile = document.querySelector("#tblFile tbody");
    const tblDll = document.querySelector("#tblDll tbody");
    const tblMemory = document.querySelector("#tblMemory tbody");
    const tblStatic = document.querySelector("#tblStatic tbody");

    const btnDumpMemory = document.getElementById("btnDumpMemory");
    const memorySearch = document.getElementById("memorySearch");
    const memoryStatus = document.getElementById("memoryStatus");
    const staticSearch = document.getElementById("staticSearch");
    const staticStatus = document.getElementById("staticStatus");

    // ── Burp Bridge ───────────────────────────────────────────────────────────
    const btnBridgeToggle  = document.getElementById("btnBridgeToggle");
    const bridgeStatusDot  = document.getElementById("bridgeStatusDot");
    const bridgeStatusText = document.getElementById("bridgeStatusText");
    const bridgePortInput  = document.getElementById("bridgePort");
    const burpPortInput    = document.getElementById("burpPort");
    let _bridgeRunning = false;

    function appendBridgeLog(text, isError) {
        const log = document.getElementById("bridgeLog");
        if (!log) return;
        const ts = new Date().toTimeString().slice(0, 8);
        const div = document.createElement("div");
        div.style.cssText = "padding:1px 0; white-space:pre-wrap; word-break:break-all;"
            + (isError ? " color:#ff6b6b;" : "");
        div.textContent = ts + "  " + text;
        log.appendChild(div);
        while (log.children.length > 400) log.removeChild(log.firstChild);
        log.scrollTop = log.scrollHeight;
    }

    const btnClearBridgeLog = document.getElementById("btnClearBridgeLog");
    if (btnClearBridgeLog) {
        btnClearBridgeLog.onclick = () => {
            const log = document.getElementById("bridgeLog");
            if (log) log.innerHTML = "";
        };
    }

    function _setBridgeUI(running, msg) {
        _bridgeRunning = running;
        if (bridgeStatusDot)
            bridgeStatusDot.style.background = running ? "#9ece6a" : "var(--text-tertiary)";
        if (btnBridgeToggle) {
            btnBridgeToggle.textContent = running ? "Stop Bridge" : "Start Bridge";
            btnBridgeToggle.className   = running ? "btn btn-danger" : "btn btn-neutral";
            btnBridgeToggle.style.cssText = "width:100%; font-size:0.78rem; padding:5px;";
        }
        if (bridgeStatusText && msg !== undefined)
            bridgeStatusText.textContent = msg;
    }

    if (btnBridgeToggle) {
        btnBridgeToggle.onclick = async () => {
            if (_bridgeRunning) {
                try {
                    await fetch("/api/bridge/stop", { method: "POST" });
                    _setBridgeUI(false, "Stopped.");
                    appendBridgeLog("Bridge stopped.");
                } catch (e) { showToast("Bridge stop failed: " + e, "error"); }
            } else {
                const bp  = parseInt(bridgePortInput?.value  || "8081");
                const bup = parseInt(burpPortInput?.value    || "8080");
                try {
                    const r = await fetch("/api/bridge/start", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ bridge_port: bp, burp_port: bup })
                    });
                    const d = await r.json();
                    if (d.status === "ok" || d.status === "already_running") {
                        _setBridgeUI(true, `:${bp} → Burp :${bup}`);
                        showToast("Bridge active on :" + bp, "success");
                    } else {
                        showToast("Bridge error: " + (d.message || d.status), "error");
                        appendBridgeLog("Start failed: " + (d.message || d.status), true);
                    }
                } catch (e) {
                    showToast("Bridge start failed: " + e, "error");
                    appendBridgeLog("Start failed: " + e, true);
                }
            }
        };
    }

    let ws = null;
    let counters = { history: 0 };
    let fullMemoryResults = [];
    let fullStaticResults = [];

    // History data store + sort/filter state
    let historyData      = [];
    let historySearch    = "";
    let historySortCol   = "id";
    let historySortAsc   = false;
    let selectedHistoryId = null;
    let historyDirFilter  = "ALL"; // "ALL" | "OUT" | "IN"

    // ── Request/response correlation ──────────────────────────────────────────
    // Pairs each inbound (IN) row with the request (OUT) it answers. Events are
    // grouped by "connection": a real socket handle for plaintext ws2_32 traffic
    // ("sk:<socket>"), or the TLS connection id the hook ships for encrypted
    // traffic (SChannel context / OpenSSL SSL*). On a connection, the most recent
    // OUT owns every IN that follows until the next OUT — so a multi-segment
    // response (many recv/SSL_read events) all map back to the one request.
    let historyBySeq   = {};   // _seq  -> history item (for jump/highlight lookup)
    let activeReqByConn = {};   // connKey -> the request item currently being answered

    function histConnKey(msg) {
        if (msg.conn) return String(msg.conn);
        const s = msg.socket;
        if (s !== undefined && s !== null && s !== 0 && s !== "0") return "sk:" + s;
        return null;   // socket 0 with no conn id → cannot correlate (leave unpaired)
    }

    // Accumulates all captured events for AI analysis
    const sessionCapture = {
        tcpPackets:      [],
        dllEvents:       [],
        registryEvents:  [],
        fileEvents:      [],
        memoryStrings:   [],
        staticStrings:   [],
        cryptoEvents:    []
    };

    // Child Process Monitor state
    let processEvents        = [];
    let processSearchText    = "";
    let processElevatedOnly  = false;

    // Crypto Monitor state
    let cryptoSearchText     = "";
    let cryptoSecretsOnly    = false;

    // Function Faker state
    let fakerRuleSeq = 0;
    const fakerRules = {};   // id -> {id, module, symbol, offset, mode, value, hits, addr}

    // Vulnerability findings state
    let allVulnFindings = [];
    let allVulnObservations = [];
    let findingView = "confirmed";
    let activeVulnFilter = "ALL";

    // AI analysis wait timer
    let vulnTimerEl       = null;
    let vulnTimerInterval = null;
    let vulnTimerStart    = null;

    const SEVERITY_CFG = {
        CRITICAL: { color: "#ff4444", bg: "rgba(255,68,68,0.10)", border: "rgba(255,68,68,0.35)" },
        HIGH:     { color: "#ff8c00", bg: "rgba(255,140,0,0.10)", border: "rgba(255,140,0,0.35)" },
        MEDIUM:   { color: "#e0af68", bg: "rgba(224,175,104,0.10)", border: "rgba(224,175,104,0.35)" },
        LOW:      { color: "#9ece6a", bg: "rgba(158,206,106,0.10)", border: "rgba(158,206,106,0.35)" },
        INFO:     { color: "#7aa2f7", bg: "rgba(122,162,247,0.10)", border: "rgba(122,162,247,0.35)" }
    };

    function getTimeString() {
        return new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) + "." + String(new Date().getMilliseconds()).padStart(3, '0');
    }

    // Tabs logic
    const tabBtns = document.querySelectorAll(".tab-btn");
    const tabContents = document.querySelectorAll(".tab-content");
    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            tabBtns.forEach(b => b.classList.remove("active"));
            tabContents.forEach(c => c.classList.remove("active"));
            btn.classList.add("active");
            const target = document.getElementById(btn.dataset.target);
            if (target) target.classList.add("active");
        });
    });

    function switchToTab(targetId) {
        const btn = document.querySelector(`.tab-btn[data-target="${targetId}"]`);
        if (btn) btn.click();
    }

    // Modal Logic
    const payloadModal = document.getElementById("payloadModal");
    const closeModal = document.getElementById("closeModal");
    const modalTitle = document.getElementById("modalTitle");
    const modalHeaders = document.getElementById("modalHeaders");
    const modalBodyUtf8 = document.getElementById("modalBodyUtf8");
    const modalBodyHex = document.getElementById("modalBodyHex");
    const modalBodyUtf16 = document.getElementById("modalBodyUtf16");

    const viewerTabs = document.querySelectorAll(".viewer-tab");
    const viewerContents = document.querySelectorAll(".viewer-content");

    viewerTabs.forEach(btn => {
        btn.addEventListener("click", () => {
            viewerTabs.forEach(b => b.classList.remove("active"));
            viewerContents.forEach(c => c.classList.remove("active"));
            btn.classList.add("active");
            const target = document.getElementById("viewer-" + btn.dataset.viewer);
            if (target) {
                target.classList.add("active");
                target.style.display = "block";
            }
            viewerContents.forEach(c => {
                if (c.id !== "viewer-" + btn.dataset.viewer) c.style.display = "none";
            });
        });
    });

    closeModal.onclick = () => payloadModal.style.display = "none";
    function showModal(title, headers, body, bodyHex) {
        modalTitle.textContent = title;
        modalHeaders.textContent = headers || "(No Headers)";
        modalBodyUtf8.textContent = body || "(Empty)";
        modalBodyHex.textContent = bodyHex || "";
        
        // UTF-16 Conversion (Basic)
        try {
            const hex = bodyHex.replace(/\s+/g, '');
            let utf16 = "";
            for (let i = 0; i < hex.length; i += 4) {
                utf16 += String.fromCharCode(parseInt(hex.substr(i, 4), 16));
            }
            modalBodyUtf16.textContent = utf16 || "(Binary)";
        } catch(e) { modalBodyUtf16.textContent = "(Encoding Error)"; }

        payloadModal.style.display = "flex";
        // Reset to UTF-8 view by default
        const utf8Tab = Array.from(viewerTabs).find(t => t.dataset.viewer === 'utf8');
        if (utf8Tab) utf8Tab.click();
    }

    // Intercept Logic (Trapping)
    const interceptHeadersArea = document.getElementById("interceptHeadersArea");
    const interceptBodyArea    = document.getElementById("interceptBodyArea");
    const interceptForwardBtn  = document.getElementById("interceptForwardBtn");
    const interceptDropBtn     = document.getElementById("interceptDropBtn");
    const interceptQueueCount  = document.getElementById("interceptQueueCount");
    const interceptQueueList   = document.getElementById("interceptQueueList");
    const interceptDestTitle   = document.getElementById("interceptDestTitle");
    const interceptFmtUtf8     = document.getElementById("interceptFmtUtf8");
    const interceptFmtHex      = document.getElementById("interceptFmtHex");
    const interceptHexHint     = document.getElementById("interceptHexHint");

    let interceptQueue = [];
    let interceptMode  = "utf8";

    function updateInterceptFmtUI(mode) {
        interceptFmtUtf8.className = "btn " + (mode === "utf8" ? "btn-primary" : "btn-neutral");
        interceptFmtHex.className  = "btn " + (mode === "hex"  ? "btn-primary" : "btn-neutral");
        interceptFmtUtf8.style.cssText = interceptFmtHex.style.cssText = "padding:2px 10px; font-size:0.8rem;";
        interceptHexHint.style.display = mode === "hex" ? "" : "none";
    }

    interceptFmtUtf8.onclick = () => {
        if (interceptMode === "utf8") return;
        try { interceptBodyArea.value = hexToUtf8(interceptBodyArea.value); }
        catch(e) { interceptBodyArea.value = ""; }
        interceptMode = "utf8";
        updateInterceptFmtUI("utf8");
    };

    interceptFmtHex.onclick = () => {
        if (interceptMode === "hex") return;
        interceptBodyArea.value = utf8ToHex(interceptBodyArea.value);
        interceptMode = "hex";
        updateInterceptFmtUI("hex");
    };

    let isInterceptDirty = false;
    interceptBodyArea.oninput = () => { isInterceptDirty = true; };

    const interceptCopyCurlBtn = document.getElementById("interceptCopyCurlBtn");

    function fallbackCopyTextToClipboard(text, successCb) {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";
        textArea.style.left = "-9999px";
        textArea.style.top = "0";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            const successful = document.execCommand('copy');
            if (successful) successCb();
        } catch (err) {
            console.error('[CLIPBOARD] Fallback copy failed', err);
        }
        document.body.removeChild(textArea);
    }

    // Copy as cURL is ALWAYS enabled — works on whatever is in the textarea
    interceptCopyCurlBtn.disabled = false;

    function buildCurlFromText(raw) {
        // Best-effort builder. ALWAYS returns something copyable.
        const lines = raw.split(/\r?\n/);
        const firstParts = lines[0].split(" ");
        const httpMethods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];
        const looksHttp = firstParts.length >= 2 && httpMethods.indexOf(firstParts[0].toUpperCase()) !== -1;

        if (!looksHttp) {
            // Not an HTTP request — emit a generic curl that pipes the raw bytes
            const escaped = raw.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
            return `curl --data-binary "${escaped}" "http://HOST_HERE/PATH_HERE"`;
        }

        const method = firstParts[0].toUpperCase();
        const path = firstParts[1];
        let host = "";
        let headerArgs = "";
        let bodyStart = -1;

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i];
            if (line === "" || line === "\r") { bodyStart = i + 1; break; }
            const colonIdx = line.indexOf(":");
            if (colonIdx > 0) {
                const key = line.slice(0, colonIdx).trim();
                const val = line.slice(colonIdx + 1).trim();
                if (key.toLowerCase() === "host") host = val;
                headerArgs += ` -H "${key}: ${val.replace(/"/g, '\\"')}"`;
            }
        }

        const body = bodyStart !== -1 ? lines.slice(bodyStart).join("\n") : "";
        const url = host ? `http://${host}${path}` : path;
        let cmd = `curl -X ${method} "${url}"${headerArgs}`;
        if (body) cmd += ` --data-binary "${body.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
        return cmd;
    }

    function flashCopied() {
        const oldText = interceptCopyCurlBtn.textContent;
        interceptCopyCurlBtn.textContent = "Copied!";
        interceptCopyCurlBtn.classList.add("btn-success");
        setTimeout(() => {
            interceptCopyCurlBtn.textContent = oldText;
            interceptCopyCurlBtn.classList.remove("btn-success");
        }, 1500);
    }

    interceptCopyCurlBtn.onclick = () => {
        const raw = interceptBodyArea.value || "";
        if (!raw.trim()) {
            alert("Textarea is empty — there is nothing to copy.\nIntercept a packet first or paste content.");
            return;
        }
        const curlCmd = buildCurlFromText(raw);

        const tryClipboard = navigator.clipboard && window.isSecureContext
            ? navigator.clipboard.writeText(curlCmd)
            : Promise.reject(new Error("clipboard api unavailable"));

        tryClipboard
            .then(() => { flashCopied(); })
            .catch(() => {
                fallbackCopyTextToClipboard(curlCmd, flashCopied);
                // Last-resort: also dump to a prompt window so user can manually copy
                setTimeout(() => {
                    if (interceptCopyCurlBtn.textContent !== "Copied!") {
                        window.prompt("Copy this cURL command (Ctrl+C):", curlCmd);
                    }
                }, 200);
            });
    };

    function updateInterceptUI() {
        interceptQueueCount.textContent = interceptQueue.length;
        interceptQueueList.innerHTML = "";
        // Copy as cURL is ALWAYS enabled regardless of queue state
        interceptCopyCurlBtn.disabled = false;
        interceptBodyArea.disabled = false;
        if (interceptQueue.length === 0) {
            interceptDestTitle.textContent = "Waiting for traffic...";
            interceptBodyArea.value = "";
            interceptForwardBtn.disabled = true;
            interceptDropBtn.disabled = true;
            return;
        }

        const current = interceptQueue[0];
        interceptDestTitle.textContent = `Intercepted: ${current.dest} (${current.size} bytes)`;

        const unifiedContent = (current.headers ? current.headers + "\n\n" : "") + (current.body || "");
        const rawHex = (current.body_hex || "").replace(/\s+/g, "").toLowerCase();
        // Save for modification checking (always in UTF-8 terms)
        interceptBodyArea._originalContent = unifiedContent;
        interceptBodyArea._originalHex = rawHex;
        // Display according to current mode
        interceptBodyArea.value = interceptMode === "hex" ? formatHexSpaced(rawHex) : unifiedContent;

        interceptForwardBtn.disabled = false;
        interceptDropBtn.disabled = false;

        interceptQueue.forEach((pkg, idx) => {
            const div = document.createElement("div");
            div.className = "intercept-queue-item" + (idx === 0 ? " active" : "");
            div.innerHTML = `<span>#${escHtml(pkg.id)}</span><span>${escHtml(pkg.dest)}</span>`;
            interceptQueueList.appendChild(div);
        });
    }

    interceptForwardBtn.onclick = () => {
        if (interceptQueue.length === 0) {
            return;
        }
        const pkg = interceptQueue.shift();

        let finalHex;
        if (interceptMode === "hex") {
            // HEX mode: textarea content IS the hex — strip spaces and use directly
            finalHex = interceptBodyArea.value.replace(/\s+/g, "").toLowerCase();
            if (finalHex.length % 2 !== 0) finalHex = "0" + finalHex;
        } else {
            const editedText  = interceptBodyArea.value;
            const originalText = interceptBodyArea._originalContent || "";
            const originalHex  = interceptBodyArea._originalHex || "";

            if (editedText === originalText && originalHex) {
                // No edit detected — replay the EXACT original bytes (bit-perfect)
                finalHex = originalHex;
            } else {
                // Edit detected — re-encode the textarea. Apply CRLF only if it looks like an HTTP request.
                let str = editedText;
                const looksHttp = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s/i.test(str);
                if (looksHttp) str = str.replace(/\r?\n/g, "\r\n");
                const bytes = new TextEncoder().encode(str);
                finalHex = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
            }
        }

        ws.send(JSON.stringify({
            action: "submit_action",
            id: pkg.id,
            decision: "forward",
            modified_hex: finalHex
        }));
        updateInterceptUI();
    };

    interceptDropBtn.onclick = () => {
        if (interceptQueue.length === 0) return;
        const pkg = interceptQueue.shift();
        ws.send(JSON.stringify({
            action: "submit_action",
            id: pkg.id,
            decision: "drop"
        }));
        updateInterceptUI();
    };

    trapToggle.onchange = () => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ action: "toggle_intercept", value: trapToggle.checked }));
        }
    };

    // Table Renderers
    function renderMemoryTable(results) {
        if (!tblMemory) return;
        tblMemory.innerHTML = "";
        results.forEach(r => {
            const tr = document.createElement("tr");
            tr.innerHTML = `<td><span class="tag-success">${escHtml(r.type)}</span></td><td><code>${escHtml(r.addr)}</code></td><td>${escHtml(r.val)}</td>`;
            tblMemory.appendChild(tr);
        });
    }

    function renderStaticTable(results) {
        if (!tblStatic) return;
        tblStatic.innerHTML = "";
        results.forEach(r => {
            const tr = document.createElement("tr");
            tr.innerHTML = `<td><span class="tag-failed">${escHtml(r.type)}</span></td><td>${escHtml(r.val)}</td>`;
            tblStatic.appendChild(tr);
        });
    }

    // History Row Context Menu
    let contextTargetMsg = null;
    const contextMenu = document.getElementById("contextMenu");
    const menuSendRepeater = document.getElementById("menuSendRepeater");

    tblHistory.addEventListener("contextmenu", (e) => {
        const tr = e.target.closest("tr");
        if (!tr) return;
        e.preventDefault();
        
        // Find message by ID
        const id = tr.cells[0].textContent;
        // In a real app we'd search an array, for now we can store it on the TR
        contextTargetMsg = tr._msg;
        
        contextMenu.style.display = "block";
        contextMenu.style.left = e.pageX + "px";
        contextMenu.style.top = e.pageY + "px";
    });

    document.addEventListener("click", () => contextMenu.style.display = "none");

    menuSendRepeater.onclick = () => {
        if (!contextTargetMsg) return;
        sendToRepeater(contextTargetMsg);
    };

    function sendToRepeater(msg) {
        switchToTab("tab-repeater");
        // Create new tab or use existing
        createNewRepeaterTab(msg.dest, msg.body, msg.socket, msg.title);
    }

    // Repeater Logic
    const repeaterTabsContainer = document.getElementById("repeaterTabsContainer");
    const btnNewRepeaterTab = document.getElementById("btnNewRepeaterTab");
    const repeaterSocketId = document.getElementById("repeaterSocketId");
    const repeaterDest = document.getElementById("repeaterDest");
    const repeaterTcpTls = document.getElementById("repeaterTcpTls");

    // Auto-enable TLS when the target is the standard HTTPS port, so replaying a
    // captured HTTPS request "just works" without the operator ticking the box.
    function autoSetRepeaterTls() {
        if (!repeaterTcpTls) return;
        const d = (repeaterDest && repeaterDest.value || "").trim();
        repeaterTcpTls.checked = /:443$/.test(d);
    }
    if (repeaterDest) repeaterDest.addEventListener("input", autoSetRepeaterTls);
    const repeaterReqArea = document.getElementById("repeaterReqArea");
    const repeaterResArea = document.getElementById("repeaterResArea");
    const repeaterCurrentTabTitle = document.getElementById("repeaterCurrentTabTitle");
    const btnRepeaterSend = document.getElementById("btnRepeaterSend");
    const btnRepeaterTcpSend = document.getElementById("btnRepeaterTcpSend");
    const repeaterFmtUtf8 = document.getElementById("repeaterFmtUtf8");
    const repeaterFmtHex = document.getElementById("repeaterFmtHex");
    const repeaterHexHint = document.getElementById("repeaterHexHint");
    const repeaterResFmtUtf8 = document.getElementById("repeaterResFmtUtf8");
    const repeaterResFmtHex = document.getElementById("repeaterResFmtHex");
    let repeaterTabs = [];
    let activeRepeaterTab = null;
    let repeaterTabCounter = 0;

    function updateRepeaterReqModeUI(mode) {
        repeaterFmtUtf8.className = "btn " + (mode === "utf8" ? "btn-primary" : "btn-neutral");
        repeaterFmtHex.className  = "btn " + (mode === "hex"  ? "btn-primary" : "btn-neutral");
        repeaterFmtUtf8.style.padding = repeaterFmtHex.style.padding = "2px 10px";
        repeaterFmtUtf8.style.fontSize = repeaterFmtHex.style.fontSize = "0.8rem";
        repeaterHexHint.style.display = mode === "hex" ? "" : "none";
    }

    function updateRepeaterResModeUI(mode) {
        repeaterResFmtUtf8.className = "btn " + (mode === "utf8" ? "btn-primary" : "btn-neutral");
        repeaterResFmtHex.className  = "btn " + (mode === "hex"  ? "btn-primary" : "btn-neutral");
        repeaterResFmtUtf8.style.padding = repeaterResFmtHex.style.padding = "2px 8px";
        repeaterResFmtUtf8.style.fontSize = repeaterResFmtHex.style.fontSize = "0.75rem";
        if (activeRepeaterTab) {
            repeaterResArea.value = mode === "hex"
                ? formatHexSpaced(activeRepeaterTab.responseHex || "")
                : (activeRepeaterTab.responseUtf8 || "");
        }
    }

    function createNewRepeaterTab(dest, body, socket, title) {
        const id = `${Date.now()}-${++repeaterTabCounter}`;
        const tab = { id, dest, body, socket, title, response: "", responseHex: "", responseUtf8: "", reqMode: "utf8", resMode: "utf8" };
        repeaterTabs.push(tab);

        const btn = document.createElement("button");
        btn.className = "btn";
        const label = title || dest || "New Tab";
        btn.textContent = label;
        btn.title = label;
        btn.style.width = "100%";
        btn.style.display = "block";
        btn.style.boxSizing = "border-box";
        btn.style.flex = "0 0 auto";
        btn.style.textAlign = "left";
        btn.style.minHeight = "34px";
        btn.style.lineHeight = "18px";
        btn.style.padding = "7px 10px";
        btn.style.margin = "0 0 7px 0";
        btn.style.borderRadius = "7px";
        btn.style.border = "1px solid rgba(122,162,247,0.32)";
        btn.style.background = "#0f1320";
        btn.style.color = "#c8d3f5";
        btn.style.overflow = "hidden";
        btn.style.whiteSpace = "nowrap";
        btn.style.textOverflow = "ellipsis";
        btn.style.fontFamily = "var(--font-mono)";
        btn.style.fontSize = "0.74rem";
        btn.style.fontWeight = "700";
        btn.style.letterSpacing = "0.3px";
        btn.style.textTransform = "none";
        btn.onclick = () => selectRepeaterTab(id);
        tab.btn = btn;

        repeaterTabsContainer.appendChild(btn);
        selectRepeaterTab(id);
    }

    function selectRepeaterTab(id) {
        activeRepeaterTab = repeaterTabs.find(t => t.id === id);
        repeaterTabs.forEach(t => {
            t.btn.classList.remove("active-repeater-tab");
            t.btn.style.background = "#0f1320";
            t.btn.style.color = "#c8d3f5";
            t.btn.style.borderColor = "rgba(122,162,247,0.32)";
        });
        activeRepeaterTab.btn.classList.add("active-repeater-tab");
        activeRepeaterTab.btn.style.background = "rgba(122,162,247,0.18)";
        activeRepeaterTab.btn.style.color = "#ffffff";
        activeRepeaterTab.btn.style.borderColor = "#7aa2f7";

        repeaterSocketId.value = activeRepeaterTab.socket || "";
        if (repeaterCurrentTabTitle) {
            repeaterCurrentTabTitle.textContent = activeRepeaterTab.title || activeRepeaterTab.dest || "Repeater Request";
        }
        // Prefill the TCP target from the captured destination (skip placeholders).
        const d = activeRepeaterTab.dest || "";
        if (repeaterDest) repeaterDest.value = /:\d+$/.test(d) ? d : "";
        autoSetRepeaterTls();
        repeaterReqArea.value  = activeRepeaterTab.body || "";
        updateRepeaterReqModeUI(activeRepeaterTab.reqMode || "utf8");
        updateRepeaterResModeUI(activeRepeaterTab.resMode || "utf8");
    }

    btnNewRepeaterTab.onclick = () => createNewRepeaterTab("Manual", "", "");

    // Request format toggle
    repeaterFmtUtf8.onclick = () => {
        if (!activeRepeaterTab || activeRepeaterTab.reqMode === "utf8") return;
        try { repeaterReqArea.value = hexToUtf8(repeaterReqArea.value); }
        catch(e) { repeaterReqArea.value = ""; }
        activeRepeaterTab.reqMode = "utf8";
        activeRepeaterTab.body = repeaterReqArea.value;
        updateRepeaterReqModeUI("utf8");
    };

    repeaterFmtHex.onclick = () => {
        if (!activeRepeaterTab || activeRepeaterTab.reqMode === "hex") return;
        repeaterReqArea.value = utf8ToHex(repeaterReqArea.value);
        activeRepeaterTab.reqMode = "hex";
        activeRepeaterTab.body = repeaterReqArea.value;
        updateRepeaterReqModeUI("hex");
    };

    // Response format toggle — also persist resMode so tab switch restores it
    repeaterResFmtUtf8.onclick = () => {
        if (!activeRepeaterTab) return;
        activeRepeaterTab.resMode = "utf8";
        updateRepeaterResModeUI("utf8");
    };

    repeaterResFmtHex.onclick = () => {
        if (!activeRepeaterTab) return;
        activeRepeaterTab.resMode = "hex";
        updateRepeaterResModeUI("hex");
    };

    btnRepeaterSend.onclick = () => {
        if (!activeRepeaterTab || !ws) return;
        activeRepeaterTab.body = repeaterReqArea.value;
        activeRepeaterTab.socket = repeaterSocketId.value;
        const isHex = activeRepeaterTab.reqMode === "hex";

        repeaterResArea.value = "Sending...";
        ws.send(JSON.stringify({
            action: "repeater_send",
            socket: activeRepeaterTab.socket,
            data: activeRepeaterTab.body,
            is_hex: isHex
        }));
    };

    // Load a raw payload file (e.g. a ysoserial-generated serialized blob) into
    // the request area as hex, then it can be sent via the TCP Repeater.
    const btnRepeaterLoadPayload = document.getElementById("btnRepeaterLoadPayload");
    const repeaterPayloadFile = document.getElementById("repeaterPayloadFile");
    if (btnRepeaterLoadPayload && repeaterPayloadFile) {
        btnRepeaterLoadPayload.onclick = () => repeaterPayloadFile.click();
        repeaterPayloadFile.onchange = () => {
            const file = repeaterPayloadFile.files && repeaterPayloadFile.files[0];
            if (!file) return;
            if (!activeRepeaterTab) createNewRepeaterTab("Manual", "", "");
            const reader = new FileReader();
            reader.onload = () => {
                const bytes = new Uint8Array(reader.result);
                let hex = "";
                for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
                repeaterReqArea.value = formatHexSpaced(hex);
                activeRepeaterTab.body = repeaterReqArea.value;
                activeRepeaterTab.reqMode = "hex";
                updateRepeaterReqModeUI("hex");
                showToast(`Loaded ${bytes.length} bytes from ${file.name} as hex.`, "success");
            };
            reader.onerror = () => showToast("Failed to read payload file.", "error");
            reader.readAsArrayBuffer(file);
            repeaterPayloadFile.value = "";   // allow re-selecting the same file
        };
    }

    // TCP Repeater: open a FRESH connection to the target and replay the bytes.
    // This is the reliable path once the original captured socket has closed.
    if (btnRepeaterTcpSend) {
        btnRepeaterTcpSend.onclick = () => {
            if (!activeRepeaterTab || !ws) return;
            const dest = (repeaterDest.value || "").trim();
            if (!/^.+:\d+$/.test(dest)) {
                showToast("Enter a valid target as host:port for the TCP repeater.", "error");
                return;
            }
            activeRepeaterTab.body = repeaterReqArea.value;
            activeRepeaterTab.dest = dest;
            const isHex = activeRepeaterTab.reqMode === "hex";
            const useTls = !!(repeaterTcpTls && repeaterTcpTls.checked);
            repeaterResArea.value = `Opening new ${useTls ? "TLS" : "TCP"} connection to ${dest} ...`;
            ws.send(JSON.stringify({
                action: "repeater_tcp_send",
                dest: dest,
                data: activeRepeaterTab.body,
                is_hex: isHex,
                tls: useTls,
                tab_id: activeRepeaterTab.id
            }));
        };
    }

    const btnRepeaterCopyCurl = document.getElementById("btnRepeaterCopyCurl");
    if (btnRepeaterCopyCurl) {
        btnRepeaterCopyCurl.onclick = () => {
            const raw = repeaterReqArea.value || "";
            if (!raw.trim()) {
                alert("Repeater request is empty — nothing to copy.");
                return;
            }
            const curlCmd = buildCurlFromText(raw);

            function flashRepeaterCopied() {
                const oldText = btnRepeaterCopyCurl.textContent;
                btnRepeaterCopyCurl.textContent = "Copied!";
                btnRepeaterCopyCurl.classList.add("btn-success");
                setTimeout(() => {
                    btnRepeaterCopyCurl.textContent = oldText;
                    btnRepeaterCopyCurl.classList.remove("btn-success");
                }, 1500);
            }

            const tryClipboard = navigator.clipboard && window.isSecureContext
                ? navigator.clipboard.writeText(curlCmd)
                : Promise.reject(new Error("clipboard api unavailable"));

            tryClipboard
                .then(flashRepeaterCopied)
                .catch(() => {
                    fallbackCopyTextToClipboard(curlCmd, flashRepeaterCopied);
                    setTimeout(() => {
                        if (btnRepeaterCopyCurl.textContent !== "Copied!") {
                            window.prompt("Copy this cURL command (Ctrl+C):", curlCmd);
                        }
                    }, 200);
                });
        };
    }

    const btnRepeaterSendCurl = document.getElementById("btnRepeaterSendCurl");
    if (btnRepeaterSendCurl) {
        btnRepeaterSendCurl.onclick = () => {
            if (!activeRepeaterTab || !ws) return;
            const raw = repeaterReqArea.value || "";
            if (!raw.trim()) {
                alert("Repeater request is empty.");
                return;
            }
            activeRepeaterTab.body = raw;
            const socketHint = (repeaterSocketId && repeaterSocketId.value || "").trim().toLowerCase();
            const destHint = (repeaterDest && repeaterDest.value || "").trim().toLowerCase();
            const scheme = socketHint === "https" || destHint.endsWith(":443") ? "https" : "http";
            repeaterResArea.value = "Executing cURL request...";
            ws.send(JSON.stringify({
                action: "repeater_curl_send",
                data: raw,
                scheme: scheme
            }));
        };
    }

    // ── History helpers ───────────────────────────────────────────────────────

    function parseHttpEndpoint(body) {
        if (!body) return null;
        const m = body.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)/);
        return m ? { method: m[1], path: m[2] } : null;
    }

    function dirShort(direction) {
        if (!direction) return "OUT";
        const d = direction.toLowerCase();
        if (d.includes("connect")) return "CONNECT";
        if (d.includes("incoming") || d.includes("recv")) return "IN";
        return "OUT";
    }

    function endpointLabel(msg) {
        const ep = parseHttpEndpoint(msg.body);
        const dir = dirShort(msg.direction);
        const dest = msg.dest || "";
        if (ep) {
            const pathShort = ep.path.length > 55 ? ep.path.substring(0, 55) + "…" : ep.path;
            return `<span class="hist-dir hist-dir-${dir.toLowerCase()}">${dir}</span> <span class="hist-method">${ep.method}</span> <span class="hist-path">${escHtml(pathShort)}</span>`;
        }
        return `<span class="hist-dir hist-dir-${dir.toLowerCase()}">${dir}</span> <span class="hist-dest-inline">${escHtml(dest)}</span>`;
    }

    // Canonical HTML escaper. Every value derived from captured/target data MUST
    // pass through this before being placed in innerHTML, otherwise hostile bytes
    // in a packet, file path, registry value, memory string, etc. can inject DOM.
    function escHtml(s) {
        if (s === null || s === undefined) return "";
        return String(s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    // Debounce: coalesce rapid input events so we re-filter/re-render at most once
    // per `wait` ms instead of on every keystroke.
    function debounce(fn, wait) {
        let t = null;
        return function (...args) {
            clearTimeout(t);
            t = setTimeout(() => fn.apply(this, args), wait);
        };
    }

    // Lightweight toast notifications for action feedback (start/stop, save/load,
    // scan complete, etc.). type: "info" | "success" | "error".
    function showToast(message, type = "info") {
        let host = document.getElementById("sf-toast-host");
        if (!host) {
            host = document.createElement("div");
            host.id = "sf-toast-host";
            document.body.appendChild(host);
        }
        const el = document.createElement("div");
        el.className = "sf-toast sf-toast-" + type;
        el.textContent = message;
        host.appendChild(el);
        requestAnimationFrame(() => el.classList.add("show"));
        setTimeout(() => {
            el.classList.remove("show");
            setTimeout(() => el.remove(), 220);
        }, 2600);
    }

    function hexFormatted(hexStr) {
        if (!hexStr) return "(no hex data)";
        const clean = hexStr.replace(/\s/g, "");
        let out = "";
        for (let i = 0; i < clean.length; i += 2) {
            out += clean.substr(i, 2) + " ";
            if ((i / 2 + 1) % 16 === 0) out += "\n";
        }
        return out.trim();
    }

    function hexToUtf16(hexStr) {
        if (!hexStr) return "(no hex data)";
        const clean = hexStr.replace(/\s/g, "");
        let out = "";
        for (let i = 0; i < clean.length; i += 4) {
            try { out += String.fromCharCode(parseInt(clean.substr(i, 4), 16)); } catch(e) {}
        }
        return out || "(binary)";
    }

    // ── Hex ↔ UTF-8 conversion helpers ───────────────────────────────────────
    function utf8ToHex(str) {
        const bytes = new TextEncoder().encode(str);
        return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join(" ");
    }

    function hexToUtf8(hex) {
        const clean = hex.replace(/\s+/g, "");
        if (!clean.length) return "";
        const bytes = new Uint8Array((clean.match(/.{1,2}/g) || []).map(h => parseInt(h, 16)));
        return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    }

    function formatHexSpaced(hexStr) {
        const clean = (hexStr || "").replace(/\s+/g, "");
        return (clean.match(/.{1,2}/g) || []).join(" ");
    }

    function getSortKey(item) {
        if (historySortCol === "size") return item.size || 0;
        if (historySortCol === "dest") return (item.dest || "").toLowerCase();
        if (historySortCol === "endpoint") {
            const ep = parseHttpEndpoint(item.body);
            return ep ? ep.path.toLowerCase() : (item.dest || "").toLowerCase();
        }
        return item._seq;
    }

    function matchesSearch(item) {
        if (historyDirFilter !== "ALL") {
            const d = dirShort(item.direction);
            if (historyDirFilter === "OUT" && d !== "OUT" && d !== "CONNECT") return false;
            if (historyDirFilter === "IN"  && d !== "IN") return false;
        }
        if (!historySearch) return true;
        const q = historySearch.toLowerCase();
        const ep = parseHttpEndpoint(item.body);
        return (
            (item.dest || "").toLowerCase().includes(q) ||
            (item.direction || "").toLowerCase().includes(q) ||
            (ep && (ep.method + " " + ep.path).toLowerCase().includes(q)) ||
            (item.body || "").substring(0, 500).toLowerCase().includes(q)
        );
    }

    function refreshHistoryTable() {
        const tbody = document.querySelector("#tblHistory tbody");
        if (!tbody) return;

        let filtered = historyData.filter(matchesSearch);
        filtered.sort((a, b) => {
            const ka = getSortKey(a), kb = getSortKey(b);
            if (ka < kb) return historySortAsc ? -1 : 1;
            if (ka > kb) return historySortAsc ? 1 : -1;
            return 0;
        });

        while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
        filtered.forEach(item => tbody.appendChild(item._tr));

        const countEl = document.getElementById("historyCount");
        if (countEl) {
            countEl.textContent = filtered.length === historyData.length
                ? `${historyData.length} requests`
                : `${filtered.length} / ${historyData.length} requests`;
        }
    }

    function showHistoryDetail(item) {
        const panel = document.getElementById("historyDetailPanel");
        const title = document.getElementById("histDetailTitle");
        if (!panel || !title) return;

        const ep = parseHttpEndpoint(item.body);
        const label = ep
            ? `#${item._seq}  ${ep.method} ${ep.path}  →  ${item.dest || ""}`
            : `#${item._seq}  ${item.direction || ""}  →  ${item.dest || ""}`;
        title.textContent = label;
        renderDetailCorr(item);

        const elU8  = document.getElementById("histDetUtf8");
        const elHex = document.getElementById("histDetHex");
        const elU16 = document.getElementById("histDetUtf16");
        if (elU8)  elU8.textContent  = item.body || "(empty — no body data)";
        if (elHex) elHex.textContent = hexFormatted(item.body_hex);
        if (elU16) elU16.textContent = hexToUtf16(item.body_hex);

        // Reset to UTF-8 view
        document.querySelectorAll(".hist-vtab").forEach(b => {
            const isActive = b.dataset.hv === "utf8";
            b.classList.toggle("active-hvtab", isActive);
            b.style.background = isActive ? "var(--primary-dim)" : "transparent";
            b.style.color = isActive ? "var(--primary)" : "var(--text-secondary)";
            b.style.borderColor = isActive ? "var(--primary)" : "var(--border-color)";
        });
        if (elU8)  elU8.style.display  = "block";
        if (elHex) elHex.style.display = "none";
        if (elU16) elU16.style.display = "none";

        panel.style.display = "flex";
    }

    // Small clickable badge that shows, and jumps to, a row's correlated pair.
    function corrBadge(item) {
        const dir = dirShort(item.direction);
        if (dir === "IN" && item._reqSeq != null) {
            return ` <span class="hist-link" data-jump="${item._reqSeq}" title="Response to request #${item._reqSeq} — click to jump">↳ req #${item._reqSeq}</span>`;
        }
        if (dir === "OUT") {
            const n = (item._respSeqs && item._respSeqs.length) || 0;
            return ` <span class="hist-link hist-respbadge" id="respbadge-${item._seq}" data-jump="${n ? item._respSeqs[0] : ""}" title="Jump to first response"${n ? "" : ' style="display:none;"'}>${n ? "↴ " + n + " resp" : ""}</span>`;
        }
        return "";
    }

    // A response linked to a request after that request's row was already built,
    // so refresh the request row's badge in place.
    function updateRespBadge(req) {
        // Update via the cached row node, not getElementById, so it works even
        // when the request row is currently filtered out of the document.
        const el = req._tr ? req._tr.querySelector(".hist-respbadge") : null;
        if (!el) return;
        const n = req._respSeqs.length;
        el.textContent = "↴ " + n + " resp";
        el.style.display = "";
        el.setAttribute("data-jump", req._respSeqs[0]);
    }

    // Highlight the selected row's counterpart(s): a request highlights its
    // responses, a response highlights its request.
    function highlightPairs(item) {
        const seqs = [];
        if (item._reqSeq != null) seqs.push(item._reqSeq);
        if (item._respSeqs) for (const s of item._respSeqs) seqs.push(s);
        for (const s of seqs) {
            const it = historyBySeq[s];
            if (it && it._tr) it._tr.classList.add("hist-paired");
        }
    }

    function jumpToHistorySeq(seq) {
        const item = historyBySeq[seq];
        if (!item || !item._tr) return;
        if (!item._tr.parentNode) return;   // currently filtered out of the table
        item._tr.scrollIntoView({ block: "center", behavior: "smooth" });
        if (typeof item._tr.onclick === "function") item._tr.onclick();
    }

    // Render the detail panel's correlation link ("show response / show request")
    // for the given item. Kept separate from showHistoryDetail so a response that
    // arrives while its request is open can update the link without resetting the
    // body view.
    function renderDetailCorr(item) {
        const corrEl = document.getElementById("histDetailCorr");
        if (!corrEl) return;
        let html = "";
        if (item._reqSeq != null) {
            html = `<span class="hist-detail-link" data-detail="${item._reqSeq}" title="Show the request this responds to">↳ show request #${item._reqSeq}</span>`;
        } else if (item._respSeqs && item._respSeqs.length) {
            html = item._respSeqs.map(s =>
                `<span class="hist-detail-link" data-detail="${s}" title="Show this request's response (IN)">↴ show response #${s}</span>`
            ).join(" ");
        } else if (dirShort(item.direction) === "IN") {
            html = `<span class="hist-detail-note">↳ no matching request</span>`;
        } else if (dirShort(item.direction) === "OUT") {
            html = `<span class="hist-detail-note">↴ no response yet</span>`;
        }
        corrEl.innerHTML = html;
    }

    function buildHistoryRow(item) {
        const tr = document.createElement("tr");
        tr._msg = item;
        tr.innerHTML = `
            <td>${item._seq}</td>
            <td style="color:var(--text-tertiary); font-size:0.72rem;">${item._time}</td>
            <td>${endpointLabel(item)}${corrBadge(item)}</td>
            <td style="text-align:right;">${item.size || 0}</td>
            <td style="color:var(--text-tertiary);">${escHtml(item.dest || "Unknown")}</td>`;
        tr.onclick = () => {
            document.querySelectorAll("#tblHistory tbody tr").forEach(r => {
                r.classList.remove("hist-selected");
                r.classList.remove("hist-paired");
            });
            tr.classList.add("hist-selected");
            selectedHistoryId = item._seq;
            highlightPairs(item);
            showHistoryDetail(item);
        };
        item._tr = tr;
        return tr;
    }

    function renderHistoryMsg(msg) {
        counters.history++;
        msg._seq  = counters.history;
        msg._time = msg._ts || getTimeString();
        historyData.push(msg);
        historyBySeq[msg._seq] = msg;

        // Correlate request↔response before building the row so IN rows can show
        // the request they answer, and OUT rows learn about their responses.
        const _dir = dirShort(msg.direction);
        const _ck  = histConnKey(msg);
        msg._respSeqs = [];
        let _linkedReq = null;
        if (_ck) {
            if (_dir === "CONNECT") {
                delete activeReqByConn[_ck];        // fresh/closed connection → reset
            } else if (_dir === "OUT") {
                activeReqByConn[_ck] = msg;          // owns the IN rows that follow
            } else if (_dir === "IN") {
                const req = activeReqByConn[_ck];
                if (req) {
                    msg._reqSeq = req._seq;
                    req._respSeqs.push(msg._seq);
                    _linkedReq = req;
                }
            }
        }

        buildHistoryRow(msg);
        if (_linkedReq) {
            updateRespBadge(_linkedReq);
            // If the request is currently open in the detail panel, reveal its new
            // "show response" link live (without disturbing the body view).
            if (selectedHistoryId === _linkedReq._seq) renderDetailCorr(_linkedReq);
        }

        // Cap history so a long session can't grow the array and DOM without bound.
        const HISTORY_CAP = 2000;
        while (historyData.length > HISTORY_CAP) {
            const old = historyData.shift();
            if (old) {
                delete historyBySeq[old._seq];
                if (old._tr && old._tr.parentNode) old._tr.parentNode.removeChild(old._tr);
            }
        }

        if (!historySearch && historySortCol === "id" && historyDirFilter === "ALL") {
            const tbody = document.querySelector("#tblHistory tbody");
            if (tbody) {
                // Respect the sort direction instead of always appending:
                //   descending (default / newest-first) → insert at the top
                //   ascending  (oldest-first)           → append at the bottom
                if (historySortAsc) tbody.appendChild(msg._tr);
                else tbody.insertBefore(msg._tr, tbody.firstChild);
            }
            const countEl = document.getElementById("historyCount");
            if (countEl) countEl.textContent = `${historyData.length} requests`;
        } else {
            refreshHistoryTable();
        }
    }

    // ── Session state management ──────────────────────────────────────────────

    function clearAllState() {
        window.SafiyeUI?.clearArchive();
        // History table
        historyData = [];
        historyBySeq = {};
        activeReqByConn = {};
        counters.history = 0;
        const hTbody = document.querySelector("#tblHistory tbody");
        if (hTbody) while (hTbody.firstChild) hTbody.removeChild(hTbody.firstChild);
        const countEl = document.getElementById("historyCount");
        if (countEl) countEl.textContent = "0 requests";
        const panel = document.getElementById("historyDetailPanel");
        if (panel) panel.style.display = "none";
        selectedHistoryId = null;

        // Capture buffers
        sessionCapture.tcpPackets = [];
        sessionCapture.dllEvents = [];
        sessionCapture.registryEvents = [];
        sessionCapture.fileEvents = [];
        sessionCapture.memoryStrings = [];
        sessionCapture.staticStrings = [];
        sessionCapture.cryptoEvents = [];
        processEvents = [];
        const processBody = document.getElementById("tblProcessesBody");
        if (processBody) processBody.replaceChildren();
        const processCount = document.getElementById("processCount");
        if (processCount) processCount.textContent = "0 processes";
        const fakerLog = document.getElementById("fakerHitLog");
        if (fakerLog) fakerLog.replaceChildren();

        // Monitor tables
        [tblRegistry, tblFile, tblDll, tblMemory, tblStatic].forEach(t => {
            if (t) while (t.firstChild) t.removeChild(t.firstChild);
        });
        const cTbody = document.getElementById("tblCryptoBody");
        if (cTbody) cTbody.innerHTML = "";
        const cCount = document.getElementById("cryptoCount");
        if (cCount) cCount.textContent = "0 events";

        // Memory / Strings
        fullMemoryResults = [];
        fullStaticResults = [];
        renderSecrets(null);
        if (memoryStatus) memoryStatus.textContent = "Click to scan process RAM for sensitive strings.";
        if (staticStatus)  staticStatus.textContent  = "Static analysis of hardcoded strings in the .exe file.";

        // Vulnerability findings
        allVulnFindings = [];
        allVulnObservations = [];
        renderVulnFindings([]);
        const log = document.getElementById("vulnAnalysisLog");
        if (log) log.innerHTML = "";
        stopVulnTimer();

        // Intercept queue
        interceptQueue = [];
        updateInterceptUI();

        addVulnLog("New session started — all previous data cleared.");
    }

    function processMessage(m) {
        if (m.type === "session_loaded") {
            window.SafiyeUI?.showArchive(m.metadata || {});
        }
        else if (m.type === "status") {
            statusText.textContent = m.message;
            const active = m.message === "Hook Active!";
            window.SafiyeUI?.setSession({ active, connected: true, targetPid: m.target_pid, targetName: m.target_name, startedAt: m.started_at });
            btnStart.disabled = active; btnStop.disabled = !active;
            if (btnAttach) btnAttach.disabled = active;
            // Mirror status changes into the System Output Log too.
            const cOut = document.getElementById("consoleOut");
            if (cOut && m.message) {
                cOut.textContent += `[status] ${m.message}\n`;
                cOut.scrollTop = cOut.scrollHeight;
            }
            // Static-string extraction needs a real on-disk path. When we attached
            // by PID/name the field holds a number/name, not a file — skip it.
            if (active && targetExeStr.value && !/^\d+$/.test(targetExeStr.value.trim())) {
                ws.send(JSON.stringify({ action: "get_static_strings", path: targetExeStr.value }));
            }
        }
        else if (m.type === "memory_dump") {
            fullMemoryResults = m.data || [];
            sessionCapture.memoryStrings = fullMemoryResults;
            memoryStatus.textContent = `Found ${fullMemoryResults.length} strings.`;
            btnDumpMemory.disabled = false;
            renderMemoryTable(fullMemoryResults.slice(0, 500));
        }
        else if (m.type === "static_strings") {
            fullStaticResults = m.data || [];
            sessionCapture.staticStrings = fullStaticResults;
            staticStatus.textContent = `Found ${fullStaticResults.length} strings.`;
            renderStaticTable(fullStaticResults.slice(0, 500));
        }
        else if (m.type === "artifact_inventory") {
            const metadata = m.metadata || {};
            const data = { ...metadata, status: "ok", native: { ...metadata.native, findings: (m.data || []).filter(f => f.tier === "native") } };
            if (metadata.managed) data.managed = { ...metadata.managed, findings: (m.data || []).filter(f => f.tier === "managed") };
            renderSecrets(data);
        }
        else if (m.type === "static_strings_error") {
            if (staticStatus) staticStatus.textContent = m.message || "Static strings failed.";
        }
        else if (m.type === "repeater_seed" || m.type === "manual_repeater_seed") {
            const body = m.body || (m.body_hex ? hexToUtf8(m.body_hex) : "");
            switchToTab("tab-repeater");
            createNewRepeaterTab(m.dest || "MCP", body, m.socket || "HTTP", m.title || "MCP Request");
            renderHistoryMsg(m);
            showToast("Request pushed to Repeater: " + (m.title || m.dest || "MCP Request"), "success");
        }
        else if (m.type === "repeater_response") {
            // Immediate send confirmation (not the actual TCP response)
            repeaterResArea.value = m.data || "";
            if (activeRepeaterTab) {
                activeRepeaterTab.responseUtf8 = m.data || "";
                activeRepeaterTab.responseHex = "";
                activeRepeaterTab.response = m.data || "";
            }
        }
        else if (m.type === "repeater_tcp_result") {
            // Response from the server-side TCP Repeater (fresh connection).
            const tab = repeaterTabs.find(t => String(t.id) === String(m.tab_id)) || activeRepeaterTab;
            if (tab) {
                tab.responseHex  = m.data_hex || "";
                tab.responseUtf8 = m.data || "";
                tab.response = tab.resMode === "hex" ? formatHexSpaced(tab.responseHex) : tab.responseUtf8;
                if (tab === activeRepeaterTab) {
                    repeaterResArea.value = tab.response || ("(" + (m.status || "no data") + ")");
                    updateRepeaterResModeUI(tab.resMode || "utf8");
                }
            }
            if (m.status) showToast("TCP repeater: " + m.status, m.ok ? "success" : "error");
        }
        else if (m.type === "repeater_tcp_response") {
            // Actual TCP response captured by Frida recv() hook
            const tab = repeaterTabs.find(t => String(t.socket) === String(m.socket)) || activeRepeaterTab;
            if (tab) {
                tab.responseHex = m.data_hex || "";
                tab.responseUtf8 = m.data || "";
                tab.response = tab.resMode === "hex"
                    ? formatHexSpaced(tab.responseHex)
                    : tab.responseUtf8;
                if (tab === activeRepeaterTab) {
                    repeaterResArea.value = tab.response;
                    updateRepeaterResModeUI(tab.resMode || "utf8");
                }
            }
        }
        else if (m.type === "tcp_out" || m.type === "tcp_in") {
            sessionCapture.tcpPackets.push({ direction: m.direction, dest: m.dest, size: m.size, body: m.body, body_hex: m.body_hex });
            if (sessionCapture.tcpPackets.length > 500) sessionCapture.tcpPackets.shift();
            renderHistoryMsg(m);
        }
        else if (m.type === "bridge_req") {
            renderHistoryMsg(m);
            const verb = m.method || (m.proto === "HTTPS" ? "CONNECT" : "HTTP");
            const dest = m.proto === "HTTPS" ? m.dest : (m.url || m.dest || "");
            appendBridgeLog(`#${m.req_id || "?"}  ${m.proto}  ${verb}  ${dest}`);
        }
        else if (m.type === "bridge_log") {
            appendBridgeLog(m.text, m.isError);
        }
        else if (m.type === "intercept_wait") {
            interceptQueue.push(m);
            updateInterceptUI();
        }
        else if (m.type === "process_spawn") {
            processEvents.push(m);
            if (processEvents.length > 500) processEvents.shift();
            renderProcessRow(m);
            if (m.elevated) flashTabBtn("tab-processes");
        }
        else if (m.type === "crypto_event") {
            const ev = {
                api: m.api, op: m.op, size: m.size, ts: m._ts || getTimeString(),
                body: m.body || "", body_hex: m.body_hex || "",
                dpapi_local_machine: !!m.dpapi_local_machine,
                dpapi_entropy: m.dpapi_entropy
            };
            sessionCapture.cryptoEvents.push(ev);
            if (sessionCapture.cryptoEvents.length > 500) sessionCapture.cryptoEvents.shift();
            renderCryptoRow(ev);
            if (ev.op === "unprotect" || ev.op === "decrypt") flashTabBtn("tab-crypto");
        }
        else if (m.type === "faker_result") {
            const st = document.getElementById("fakerStatus");
            if (m.op === "add") {
                const okAdd = typeof m.result === "string" && m.result.indexOf("ok") === 0;
                if (okAdd) {
                    fakerRules[m.id] = { id: m.id, module: m.module, symbol: m.symbol, offset: m.offset, mode: m.mode, value: m.value, hits: 0, addr: m.result.slice(3) };
                    renderFakerRules();
                    if (st) { st.textContent = "hooked " + (m.symbol || (m.module + "+" + m.offset)) + " @ " + m.result.slice(3); st.style.color = "#9ece6a"; }
                } else if (st) { st.textContent = "failed: " + (m.result || "unknown"); st.style.color = "#ff6b6b"; }
            } else if (m.op === "remove") {
                delete fakerRules[m.id];
                renderFakerRules();
                if (st) { st.textContent = "removed"; st.style.color = "var(--text-tertiary)"; }
            }
        }
        else if (m.type === "faker_list") {
            Object.keys(fakerRules).forEach(k => delete fakerRules[k]);
            (m.rules || []).forEach(r => { fakerRules[r.id] = r; });
            renderFakerRules();
        }
        else if (m.type === "faker_search") {
            const box = document.getElementById("fakerSearchBox");
            if (box) {
                const results = m.results || [];
                if (!results.length) {
                    box.innerHTML = `<span style="color:var(--text-tertiary); font-size:0.76rem;">no exports matching "${escHtml(m.query || "")}" in ${escHtml(m.module || "")}</span>`;
                } else {
                    const _trunc = results.length >= 100 ? ` <span style="color:#e0af68;">(first 100 shown — type more letters to narrow)</span>` : "";
                    box.innerHTML = `<div style="font-size:0.7rem; color:var(--text-tertiary); margin-bottom:4px;">${results.length} match(es) — click to use:${_trunc}</div>` +
                        results.map(r => `<span class="faker-sym-pick" data-sym="${escHtml(r.name)}" style="display:inline-block; margin:2px 4px 2px 0; padding:2px 8px; background:var(--bg-surface); border:1px solid var(--border-color); border-radius:4px; font-family:var(--font-mono); font-size:0.74rem; cursor:pointer; color:var(--primary);">${escHtml(r.name)}</span>`).join("");
                    box.querySelectorAll(".faker-sym-pick").forEach(el => {
                        el.onclick = () => { const si = document.getElementById("fakerSymbol"); if (si) si.value = el.dataset.sym; box.style.display = "none"; };
                    });
                }
            }
        }
        else if (m.type === "faker_hit") {
            if (fakerRules[m.id]) {
                fakerRules[m.id].hits = m.hits;
                const cell = document.getElementById("faker-hits-" + m.id);
                if (cell) cell.textContent = m.hits;
            }
            const log = document.getElementById("fakerHitLog");
            if (log) {
                const changed = m.mode === "return" && m.orig_ret !== m.forced_ret;
                const retHtml = changed
                    ? `<span style="color:#9ece6a;">${escHtml(m.orig_ret)} &rarr; ${escHtml(m.forced_ret)}</span>`
                    : `<span style="color:var(--text-tertiary);">${escHtml(m.orig_ret)}</span>`;
                const line = document.createElement("div");
                line.innerHTML = `<span style="color:var(--text-tertiary);">${escHtml(m._ts || "")}</span> ` +
                    `<span style="color:var(--primary);">${escHtml(m.label || m.symbol || "")}</span> ret ${retHtml} ` +
                    `<span style="color:var(--text-tertiary);">args=[${escHtml((m.args || []).join(", "))}] caller=${escHtml(m.caller || "")}</span>`;
                log.insertBefore(line, log.firstChild);
                while (log.childNodes.length > 300) log.removeChild(log.lastChild);
            }
        }
        else if (m.type === "dll_monitor" || m.type === "registry_file_monitor") {
            if (m.type === "dll_monitor") {
                sessionCapture.dllEvents.push({ api: m.api, status: m.status, dllName: m.dllName || m.target });
                if (sessionCapture.dllEvents.length > 500) sessionCapture.dllEvents.shift();
            } else if (m.api && m.api.includes("Reg")) {
                sessionCapture.registryEvents.push({ api: m.api, status: m.status, target: m.target });
                if (sessionCapture.registryEvents.length > 500) sessionCapture.registryEvents.shift();
            } else {
                sessionCapture.fileEvents.push({ api: m.api, status: m.status, target: m.target });
                if (sessionCapture.fileEvents.length > 500) sessionCapture.fileEvents.shift();
            }
            const targetTbl = m.type === "dll_monitor" ? tblDll : (m.api.includes("Reg") ? tblRegistry : tblFile);
            if (targetTbl) {
                const rowTime = m._ts || getTimeString();
                const tr = document.createElement("tr");
                tr.innerHTML = `<td>${Date.now().toString().slice(-4)}</td><td>${escHtml(rowTime)}</td><td>${escHtml(m.api)}</td><td class="${m.isFailed ? 'tag-failed' : 'tag-success'}">${escHtml(m.status)}</td><td>${escHtml(m.target || m.dllName)}</td>`;
                targetTbl.appendChild(tr);
                // Cap the visible rows so the monitor tables don't grow without bound.
                while (targetTbl.rows && targetTbl.rows.length > 1000) targetTbl.deleteRow(0);
            }
        }
        else if (m.type === "console_output") {
            const c = document.getElementById("consoleOut");
            if (c) {
                c.textContent += m.text;
                // Cap the buffer so a long session can't grow it without bound.
                if (c.textContent.length > 200000) {
                    c.textContent = c.textContent.slice(-160000);
                }
                c.scrollTop = c.scrollHeight;
            }
        }
        else if (m.type === "vuln_findings") {
            const findings = m.findings || [];
            stopVulnTimer(`Analysis complete — ${findings.length} confirmed, ${(m.observations || []).length} for review`);
            renderVulnFindings(findings, m.observations || []);
        }
        else if (m.type === "vuln_analysis_log") {
            addVulnLog(m.message || "");
        }
        else if (m.type === "vulnerability_report") {
            // Old servers may emit this event; it must never bypass the review gate.
            addVulnLog("Runtime signal received; confirmation requires evidence review.");
        }
        else if (m.type === "session_replay") {
            (m.events || []).forEach(ev => processMessage(ev));
        }
        else if (m.type === "session_cleared") {
            clearAllState();
        }
    }

    // WebSocket
    function connectWebSocket() {
        const _t = (window.__safiyeToken && window.__safiyeToken()) || "";
        const _q = _t ? ("?token=" + encodeURIComponent(_t)) : "";
        ws = new WebSocket(`ws://${window.location.host}/ws${_q}`);
        ws.onopen = () => { statusText.textContent = "Connected (Ready)"; window.SafiyeUI?.setSession({ connected: true }); syncStatus(); };
        ws.onmessage = (e) => processMessage(JSON.parse(e.data));
        ws.onclose = () => {
            statusText.textContent = "Disconnected";
            window.SafiyeUI?.setSession({ connected: false });
            setTimeout(connectWebSocket, 2000);
        };
    }

    async function syncStatus() {
        try {
            const r = await fetch("/api/status");
            const d = await r.json();
            if (typeof d.is_hooking === "boolean") {
                statusText.textContent = d.is_hooking ? "Hook Active!" : "Connected (Ready)";
                btnStart.disabled = d.is_hooking; btnStop.disabled = !d.is_hooking;
                if (btnAttach) btnAttach.disabled = d.is_hooking;
                window.SafiyeUI?.setSession({ active: d.is_hooking, targetPid: d.target_pid, targetName: d.target_name, startedAt: d.started_at });
            }
        } catch {}
    }

    btnStart.onclick = () => {
        if (!targetExeStr.value) { showToast("Set a target executable first.", "error"); return; }
        const scripts = getScriptPaths();
        if (!scripts.length) { showToast("Add at least one Frida script.", "error"); return; }
        fetch("/api/start_hook", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({target_exe: targetExeStr.value, target_script: scripts[0], target_scripts: scripts, target_args: targetArgsStr.value})})
            .then(() => showToast("Spawning target and attaching hooks...", "info"))
            .catch(() => showToast("Failed to start hook.", "error"));
    };
    if (btnAttach) btnAttach.onclick = () => {
        const target = (targetPidStr ? targetPidStr.value : "").trim();
        if (!target) { showToast("Enter a PID to attach to.", "error"); return; }
        if (!/^\d+$/.test(target)) { showToast("PID must be a number.", "error"); return; }
        const scripts = getScriptPaths();
        if (!scripts.length) { showToast("Add at least one Frida script.", "error"); return; }
        fetch("/api/attach_hook", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({target: target, target_script: scripts[0], target_scripts: scripts})})
            .then(r => r.json())
            .then(d => {
                if (d && d.status === "ok") showToast(`Attaching to PID ${target}...`, "info");
                else showToast(`Attach failed: ${(d && d.message) || "unknown error"}`, "error");
            })
            .catch(() => showToast("Failed to attach hook.", "error"));
    };

    // Spawn vs PID-Attach mode: show only the fields + action button each needs.
    function applyHookMode() {
        const pid = !!(modePid && modePid.checked);
        if (spawnFields) spawnFields.style.display = pid ? "none" : "";
        if (argsField)   argsField.style.display   = pid ? "none" : "";
        if (pidField)    pidField.style.display    = pid ? "" : "none";
        if (btnStart)    btnStart.style.display     = pid ? "none" : "";
        if (btnAttach)   btnAttach.style.display    = pid ? "" : "none";
    }
    if (modeSpawn) modeSpawn.addEventListener("change", applyHookMode);
    if (modePid)   modePid.addEventListener("change", applyHookMode);
    applyHookMode();
    btnStop.onclick = () => {
        fetch("/api/stop_hook", { method: "POST" })
            .then(() => { showToast("Hook stopped.", "info"); if (btnAttach) btnAttach.disabled = false; })
            .catch(() => showToast("Failed to stop hook.", "error"));
    };
    btnBrowseExe.onclick = async () => { const r = await fetch("/api/browse_file"); const d = await r.json(); if (d.path) targetExeStr.value = d.path; };

    if (btnDumpMemory) {
        btnDumpMemory.onclick = () => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                btnDumpMemory.disabled = true;
                memoryStatus.textContent = "Scanning...";
                ws.send(JSON.stringify({ action: "dump_memory" }));
            }
        };
    }

    if (memorySearch) {
        memorySearch.oninput = debounce(() => {
            const val = memorySearch.value.toLowerCase();
            const filtered = fullMemoryResults.filter(r => r.val.toLowerCase().includes(val) || r.addr.toLowerCase().includes(val));
            renderMemoryTable(filtered.slice(0, 500));
        }, 150);
    }

    if (staticSearch) {
        staticSearch.oninput = debounce(() => {
            const val = staticSearch.value.toLowerCase();
            const filtered = fullStaticResults.filter(r => r.val.toLowerCase().includes(val));
            renderStaticTable(filtered.slice(0, 500));
        }, 150);
    }

    // ── Vulnerability Analysis ────────────────────────────────

    function addVulnLog(msg) {
        const log = document.getElementById("vulnAnalysisLog");
        if (!log) return;
        const d = document.createElement("div");
        d.textContent = `[${getTimeString()}] ${msg}`;
        log.appendChild(d);
        log.scrollTop = log.scrollHeight;
    }

    function startVulnTimer() {
        stopVulnTimer();
        const log = document.getElementById("vulnAnalysisLog");
        if (!log) return;
        vulnTimerStart = Date.now();
        vulnTimerEl = document.createElement("div");
        vulnTimerEl.style.color = "var(--primary)";
        vulnTimerEl.style.fontWeight = "600";
        log.appendChild(vulnTimerEl);
        vulnTimerInterval = setInterval(() => {
            const s = Math.floor((Date.now() - vulnTimerStart) / 1000);
            const mm = String(Math.floor(s / 60)).padStart(2, "0");
            const ss = String(s % 60).padStart(2, "0");
            vulnTimerEl.textContent = `  Waiting for AI analysis... ${mm}:${ss} elapsed`;
            log.scrollTop = log.scrollHeight;
        }, 1000);
    }

    function stopVulnTimer(label) {
        if (vulnTimerInterval) { clearInterval(vulnTimerInterval); vulnTimerInterval = null; }
        if (vulnTimerEl && label) {
            const s = Math.floor((Date.now() - vulnTimerStart) / 1000);
            const mm = String(Math.floor(s / 60)).padStart(2, "0");
            const ss = String(s % 60).padStart(2, "0");
            vulnTimerEl.style.color = "var(--accent)";
            vulnTimerEl.textContent = `  ${label} — took ${mm}:${ss}`;
            const log = document.getElementById("vulnAnalysisLog");
            if (log) log.scrollTop = log.scrollHeight;
        }
        vulnTimerEl = null;
        vulnTimerStart = null;
    }

    function updateVulnBadges() {
        const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0 };
        allVulnFindings.forEach(f => { counts[f.severity] = (counts[f.severity]||0)+1; });
        document.getElementById("vulnBadgeCrit").textContent = `${counts.CRITICAL} Critical`;
        document.getElementById("vulnBadgeHigh").textContent = `${counts.HIGH} High`;
        document.getElementById("vulnBadgeMed").textContent  = `${counts.MEDIUM} Medium`;
        document.getElementById("vulnBadgeLow").textContent  = `${counts.LOW} Low`;
        // Tab nav badge
        const navBadge = document.getElementById("vulnCountBadge");
        const urgent = counts.CRITICAL + counts.HIGH;
        if (navBadge) {
            navBadge.textContent = urgent || (allVulnFindings.length || "");
            navBadge.style.display = allVulnFindings.length ? "inline" : "none";
            navBadge.style.background = urgent > 0 ? "#ff4444" : "#ff8c00";
        }
    }

    function applyVulnFilter() {
        const records = findingView === "confirmed" ? allVulnFindings : allVulnObservations;
        const filtered = activeVulnFilter === "ALL"
            ? records
            : records.filter(f => f.severity === activeVulnFilter);
        window.SafiyeUI.renderFindings(filtered, records.length, findingView);
        const confirmed = document.getElementById("btnConfirmedFindings");
        const review = document.getElementById("btnReviewObservations");
        if (confirmed) { confirmed.textContent = `Confirmed (${allVulnFindings.length})`; confirmed.setAttribute("aria-pressed", String(findingView === "confirmed")); }
        if (review) { review.textContent = `Needs review (${allVulnObservations.length})`; review.setAttribute("aria-pressed", String(findingView === "review")); }
    }

    function renderVulnFindings(findings, observations = []) {
        // Also protect the UI when replaying old or inconsistent events.
        allVulnFindings = findings.filter(f => f.ui_review_status === "Confirmed" && f.validation_status === "confirmed");
        allVulnObservations = [...observations, ...findings.filter(f => !allVulnFindings.includes(f))];
        updateVulnBadges();
        applyVulnFilter();
        const lastScan = document.getElementById("vulnLastScan");
        if (lastScan) lastScan.textContent = `Last scan: ${getTimeString()}`;
    }

    document.getElementById("btnConfirmedFindings")?.addEventListener("click", () => { findingView = "confirmed"; applyVulnFilter(); });
    document.getElementById("btnReviewObservations")?.addEventListener("click", () => { findingView = "review"; applyVulnFilter(); });

    // Filter buttons
    document.querySelectorAll(".vuln-filter-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".vuln-filter-btn").forEach(b => b.classList.remove("active-filter"));
            btn.classList.add("active-filter");
            activeVulnFilter = btn.dataset.sev;
            applyVulnFilter();
        });
    });

    // Summary badge click → filter
    ["vulnBadgeCrit","vulnBadgeHigh","vulnBadgeMed","vulnBadgeLow"].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        el.addEventListener("click", () => {
            const sev = el.dataset.sev;
            document.querySelectorAll(".vuln-filter-btn").forEach(b => {
                b.classList.toggle("active-filter", b.dataset.sev === sev);
            });
            activeVulnFilter = sev;
            applyVulnFilter();
        });
    });

    // ── History: search / sort / detail panel ────────────────────────────────

    const histSearchEl    = document.getElementById("historySearch");
    const histSortColEl   = document.getElementById("historySortCol");
    const histSortToggle  = document.getElementById("historySortToggle");
    const histDetailPanel = document.getElementById("historyDetailPanel");
    const histDetailClose = document.getElementById("histDetailClose");

    // Clicking a correlation badge jumps to the paired row. Capture phase + stop
    // so the badge click doesn't also trigger the row's own select handler.
    const histTbodyEl = document.querySelector("#tblHistory tbody");
    if (histTbodyEl) {
        histTbodyEl.addEventListener("click", (e) => {
            const link = e.target.closest(".hist-link");
            if (!link) return;
            e.stopPropagation();
            e.preventDefault();
            const seq = parseInt(link.getAttribute("data-jump"), 10);
            if (!isNaN(seq)) jumpToHistorySeq(seq);
        }, true);
    }

    if (histSearchEl) {
        histSearchEl.addEventListener("input", debounce(() => {
            historySearch = histSearchEl.value.trim();
            refreshHistoryTable();
        }, 150));
    }

    if (histSortColEl) {
        histSortColEl.addEventListener("change", () => {
            historySortCol = histSortColEl.value;
            refreshHistoryTable();
        });
    }

    if (histSortToggle) {
        histSortToggle.addEventListener("click", () => {
            historySortAsc = !historySortAsc;
            histSortToggle.textContent = historySortAsc ? "▲ Asc" : "▼ Desc";
            refreshHistoryTable();
        });
    }

    // Direction filter buttons (All / OUT / IN)
    document.querySelectorAll(".hist-dir-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            historyDirFilter = btn.dataset.dir;
            document.querySelectorAll(".hist-dir-btn").forEach(b => {
                const active = b.dataset.dir === historyDirFilter;
                b.style.background = active ? "var(--primary)" : "var(--bg-raised)";
                b.style.color      = active ? "#fff" : "var(--text-secondary)";
            });
            refreshHistoryTable();
        });
    });

    // Column header click → sort
    document.querySelectorAll("#tblHistory thead th[data-hcol]").forEach(th => {
        th.addEventListener("click", () => {
            const col = th.dataset.hcol;
            if (historySortCol === col) {
                historySortAsc = !historySortAsc;
            } else {
                historySortCol = col;
                historySortAsc = false;
            }
            if (histSortColEl) histSortColEl.value = col;
            if (histSortToggle) histSortToggle.textContent = historySortAsc ? "▲ Asc" : "▼ Desc";
            refreshHistoryTable();
        });
    });

    // Detail panel: viewer tab switching
    document.querySelectorAll(".hist-vtab").forEach(btn => {
        btn.addEventListener("click", () => {
            const view = btn.dataset.hv;
            document.querySelectorAll(".hist-vtab").forEach(b => {
                const active = b.dataset.hv === view;
                b.classList.toggle("active-hvtab", active);
                b.style.background   = active ? "var(--primary-dim)" : "transparent";
                b.style.color        = active ? "var(--primary)" : "var(--text-secondary)";
                b.style.borderColor  = active ? "var(--primary)" : "var(--border-color)";
            });
            ["utf8","hex","utf16"].forEach(v => {
                const el = document.getElementById(`histDet${v.charAt(0).toUpperCase() + v.slice(1)}`);
                if (el) el.style.display = v === view ? "block" : "none";
            });
        });
    });

    if (histDetailClose) {
        histDetailClose.addEventListener("click", () => {
            if (histDetailPanel) histDetailPanel.style.display = "none";
            document.querySelectorAll("#tblHistory tbody tr").forEach(r => r.classList.remove("hist-selected"));
            selectedHistoryId = null;
        });
    }

    // Detail-panel correlation links: clicking "show response / show request"
    // loads the paired row's body into the same panel (and syncs the table
    // selection when that row is currently visible).
    const histDetailCorrEl = document.getElementById("histDetailCorr");
    if (histDetailCorrEl) {
        histDetailCorrEl.addEventListener("click", (e) => {
            const link = e.target.closest(".hist-detail-link");
            if (!link) return;
            const seq = parseInt(link.getAttribute("data-detail"), 10);
            if (isNaN(seq)) return;
            const item = historyBySeq[seq];
            if (!item) return;
            if (item._tr && item._tr.parentNode) jumpToHistorySeq(seq);  // sync row + panel
            else showHistoryDetail(item);                                 // row filtered out
        });
    }

    const histDetailSendRepeater = document.getElementById("histDetailSendRepeater");
    if (histDetailSendRepeater) {
        histDetailSendRepeater.addEventListener("click", () => {
            const item = historyData.find(d => d._seq === selectedHistoryId);
            if (!item) return;
            sendToRepeater(item);
        });
    }

    // AI Analysis Modal
    const aiModal       = document.getElementById("aiModal");
    const aiModalClose  = document.getElementById("aiModalClose");
    const aiModalDone   = document.getElementById("aiModalDone");
    const aiModalCopy   = document.getElementById("aiModalCopy");
    const aiModalPrompt = document.getElementById("aiModalPrompt");
    const aiModalDot    = document.getElementById("aiModalMcpDot");
    const aiModalText   = document.getElementById("aiModalMcpText");

    const AI_PROMPT = "Call get_capture_data from the safiye MCP server to retrieve the runtime capture data. " +
        "Analyze every section thoroughly: " +
        "network packets (cleartext credentials, JWT tokens, API keys, insecure protocols, SQL injection in HTTP bodies), " +
        "DLL load events (hijacking via missing or writable-path DLLs, search-order hijacking), " +
        "registry operations (stored secrets, HKLM write access, autorun persistence keys), " +
        "file operations (sensitive config files, world-writable directories), " +
        "memory strings (hardcoded credentials, private keys, connection strings), " +
        "static PE strings (embedded secrets, debug flags, internal URLs). " +
        "Call log_progress at the start of each section with a plain-text message and the item count. " +
        "Call log_progress again when you find something notable. " +
        "When fully done, call submit_findings with ALL findings — include INFO-level observations too. " +
        "Each finding must have: severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), title, description, evidence, verification_steps, exploitation_notes.";

    async function openAiModal() {
        if (aiModalPrompt) aiModalPrompt.value = AI_PROMPT;
        if (aiModal) aiModal.style.display = "flex";
        // Check MCP status
        try {
            const r = await fetch("/api/status");
            const d = await r.json();
            const age = d.mcp_last_seen ? (Date.now()/1000 - d.mcp_last_seen) : null;
            const connected = age !== null && age < 120;
            if (aiModalDot) aiModalDot.style.background = connected ? "#4caf50" : "#f44336";
            if (aiModalText) aiModalText.textContent = connected
                ? `MCP connected (last seen ${Math.round(age)}s ago)`
                : age === null
                    ? "MCP never connected — complete steps 1 and 2 first"
                    : `MCP last seen ${Math.round(age)}s ago — is mcp_server.py still running?`;
        } catch {
            if (aiModalDot) aiModalDot.style.background = "#f44336";
            if (aiModalText) aiModalText.textContent = "Cannot reach Safiye server";
        }
    }

    if (aiModalClose) aiModalClose.onclick = () => { aiModal.style.display = "none"; };
    if (aiModalDone)  aiModalDone.onclick  = () => { aiModal.style.display = "none"; };
    if (aiModalCopy && aiModalPrompt) {
        aiModalCopy.onclick = () => {
            navigator.clipboard.writeText(aiModalPrompt.value).then(() => {
                aiModalCopy.textContent = "Copied!";
                setTimeout(() => { aiModalCopy.textContent = "Copy"; }, 1800);
            });
        };
    }

    // Analyze with AI button
    const btnAnalyzeAI = document.getElementById("btnAnalyzeAI");
    if (btnAnalyzeAI) {
        btnAnalyzeAI.onclick = async () => {
            const total = sessionCapture.tcpPackets.length + sessionCapture.dllEvents.length +
                          sessionCapture.registryEvents.length + sessionCapture.fileEvents.length + sessionCapture.staticStrings.length +
                          sessionCapture.memoryStrings.length + sessionCapture.cryptoEvents.length + processEvents.length;
            if (total === 0) {
                addVulnLog("No data captured yet. Start the hook and generate some traffic first.");
                return;
            }
            // Queue data in background
            fetch("/api/analyze_vulnerabilities", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: "{}"
            }).then(r => r.json()).then(result => {
                if (result.status !== "error") startVulnTimer();
                else addVulnLog("Could not prepare analysis: " + result.error);
            }).catch(error => addVulnLog("Could not prepare analysis: " + error.message));
            // Show modal immediately
            openAiModal();
        };
    }

    // Analyze without AI button
    const btnAnalyzeRules = document.getElementById("btnAnalyzeRules");
    if (btnAnalyzeRules) {
        btnAnalyzeRules.onclick = async () => {
            const total = sessionCapture.tcpPackets.length + sessionCapture.dllEvents.length +
                          sessionCapture.registryEvents.length + sessionCapture.staticStrings.length +
                          sessionCapture.memoryStrings.length + sessionCapture.cryptoEvents.length;
            addVulnLog(`Rule-based scan started... (${total} captured events)`);
            btnAnalyzeRules.disabled = true;
            btnAnalyzeRules.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite;"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg> Scanning...`;
            try {
                const resp = await fetch("/api/rule_scan", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: "{}"
                });
                const result = await resp.json();
                if (result.status === "error") addVulnLog(`Rule scan error: ${result.error}`);
            } catch(e) {
                addVulnLog(`Rule scan request failed: ${e.message}`);
            } finally {
                btnAnalyzeRules.disabled = false;
                btnAnalyzeRules.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg> Analyze without AI`;
            }
        };
    }

    // Clear findings
    const btnClearVulns = document.getElementById("btnClearVulns");
    if (btnClearVulns) {
        btnClearVulns.onclick = () => {
            allVulnFindings = [];
            renderVulnFindings([]);
            addVulnLog("Findings cleared.");
        };
    }

    // Export Logic
    function exportTableAsCSV(tableId, filename) {
        const table = document.getElementById(tableId);
        if (!table) return;
        const rows = table.querySelectorAll("tr");
        const csv = [];
        rows.forEach(row => {
            const cols = row.querySelectorAll("td, th");
            const rowData = Array.from(cols).map(c => '"' + c.innerText.replace(/"/g, '""') + '"');
            csv.push(rowData.join(","));
        });
        const blob = new Blob([csv.join("\n")], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    const btnExportMemory = document.getElementById("btnExportMemory");
    if (btnExportMemory) {
        btnExportMemory.onclick = () => exportTableAsCSV("tblMemory", `safiye_memory_${Date.now()}.csv`);
    }

    const btnExportStatic = document.getElementById("btnExportStatic");
    if (btnExportStatic) {
        btnExportStatic.onclick = () => exportTableAsCSV("tblStatic", `safiye_static_${Date.now()}.csv`);
    }

    // ── Named Pipe Tab ────────────────────────────────────────────────────────

    let pipeData       = [];
    let pipeFilter     = "ALL";
    let pipeSearchText = "";
    let activePipeId   = null;
    let pipeRecvTimer  = null;
    let pipeSendFmt    = "utf8";

    // ── MSRPC helpers ─────────────────────────────────────────────────────────
    const _NDR_UUID = [0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60];
    const _MSRPC_UUIDS = {
        epmapper: {uuid:[0x08,0x83,0xaf,0xe1,0x1f,0x5d,0xc9,0x11,0x91,0xa4,0x08,0x00,0x2b,0x14,0xa0,0xfa],ver:[3,0,0,0],label:"BIND - Endpoint Mapper v3"},
        atsvc:    {uuid:[0x82,0x06,0xf7,0x1f,0x51,0x0a,0xe8,0x30,0x07,0x6d,0x74,0x0b,0xe8,0xce,0xe9,0x8b],ver:[1,0,0,0],label:"BIND - Task Scheduler v1"},
        svcctl:   {uuid:[0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,0x00,0x10,0x03],ver:[2,0,0,0],label:"BIND - Service Control v2"},
        winreg:   {uuid:[0x01,0xd0,0x8c,0x33,0x44,0x22,0xf1,0x31,0xaa,0xaa,0x90,0x00,0x38,0x00,0x10,0x03],ver:[1,0,0,0],label:"BIND - Remote Registry v1"},
        lsarpc:   {uuid:[0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab],ver:[0,0,0,0],label:"BIND - LSA Policy v0"},
        samr:     {uuid:[0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xac],ver:[1,0,0,0],label:"BIND - SAM Database v1"},
        srvsvc:   {uuid:[0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88],ver:[3,0,0,0],label:"BIND - Server Service v3"},
        wkssvc:   {uuid:[0x98,0xd0,0xff,0x6b,0x12,0xa1,0x10,0x36,0x98,0x33,0x46,0xc3,0xf8,0x7e,0x34,0x5a],ver:[1,0,0,0],label:"BIND - Workstation Service v1"},
        spoolss:  {uuid:[0x78,0x56,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab],ver:[1,0,0,0],label:"BIND - Print Spooler v1"},
        netlogon: {uuid:[0x78,0x56,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0xcf,0xfb],ver:[1,0,0,0],label:"BIND - Netlogon v1"},
        eventlog: {uuid:[0xdc,0x3f,0x27,0x82,0x2a,0xe3,0xc3,0x18,0x3f,0x78,0x82,0x79,0x29,0xdc,0x23,0xea],ver:[0,0,0,0],label:"BIND - Event Log v0"},
    };

    function _buildMsrpcBind(uuidArr, verArr) {
        const header = [0x05,0x00,0x0b,0x03,0x10,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x01,0x00,0x00,0x00];
        const params = [0xd0,0x16,0xd0,0x16,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00];
        const all    = [...header, ...params, ...uuidArr, ...verArr, ..._NDR_UUID, 0x02,0x00,0x00,0x00];
        const pairs  = all.map(b => b.toString(16).padStart(2,'0').toUpperCase());
        const lines  = [];
        for (let i = 0; i < pairs.length; i += 16) lines.push(pairs.slice(i,i+16).join(' '));
        return lines.join('\n');
    }

    function _msrpcDecode(hexStr) {
        const clean = (hexStr || "").replace(/\s+/g,"");
        if (clean.length < 32) return null;
        const b = [];
        for (let i = 0; i < clean.length; i += 2) b.push(parseInt(clean.substr(i,2),16));
        if (b[0] !== 5) return null;
        const ptype   = b[2];
        const fragLen = b[8] | (b[9]<<8);
        const callId  = b[12] | (b[13]<<8) | (b[14]<<16) | (b[15]<<24);
        const PTYPES  = {0x00:"REQUEST",0x02:"RESPONSE",0x03:"FAULT",
                         0x0b:"BIND",0x0c:"BIND_ACK",0x0d:"BIND_NACK",
                         0x10:"ALTER_CTX",0x11:"ALTER_CTX_RESP"};
        if (ptype === 0x0c && b.length >= 26) {
            const maxRecv    = b[18] | (b[19]<<8);
            const secAddrLen = b[24] | (b[25]<<8);
            let secAddr = "";
            for (let i = 0; i < secAddrLen - 1 && 26+i < b.length; i++) {
                const c = b[26+i]; if (c >= 32 && c < 127) secAddr += String.fromCharCode(c);
            }
            const padded = Math.ceil((26+secAddrLen)/4)*4;
            let resultStr = "";
            if (b.length >= padded+6) {
                const res = b[padded+4] | (b[padded+5]<<8);
                const R   = {0:"ACCEPTED",1:"USER_REJECT",2:"PROVIDER_REJECT",3:"NEGOTIATE_ACK"};
                resultStr = "  result=" + (R[res] || res);
            }
            return `BIND_ACK  frag=${fragLen}  max_recv=${maxRecv}  pipe="${secAddr}"${resultStr}`;
        }
        if (ptype === 0x0d && b.length >= 18) {
            const reason = b[16] | (b[17]<<8);
            const R = {0:"not_specified",1:"temporary_congestion",2:"local_limit_exceeded",3:"protocol_version_not_supported"};
            return `BIND_NACK  reason=${R[reason] || reason}`;
        }
        if (ptype === 0x03 && b.length >= 28) {
            const st = ((b[27]<<24)|(b[26]<<16)|(b[25]<<8)|b[24]) >>> 0;
            const F  = {0x1C000006:"access_denied",0x1C000008:"context_mismatch",0x00000005:"access_denied"};
            return `FAULT  status=${F[st] || "0x"+st.toString(16).toUpperCase().padStart(8,"0")}`;
        }
        if (ptype === 0x02) return `RESPONSE  frag=${fragLen}  call_id=${callId}  stub=${Math.max(0,fragLen-24)} bytes`;
        return `${PTYPES[ptype]||"TYPE_0x"+ptype.toString(16).toUpperCase()}  frag=${fragLen}  call_id=${callId}`;
    }

    function _pipeMatchesFilter(p) {
        if (pipeFilter === "ACCESSIBLE"  && !p.accessible)  return false;
        if (pipeFilter === "INTERESTING" && !p.interesting) return false;
        if (pipeFilter === "WEAKDACL" && !["CRITICAL", "HIGH", "MEDIUM"].includes(p.risk)) return false;
        if (pipeSearchText) {
            const q = pipeSearchText.toLowerCase();
            if (!(p.name   || "").toLowerCase().includes(q) &&
                !(p.reason || "").toLowerCase().includes(q)) return false;
        }
        return true;
    }

    function _pipeRowBg(p) {
        if (p.risk === "CRITICAL") return "rgba(255,68,68,0.16)";
        if (p.risk === "HIGH")     return "rgba(255,140,0,0.13)";
        if (p.interesting && p.accessible)  return "rgba(255,107,107,0.13)";
        if (p.interesting && !p.accessible) return "rgba(224,175,104,0.10)";
        return "";
    }

    const _DACL_STYLE = {
        CRITICAL: {bg:"#ff4444",                 color:"#ffffff"},
        HIGH:     {bg:"rgba(255,140,0,0.92)",    color:"#ffffff"},
        MEDIUM:   {bg:"rgba(224,175,104,0.90)",  color:"#1a1a1a"},
        LOW:      {bg:"rgba(158,206,106,0.22)",  color:"#9ece6a"},
        INFO:     {bg:"rgba(122,162,247,0.20)",  color:"#7aa2f7"},
        UNKNOWN:  {bg:"rgba(130,130,130,0.16)",  color:"#8a94b0"},
    };

    function _pipeDaclBadge(p) {
        if (!p.risk) return `<span style="color:var(--text-tertiary); font-size:0.75rem;">—</span>`;
        const s = _DACL_STYLE[p.risk] || _DACL_STYLE.UNKNOWN;
        const tip = escHtml(p.risk_reason || "");
        return `<span title="${tip}" style="display:inline-block; padding:1px 7px; border-radius:3px; font-size:0.67rem; font-weight:700; letter-spacing:0.3px; background:${s.bg}; color:${s.color};">${escHtml(p.risk)}</span>`;
    }

    function _pipeAccessBadge(p) {
        if (p.accessible === null || p.accessible === undefined)
            return `<span style="color:var(--text-tertiary); font-size:0.75rem;">—</span>`;
        if (p.accessible)
            return `<span style="color:#9ece6a; font-size:0.75rem; font-weight:700;">YES</span>`;
        return `<span style="color:var(--text-tertiary); font-size:0.75rem;">no</span>`;
    }

    function rebuildPipeTable() {
        const tbody    = document.getElementById("tblPipelistBody");
        const countEl  = document.getElementById("pipeCount");
        if (!tbody) return;
        tbody.innerHTML = "";
        const visible = pipeData.filter(_pipeMatchesFilter);
        if (visible.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-tertiary); padding:32px;">No pipes match the current filter.</td></tr>`;
        } else {
            visible.forEach((p, i) => {
                const tr = document.createElement("tr");
                tr.style.cssText = `background:${_pipeRowBg(p)}; cursor:pointer;`;
                tr.dataset.pipeName = p.name;
                tr.innerHTML = `
                    <td style="color:var(--text-tertiary); font-size:0.75rem;">${i+1}</td>
                    <td style="font-family:'Fira Code',monospace; font-size:0.78rem;">\\\\.\\pipe\\${escHtml(p.name)}</td>
                    <td style="text-align:center;">${_pipeAccessBadge(p)}</td>
                    <td style="text-align:center;">${_pipeDaclBadge(p)}</td>
                    <td style="font-size:0.75rem;">${_catBadge(p.category)}${escHtml(p.reason || "")}</td>`;
                tr.onclick = () => openPipeClientPanel(p.name);
                tbody.appendChild(tr);
            });
        }
        if (countEl) countEl.textContent = `${visible.length} / ${pipeData.length} pipes`;
    }

    const _CAT_STYLE = {
        CRED:   {bg:"rgba(247,118,142,0.18)", color:"#f7768e",   label:"CRED"},
        EXEC:   {bg:"rgba(255,158,100,0.18)", color:"#ff9e64",   label:"EXEC"},
        INFO:   {bg:"rgba(122,162,247,0.18)", color:"#7aa2f7",   label:"INFO"},
        REG:    {bg:"rgba(187,154,247,0.18)", color:"#bb9af7",   label:"REG"},
        CUSTOM: {bg:"rgba(158,206,106,0.18)", color:"#9ece6a",   label:"CUSTOM"},
    };

    function _catBadge(cat) {
        if (!cat) return "";
        const s = _CAT_STYLE[cat] || _CAT_STYLE.CUSTOM;
        return `<span style="display:inline-block; padding:1px 6px; border-radius:3px; font-size:0.68rem; font-weight:700; background:${s.bg}; color:${s.color}; margin-right:5px;">${s.label}</span>`;
    }

    async function loadPipes(doScan) {
        const scanStatus = document.getElementById("pipeScanStatus");
        const btnList    = document.getElementById("btnListPipes");
        const btnScan    = document.getElementById("btnScanPipes");
        if (btnList) btnList.disabled = true;
        if (btnScan) btnScan.disabled = true;
        if (scanStatus) scanStatus.textContent = doScan ? "Scanning…" : "Loading…";
        try {
            if (doScan) {
                const r = await fetch("/api/pipes/scan", {method:"POST"});
                const d = await r.json();
                pipeData = (d.pipes || []).map(p => ({
                    name:        p.name,
                    accessible:  p.accessible  ?? null,
                    interesting: p.interesting ?? false,
                    reason:      p.reason      || "",
                    category:    p.category    || "",
                    hint:        p.hint        || "",
                    risk:        p.risk        || null,
                    risk_reason: p.risk_reason || "",
                    null_dacl:   p.null_dacl   || false,
                    sddl:        p.sddl        || "",
                    owner:       p.owner       || "",
                    risky_aces:  p.risky_aces  || [],
                }));
            } else {
                const r = await fetch("/api/pipes");
                const d = await r.json();
                pipeData = (d.pipes || []).map(p => ({
                    name: p.name, accessible: null,
                    interesting: false, reason: "", category: "", hint: "",
                    risk: null, risk_reason: "", null_dacl: false, sddl: "", owner: "", risky_aces: [],
                }));
            }
            rebuildPipeTable();
            if (scanStatus) scanStatus.textContent = doScan ? "Scan done." : "";
        } catch(e) {
            console.error("Pipe load error:", e);
            if (scanStatus) scanStatus.textContent = "Error!";
        } finally {
            if (btnList) btnList.disabled = false;
            if (btnScan) btnScan.disabled = false;
        }
    }

    // Pipe filter button toggles
    document.querySelectorAll(".pipe-flt").forEach(btn => {
        btn.onclick = () => {
            pipeFilter = btn.dataset.pf;
            document.querySelectorAll(".pipe-flt").forEach(b => {
                b.style.background = b.dataset.pf === pipeFilter
                    ? "var(--primary)" : "var(--bg-raised)";
                b.style.color = b.dataset.pf === pipeFilter
                    ? "#fff" : "var(--text-secondary)";
            });
            rebuildPipeTable();
        };
    });

    // ── PE protection analysis (DLL & Modules tab) ────────────────────────────
    const _PE_RISK_STYLE = {
        HIGH:    {bg:"rgba(255,140,0,0.92)",   color:"#fff"},
        MEDIUM:  {bg:"rgba(224,175,104,0.90)", color:"#1a1a1a"},
        LOW:     {bg:"rgba(158,206,106,0.22)", color:"#9ece6a"},
        INFO:    {bg:"rgba(122,162,247,0.20)", color:"#7aa2f7"},
        UNKNOWN: {bg:"rgba(130,130,130,0.16)", color:"#8a94b0"},
    };
    function _peYesNo(v) {
        return v
            ? `<span style="color:#9ece6a; font-weight:700;">✓</span>`
            : `<span style="color:#ff6b6b; font-weight:700;">✗</span>`;
    }
    // SEH is a tri-state string ("n/a" on x64, "no-SEH"/"SafeSEH" safe on x86,
    // "unknown" when it can't be determined) — not a simple yes/no.
    function _peSeh(v) {
        const safe = v === "no-SEH" || v === "SafeSEH";
        const col = safe ? "#9ece6a" : "var(--text-tertiary)";
        return `<span style="color:${col}; font-size:0.72rem;">${escHtml(v || "—")}</span>`;
    }
    function _peSigBadge(sig) {
        const good = sig === "signed";
        const bad  = sig === "UNSIGNED" || sig === "INVALID";
        const col  = good ? "#9ece6a" : (bad ? "#ff6b6b" : "var(--text-tertiary)");
        return `<span style="color:${col}; font-weight:${bad ? 700 : 400}; font-size:0.74rem;">${escHtml(sig || "?")}</span>`;
    }
    function _peRiskBadge(risk) {
        const s = _PE_RISK_STYLE[risk] || _PE_RISK_STYLE.UNKNOWN;
        return `<span style="display:inline-block; padding:1px 7px; border-radius:3px; font-size:0.67rem; font-weight:700; background:${s.bg}; color:${s.color};">${escHtml(risk || "?")}</span>`;
    }
    function renderPeScan(results) {
        const tbody = document.getElementById("tblPeScanBody");
        if (!tbody) return;
        if (!results.length) {
            tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; color:var(--text-tertiary); padding:24px;">No PE files found for that path.</td></tr>`;
            return;
        }
        tbody.innerHTML = "";
        results.forEach(r => {
            const tr = document.createElement("tr");
            if (r.risk === "HIGH")   tr.style.background = "rgba(255,140,0,0.10)";
            else if (r.risk === "MEDIUM") tr.style.background = "rgba(224,175,104,0.07)";
            if (!r.ok) {
                tr.innerHTML = `<td title="${escHtml(r.path||"")}" style="font-family:'Fira Code',monospace; font-size:0.76rem;">${escHtml(r.name||"?")}</td>`
                    + `<td colspan="7" style="color:var(--text-tertiary); font-size:0.75rem;">${escHtml(r.risk_reason||"not a PE / unreadable")}</td>`
                    + `<td>${_peRiskBadge(r.risk)}</td>`;
                tbody.appendChild(tr); return;
            }
            const notes = (r.dotnet ? `<span style="color:#bb9af7;">.NET</span> ` : "") + escHtml(r.risk_reason || "");
            tr.innerHTML = `
                <td title="${escHtml(r.path||"")}" style="font-family:'Fira Code',monospace; font-size:0.76rem;">${escHtml(r.name||"?")}</td>
                <td style="font-size:0.74rem; color:var(--text-secondary);">${escHtml(r.arch||"")}</td>
                <td style="text-align:center;">${_peYesNo(r.aslr)}</td>
                <td style="text-align:center;">${_peYesNo(r.dep)}</td>
                <td style="text-align:center;">${_peYesNo(r.cfg)}</td>
                <td style="text-align:center;">${_peSeh(r.seh)}</td>
                <td>${_peSigBadge(r.signature)}</td>
                <td>${_peRiskBadge(r.risk)}</td>
                <td style="font-size:0.74rem; color:var(--text-secondary);">${notes}</td>`;
            tbody.appendChild(tr);
        });
    }
    const btnPeScan = document.getElementById("btnPeScan");
    if (btnPeScan) {
        btnPeScan.onclick = async () => {
            const pathEl = document.getElementById("peScanPath");
            const recEl  = document.getElementById("peScanRecursive");
            const statusEl = document.getElementById("peScanStatus");
            let path = (pathEl && pathEl.value || "").trim();
            if (!path && targetExeStr) { path = (targetExeStr.value || "").trim(); if (pathEl) pathEl.value = path; }
            if (!path) { if (statusEl) statusEl.textContent = "Enter an exe path or folder."; return; }
            btnPeScan.disabled = true;
            if (statusEl) statusEl.textContent = "Scanning…";
            try {
                const r = await fetch("/api/pe_scan", {
                    method: "POST", headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({ path, recursive: !!(recEl && recEl.checked) })
                });
                const d = await r.json();
                renderPeScan(d.results || []);
                if (statusEl) {
                    const risky = (d.results || []).filter(x => x.risk === "HIGH" || x.risk === "MEDIUM").length;
                    statusEl.textContent = `${d.count} module(s), ${risky} flagged.`;
                }
            } catch (e) {
                if (statusEl) statusEl.textContent = "Error!";
                console.error("PE scan error:", e);
            } finally {
                btnPeScan.disabled = false;
            }
        };
    }

    // ── COM/RPC scan (COM/RPC tab) ────────────────────────────────────────────
    function renderComRpc(d) {
        const db = document.getElementById("tblComDcomBody");
        const findings = (d.dcom && d.dcom.findings) || [];
        if (db) {
            if (!findings.length) {
                db.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-tertiary); padding:24px;">No weak DCOM permissions found (${(d.dcom && d.dcom.scanned) || 0} AppIDs scanned).</td></tr>`;
            } else {
                db.innerHTML = "";
                findings.forEach(f => {
                    const who = (f.principals || []).map(p =>
                        `${escHtml(p.name)} <span style="color:var(--text-tertiary);">(${escHtml((p.rights || []).join(","))})</span>`).join("; ")
                        + (f.null_dacl ? ` <span style="color:#ff6b6b; font-weight:700;">NULL DACL</span>` : "");
                    const tr = document.createElement("tr");
                    if (f.severity === "HIGH") tr.style.background = "rgba(255,140,0,0.08)";
                    tr.innerHTML = `
                        <td>${_peRiskBadge(f.severity)}</td>
                        <td style="font-size:0.78rem;">${escHtml(f.name || "")}</td>
                        <td style="font-family:'Fira Code',monospace; font-size:0.73rem; color:var(--text-secondary);">${escHtml(f.appid || "")}</td>
                        <td style="font-size:0.73rem; color:var(--text-tertiary);">${escHtml((f.permissions || []).join(", "))}</td>
                        <td style="font-size:0.75rem;">${who}</td>`;
                    db.appendChild(tr);
                });
            }
        }
        const rb = document.getElementById("tblComRpcBody");
        const eps = (d.rpc && d.rpc.endpoints) || [];
        const sum = document.getElementById("comRpcSummary");
        if (sum) {
            const by = (d.rpc && d.rpc.by_protseq) || {};
            sum.textContent = Object.keys(by).length ? ("— " + Object.keys(by).map(k => `${by[k]} ${k}`).join(", ")) : "";
        }
        if (rb) {
            if (!eps.length) {
                rb.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-tertiary); padding:24px;">No RPC endpoints returned.</td></tr>`;
            } else {
                rb.innerHTML = "";
                eps.forEach(e => {
                    const tcp = e.protseq === "ncacn_ip_tcp";
                    const tr = document.createElement("tr");
                    if (tcp) tr.style.background = "rgba(224,175,104,0.08)";
                    tr.innerHTML = `
                        <td style="font-family:'Fira Code',monospace; font-size:0.72rem;">${escHtml(e.uuid || "")}</td>
                        <td style="font-size:0.72rem; color:var(--text-tertiary);">${escHtml(e.version || "")}</td>
                        <td style="font-family:'Fira Code',monospace; font-size:0.72rem; ${tcp ? 'color:#e0af68;' : 'color:var(--text-secondary);'}">${escHtml(e.binding || "")}</td>
                        <td style="font-size:0.74rem;">${escHtml(e.annotation || "")}</td>`;
                    rb.appendChild(tr);
                });
            }
        }
    }
    const btnComRpcScan = document.getElementById("btnComRpcScan");
    if (btnComRpcScan) {
        btnComRpcScan.onclick = async () => {
            const st = document.getElementById("comRpcStatus");
            btnComRpcScan.disabled = true;
            if (st) st.textContent = "Scanning…";
            try {
                const r = await fetch("/api/com_rpc_scan", { method: "POST" });
                const d = await r.json();
                renderComRpc(d);
                if (st) {
                    const nf = ((d.dcom && d.dcom.findings) || []).length;
                    st.textContent = `${(d.rpc && d.rpc.count) || 0} RPC endpoints, ${nf} DCOM finding(s).`;
                }
            } catch (e) {
                if (st) st.textContent = "Error!";
                console.error("COM/RPC scan error:", e);
            } finally {
                btnComRpcScan.disabled = false;
            }
        };
    }

    // ── Active TLS certificate probe (COM/RPC tab) ────────────────────────────
    function renderTlsProbe(d) {
        const box = document.getElementById("tlsProbeResult");
        if (!box) return;
        box.style.display = "block";
        if (!d.ok) {
            box.innerHTML = `<span style="color:#ff6b6b;">${escHtml(d.risk_reason || "probe failed")}</span>`;
            return;
        }
        const badge = d.trusted === true
            ? `<span style="color:#9ece6a; font-weight:700;">TRUSTED</span>`
            : `<span style="color:#ff6b6b; font-weight:700;">NOT TRUSTED</span>`;
        const c = d.cert || {};
        box.innerHTML =
            `${badge} ${_peRiskBadge(d.severity)} <span style="color:var(--text-secondary);">${escHtml(d.risk_reason || "")}</span><br>`
            + `<span style="color:var(--text-tertiary);">proto:</span> ${escHtml(d.protocol || "")} &nbsp; `
            + `<span style="color:var(--text-tertiary);">cipher:</span> ${escHtml(d.cipher || "")}<br>`
            + (c.subject_cn ? `<span style="color:var(--text-tertiary);">subject:</span> ${escHtml(c.subject_cn)} &nbsp; <span style="color:var(--text-tertiary);">issuer:</span> ${escHtml(c.issuer_cn || "")}<br>` : "")
            + (c.not_after ? `<span style="color:var(--text-tertiary);">expires:</span> ${escHtml(c.not_after)}${c.expired ? ' <span style="color:#ff6b6b;">(EXPIRED)</span>' : ''} ${c.self_signed ? '<span style="color:#e0af68;">self-signed</span> ' : ''}${c.sig_alg ? '<span style="color:var(--text-tertiary);">sig:</span> ' + escHtml(c.sig_alg) : ''}<br>` : "")
            + ((c.sans && c.sans.length) ? `<span style="color:var(--text-tertiary);">SANs:</span> ${escHtml(c.sans.join(", "))}<br>` : "")
            + (d.sha256 ? `<span style="color:var(--text-tertiary);">sha256:</span> <code style="font-size:0.72rem;">${escHtml(d.sha256)}</code>` : "");
    }
    const btnTlsProbe = document.getElementById("btnTlsProbe");
    if (btnTlsProbe) {
        btnTlsProbe.onclick = async () => {
            const host = (document.getElementById("tlsProbeHost").value || "").trim();
            const port = parseInt(document.getElementById("tlsProbePort").value, 10) || 443;
            const sni = (document.getElementById("tlsProbeSni").value || "").trim();
            const st = document.getElementById("tlsProbeStatus");
            if (!host) { if (st) st.textContent = "Enter a host."; return; }
            btnTlsProbe.disabled = true;
            if (st) st.textContent = "Probing…";
            try {
                const r = await fetch("/api/tls_probe", {
                    method: "POST", headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ host, port, server_hostname: sni })
                });
                const d = await r.json();
                renderTlsProbe(d);
                if (st) st.textContent = d.ok ? "" : (d.risk_reason || "failed");
            } catch (e) {
                if (st) st.textContent = "Error!";
                console.error("TLS probe error:", e);
            } finally {
                btnTlsProbe.disabled = false;
            }
        };
    }


    // ═══════════════════════════════════════════════════════════════════════
    // Privesc + Managed Secret scanners (safiyemonitor-08 lane)
    // ═══════════════════════════════════════════════════════════════════════
    const _RISK_STYLE = {
        CRITICAL: {bg:"#7f1d1d", color:"#fecaca"}, HIGH: {bg:"rgba(255,107,107,0.18)", color:"#ff6b6b"},
        MEDIUM: {bg:"rgba(224,175,104,0.18)", color:"#e0af68"}, LOW: {bg:"rgba(158,206,106,0.15)", color:"#9ece6a"},
        INFO: {bg:"rgba(122,162,247,0.15)", color:"#7aa2f7"},
    };
    function _riskBadge(r) {
        const s = _RISK_STYLE[r] || _RISK_STYLE.INFO;
        return `<span style="display:inline-block; padding:1px 7px; border-radius:3px; font-size:0.67rem; font-weight:700; background:${s.bg}; color:${s.color};">${escHtml(r||"?")}</span>`;
    }
    async function _sendToVuln(findings, statusEl, source) {
        try {
            const r = await fetch("/api/vuln_add", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({findings, source: source||"scanner"})});
            const d = await r.json();
            if (statusEl) statusEl.textContent = d.status==="ok" ? `Queued ${d.added} for review (${d.total} confirmed).` : ("Error: "+(d.message||""));
        } catch(e){ if(statusEl) statusEl.textContent="Send failed!"; console.error("send to vuln", e); }
    }

    // ── Privesc scan ─────────────────────────────────────────────────────────
    let _privescFindings = [];
    function renderPrivesc(findings) {
        _privescFindings = findings || [];
        const tbody = document.getElementById("tblPrivescBody");
        if (!tbody) return;
        if (!_privescFindings.length) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-tertiary); padding:24px;">No privilege-escalation issues found.</td></tr>`;
            return;
        }
        tbody.innerHTML = "";
        _privescFindings.forEach(f => {
            const tr = document.createElement("tr");
            if (f.risk === "HIGH" || f.risk === "CRITICAL") tr.style.background = "rgba(255,107,107,0.08)";
            else if (f.risk === "MEDIUM") tr.style.background = "rgba(224,175,104,0.06)";
            const writers = (f.principals||[]).map(p => `${escHtml(p.principal)} <span style="color:var(--text-tertiary);">${escHtml(p.rights||"")}</span>`).join("<br>") || "<span style='color:var(--text-tertiary);'>—</span>";
            tr.innerHTML = `
                <td>${_riskBadge(f.risk)}</td>
                <td style="font-size:0.74rem; color:var(--text-secondary); font-family:'Fira Code',monospace;">${escHtml(f.category||"")}</td>
                <td style="font-size:0.78rem;">${escHtml(f.title||"")}</td>
                <td title="${escHtml(f.target||"")}" style="font-size:0.73rem; font-family:'Fira Code',monospace; color:var(--text-secondary); word-break:break-all;">${escHtml(f.target||"")}</td>
                <td style="font-size:0.72rem;">${writers}</td>
                <td style="font-size:0.73rem; color:var(--text-secondary);">${escHtml(f.detail||"")}${f.remediation?`<br><span style="color:#9ece6a;">Fix:</span> ${escHtml(f.remediation)}`:""}</td>`;
            tbody.appendChild(tr);
        });
    }
    const _btnPrivescScan = document.getElementById("btnPrivescScan");
    if (_btnPrivescScan) {
        _btnPrivescScan.onclick = async () => {
            const dirEl = document.getElementById("privescDir");
            const svcEl = document.getElementById("privescServices");
            const st = document.getElementById("privescStatus");
            _btnPrivescScan.disabled = true; if (st) st.textContent = "Scanning… (services + ACLs, can take a few seconds)";
            try {
                const r = await fetch("/api/privesc_scan", {method:"POST", headers:{"Content-Type":"application/json"},
                    body: JSON.stringify({ target_dir:(dirEl&&dirEl.value||"").trim(), scan_services:!!(svcEl&&svcEl.checked) })});
                const d = await r.json();
                renderPrivesc(d.findings||[]);
                const c = d.counts||{};
                if (st) st.textContent = `${d.count} finding(s) — ${c.HIGH||0} high, ${c.MEDIUM||0} medium.`;
                const toV = document.getElementById("btnPrivescToVuln"); if (toV) toV.disabled = !(d.findings||[]).length;
            } catch(e) { if (st) st.textContent = "Error!"; console.error("privesc scan", e); }
            finally { _btnPrivescScan.disabled = false; }
        };
    }
    const _btnPrivescBrowse = document.getElementById("btnPrivescBrowse");
    if (_btnPrivescBrowse) _btnPrivescBrowse.onclick = async () => { const r=await fetch("/api/browse_file"); const d=await r.json(); if(d.path){ const el=document.getElementById("privescDir"); if(el) el.value=d.path; } };
    const _btnPrivescToVuln = document.getElementById("btnPrivescToVuln");
    if (_btnPrivescToVuln) _btnPrivescToVuln.onclick = async () => {
        const flagged = _privescFindings.filter(f => f.risk==="HIGH"||f.risk==="CRITICAL"||f.risk==="MEDIUM");
        if (!flagged.length) return;
        const findings = flagged.map(f => ({
            severity: f.risk==="CRITICAL"?"CRITICAL":(f.risk==="HIGH"?"HIGH":"MEDIUM"),
            title: `[Privesc] ${f.title}`,
            description: f.detail || "",
            evidence: `Target: ${f.target||""}` + ((f.principals||[]).length?`\nWriters: ${f.principals.map(p=>p.principal+" "+(p.rights||"")).join(", ")}`:""),
            verification_steps: ["Confirm the ACL with: icacls \"<target>\"", "Verify a low-priv user can write/plant at the target path."],
            exploitation_notes: f.remediation ? ("Remediation: "+f.remediation) : "",
        }));
        await _sendToVuln(findings, document.getElementById("privescStatus"), "privesc");
    };

    // ── Managed Secret scan ──────────────────────────────────────────────────
    let _secretsData = null;

    function _secNativeRows(findings) {
        const tbody = document.getElementById("tblNativeSecretsBody");
        if (!tbody) return;
        if (!findings.length) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-tertiary); padding:18px;">No secret-like strings found.</td></tr>`;
            return;
        }
        tbody.innerHTML = "";
        findings.forEach(f => {
            const tr = document.createElement("tr");
            if (f.severity === "HIGH") tr.style.background = "rgba(255,107,107,0.08)";
            const revealed = (f.value !== undefined && f.value !== null);
            const shown = revealed ? f.value : f.masked;
            tr.innerHTML = `
                <td>${_riskBadge(f.severity)}</td>
                <td style="font-size:0.74rem; font-family:'Fira Code',monospace; color:var(--text-secondary);">${escHtml(f.category||"")}</td>
                <td style="font-size:0.72rem; color:var(--text-tertiary);">${escHtml(f.enc||"")}</td>
                <td style="font-size:0.72rem; color:var(--text-tertiary); font-family:'Fira Code',monospace;">${escHtml(f.section||"-")}</td>
                <td style="font-size:0.72rem; color:var(--text-tertiary); font-family:'Fira Code',monospace;">0x${(f.offset||0).toString(16)}</td>
                <td style="font-size:0.73rem; text-align:center;">${f.length||0}</td>
                <td style="font-size:0.73rem; font-family:'Fira Code',monospace; color:${revealed?'#ff6b6b':'var(--text-secondary)'}; word-break:break-all;">${escHtml(String(shown==null?"":shown))}</td>
                <td title="${escHtml(f.sha256||"")}" style="font-size:0.68rem; font-family:'Fira Code',monospace; color:var(--text-tertiary);">${escHtml((f.sha256||"").slice(0,16))}</td>`;
            tbody.appendChild(tr);
        });
    }
    function _secManagedRows(findings) {
        const tbody = document.getElementById("tblSecretsBody");
        if (!tbody) return;
        tbody.innerHTML = "";
        if (!findings.length) {
            tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; color:var(--text-tertiary); padding:18px;">No secret-like managed members found.</td></tr>`;
            return;
        }
        findings.forEach(f => {
            const tr = document.createElement("tr");
            if (f.severity === "HIGH") tr.style.background = "rgba(255,107,107,0.08)";
            const revealed = (f.value !== undefined && f.value !== null);
            const shown = revealed ? f.value : f.masked_value;
            tr.innerHTML = `
                <td>${_riskBadge(f.severity)}</td>
                <td title="${escHtml(f.type||"")}" style="font-size:0.72rem; font-family:'Fira Code',monospace; color:var(--text-secondary); word-break:break-all;">${escHtml(f.type||"")}</td>
                <td style="font-size:0.76rem; font-weight:600;">${escHtml(f.member||"")}</td>
                <td style="font-size:0.72rem; color:var(--text-tertiary);">${escHtml(f.kind||"")}</td>
                <td style="font-size:0.72rem; color:var(--text-tertiary);">${f.is_public?"pub":"priv"}/${f.is_static?"stat":"inst"}</td>
                <td style="font-size:0.73rem; text-align:center;">${f.length||0}</td>
                <td style="font-size:0.73rem; font-family:'Fira Code',monospace; color:${revealed?'#ff6b6b':'var(--text-secondary)'}; word-break:break-all;">${escHtml(String(shown==null?"":shown))}</td>
                <td title="${escHtml(f.sha256||"")}" style="font-size:0.68rem; font-family:'Fira Code',monospace; color:var(--text-tertiary);">${escHtml((f.sha256||"").slice(0,16))}</td>
                <td style="font-size:0.72rem; color:var(--text-secondary); font-family:'Fira Code',monospace;">${escHtml(f.risk_label||"")}</td>`;
            tbody.appendChild(tr);
        });
    }
    function renderSecrets(data) {
        _secretsData = data;
        const native = (data && data.native) || { findings: [] };
        const nf = native.findings || [];
        _secNativeRows(nf);
        const nmeta = document.getElementById("secretsNativeMeta");
        if (nmeta) nmeta.textContent = data ? `— ${nf.length} inventory item(s), ${((native.scanned_bytes||0)/1048576).toFixed(1)}MB scanned${native.file_truncated || native.results_truncated ? " — partial scan (limit reached)" : ""}${native.packed?" — few readable strings":""}` : "";
        const managedSec = document.getElementById("secretsManagedSection");
        const managed = data && data.managed;
        const mf = (managed && managed.findings) || [];
        const exportButton = document.getElementById("btnSecretsExport");
        if (exportButton) exportButton.disabled = !(nf.length + mf.length);
        const reviewButton = document.getElementById("btnSecretsToVuln");
        if (reviewButton) reviewButton.disabled = !nf.some(f => f.validation_status === "needs_review") && !mf.some(f => f.value_available && f.validation_status === "needs_review");
        if (data && data.is_dotnet && managed) {
            if (managedSec) managedSec.style.display = "";
            _secManagedRows(mf);
        } else if (managedSec) {
            managedSec.style.display = "none";
        }
        const meta = document.getElementById("secretsMeta");
        if (meta && data) {
            meta.textContent = data.is_dotnet
                ? `.NET (${data.arch||""}) — native strings + reflection [${((managed&&managed.mode)||"safe").toUpperCase()}]. ${nf.length} native + ${mf.length} managed inventory items.`
                : `Native binary (${data.arch||"non-.NET"}) — ${Object.entries(native.counts || {}).map(([kind, count]) => `${kind}: ${count}`).join(" · ") || `${nf.length} inventory items`}. No credential validity or vulnerability is assumed.`;
        }
    }
    const _btnSecretsScan = document.getElementById("btnSecretsScan");
    if (_btnSecretsScan) {
        _btnSecretsScan.onclick = async () => {
            const pathEl = document.getElementById("secretsPath");
            const revEl = document.getElementById("secretsReveal");
            const deepEl = document.getElementById("secretsDeep");
            const st = document.getElementById("secretsStatus");
            const path = (pathEl&&pathEl.value||"").trim();
            if (!path) { if(st) st.textContent="Enter or browse a file path."; return; }
            const deep = !!(deepEl&&deepEl.checked);
            if (deep && !confirm("DEEP scan runs the TARGET .NET assembly's static constructors — it EXECUTES code from the target binary in a child process (only applies if the file is .NET).\n\nOnly do this on a binary you trust or in an isolated VM.\n\nProceed with deep scan?")) return;
            _btnSecretsScan.disabled=true; if(st) st.textContent = "Scanning…";
            try {
                const r = await fetch("/api/managed_secret_scan", {method:"POST", headers:{"Content-Type":"application/json"},
                    body: JSON.stringify({ path, reveal: !!(revEl&&revEl.checked), deep })});
                const d = await r.json();
                if (d.status!=="ok") { if(st) st.textContent = "Error: "+(d.message||"scan failed"); renderSecrets(null); return; }
                renderSecrets(d);
                const nc = (d.native&&d.native.count)||0, mc = (d.managed&&d.managed.count)||0;
                if (st) st.textContent = d.is_dotnet ? `${nc} native + ${mc} managed inventory items.` : `${nc} native inventory items (not .NET).`;
                const any = (nc + mc) > 0;
                const ex=document.getElementById("btnSecretsExport"); if(ex) ex.disabled=!any;
                const tv=document.getElementById("btnSecretsToVuln"); if(tv) tv.disabled=!(d.native?.findings || []).some(f => f.validation_status === "needs_review") && !(d.managed?.findings || []).some(f => f.value_available && f.validation_status === "needs_review");
            } catch(e){ if(st) st.textContent="Error!"; console.error("secret scan", e); }
            finally { _btnSecretsScan.disabled=false; }
        };
    }
    const _btnSecretsBrowse = document.getElementById("btnSecretsBrowse");
    if (_btnSecretsBrowse) _btnSecretsBrowse.onclick = async () => { const r=await fetch("/api/browse_file"); const d=await r.json(); if(d.path){ const el=document.getElementById("secretsPath"); if(el) el.value=d.path; } };
    const _btnSecretsExport = document.getElementById("btnSecretsExport");
    if (_btnSecretsExport) _btnSecretsExport.onclick = () => {
        if (!_secretsData) return;
        const blob = new Blob([JSON.stringify(_secretsData, null, 2)], {type:"application/json"});
        const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
        a.download = "secrets.json"; a.click(); URL.revokeObjectURL(a.href);
    };
    const _btnSecretsToVuln = document.getElementById("btnSecretsToVuln");
    if (_btnSecretsToVuln) _btnSecretsToVuln.onclick = async () => {
        const out = [];
        ((_secretsData&&_secretsData.native&&_secretsData.native.findings)||[]).filter(f => f.validation_status === "needs_review").forEach(f => out.push({
            severity: "INFO",
            title: `[Embedded candidate] ${f.category} @ 0x${(f.offset||0).toString(16)}`,
            description: f.basis || "A labelled literal was extracted; credential validity and security impact are unverified.",
            evidence: `SHA-256: ${f.sha256||""}\nMasked: ${f.masked||""}`,
            verification_steps: ["Open the binary in a hex editor / disassembler at the offset and confirm the secret.", "Rotate the secret if it is live."],
            exploitation_notes: "",
        }));
        ((_secretsData&&_secretsData.managed&&_secretsData.managed.findings)||[]).filter(f => f.value_available && f.validation_status === "needs_review").forEach(f => out.push({
            severity: "INFO",
            title: `[Managed Secret] ${f.risk_label} — ${f.type}.${f.member}`,
            description: `Static ${f.kind} '${f.member}' (${f.value_type}, len ${f.length}) in ${f.type} looks like ${f.risk_label}.`,
            evidence: `SHA-256: ${f.sha256||""}\nMasked: ${f.masked_value||""}`,
            verification_steps: ["Open the assembly in dnSpy/ILSpy and inspect the member initializer.", "Correlate the SHA-256 with runtime crypto-boundary events if the process is hooked."],
            exploitation_notes: "Validity and impact unverified; runtime static fields are not proof of hardcoding.",
        }));
        if (!out.length) return;
        await _sendToVuln(out, document.getElementById("secretsStatus"), "secret");
    };

    // ── Memory credential scan (Tier-2: cred scan + post-logout cleanup) ──────
    let _credFindings = [];
    function renderCredScan(data) {
        _credFindings = (data && data.findings) || [];
        const st = document.getElementById("credScanStatus");
        const tbody = document.getElementById("tblCredScanBody");
        if (st && data) {
            const t = data.truncated ? " (truncated — budget hit)" : "";
            st.textContent = `${data.phase||"scan"}: ${_credFindings.length} finding(s), ${(data.scanned_bytes/1048576)|0}MB scanned${t}.`;
        }
        if (!tbody) return;
        if (!_credFindings.length) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-tertiary); padding:18px;">No credential-like material found in memory.</td></tr>`;
            return;
        }
        tbody.innerHTML = "";
        _credFindings.forEach(f => {
            const tr = document.createElement("tr");
            const notCleared = f.status && f.status.indexOf("NOT CLEARED") >= 0;
            if (f.severity === "HIGH") tr.style.background = "rgba(255,107,107,0.08)";
            tr.innerHTML = `
                <td>${_riskBadge(f.severity||"MEDIUM")}</td>
                <td style="font-size:0.74rem; font-family:'Fira Code',monospace; color:var(--text-secondary);">${escHtml(f.category||"")}</td>
                <td style="font-size:0.72rem; color:var(--text-tertiary);">${escHtml(f.enc||"")}</td>
                <td style="font-size:0.72rem; font-family:'Fira Code',monospace; color:var(--text-tertiary);">${escHtml(f.addr||"")}</td>
                <td style="font-size:0.73rem; text-align:center;">${f.len||0}</td>
                <td style="font-size:0.73rem; font-family:'Fira Code',monospace;">${escHtml(f.masked||"")}</td>
                <td style="font-size:0.74rem; color:${notCleared ? '#ff6b6b' : 'var(--text-secondary)'};">${escHtml(f.status||"present")}</td>`;
            tbody.appendChild(tr);
        });
    }
    async function _credScan(phase) {
        const st = document.getElementById("credScanStatus");
        if (st) st.textContent = phase === "after" ? "Re-scanning memory (after logout)…" : "Scanning memory…";
        try {
            const r = await fetch("/api/memory_cred_scan", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({phase})});
            const d = await r.json();
            if (d.status !== "ok") { if (st) st.textContent = "Error: "+(d.message||"scan failed (is a process hooked?)"); return; }
            renderCredScan(d);
            const after = document.getElementById("btnCredScanAfter"); if (after) after.disabled = false;
            const tv = document.getElementById("btnCredToVuln"); if (tv) tv.disabled = !(d.findings||[]).length;
        } catch(e) { if (st) st.textContent = "Error!"; console.error("cred scan", e); }
    }
    const _btnCredBefore = document.getElementById("btnCredScanBefore");
    if (_btnCredBefore) _btnCredBefore.onclick = () => _credScan("before");
    const _btnCredAfter = document.getElementById("btnCredScanAfter");
    if (_btnCredAfter) _btnCredAfter.onclick = () => _credScan("after");
    const _btnCredToVuln = document.getElementById("btnCredToVuln");
    if (_btnCredToVuln) _btnCredToVuln.onclick = async () => {
        const findings = _credFindings.map(f => {
            const notCleared = f.status && f.status.indexOf("NOT CLEARED") >= 0;
            return {
                severity: f.severity || "MEDIUM",
                title: `[Memory Cred] ${f.category}${notCleared ? ' — not cleared after logout' : ''} @ ${f.addr}`,
                description: `Credential-like ${f.category} (${f.enc}, len ${f.len}) found in process memory at ${f.addr}. ${f.status||""}`,
                evidence: `Masked: ${f.masked||""}\nfp: ${f.fp||""}`,
                verification_steps: ["Re-run the scan after logging out to confirm the secret is (not) cleared.", "Correlate the address with the app's credential handling."],
                exploitation_notes: "Secrets left in process memory can be recovered by a local attacker or a memory dump.",
            };
        });
        if (!findings.length) return;
        await _sendToVuln(findings, document.getElementById("credScanStatus"), "memcreds");
    };

    const pipeSearchEl = document.getElementById("pipeSearch");
    if (pipeSearchEl) pipeSearchEl.oninput = (e) => { pipeSearchText = e.target.value.trim(); rebuildPipeTable(); };

    const btnListPipes = document.getElementById("btnListPipes");
    if (btnListPipes) btnListPipes.onclick = () => loadPipes(false);

    const btnScanPipes = document.getElementById("btnScanPipes");
    if (btnScanPipes) btnScanPipes.onclick = () => loadPipes(true);

    // ── Pipe Interactive Client ───────────────────────────────────────────────

    async function openPipeClientPanel(pipeName) {
        const panel = document.getElementById("pipeClientPanel");
        const nameEl = document.getElementById("pipeClientName");
        const recvArea = document.getElementById("pipeRecvArea");
        if (!panel) return;
        // Close any existing connection before switching pipes
        if (activePipeId !== null) {
            try { await fetch("/api/pipe/close", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({pipe_id: activePipeId})}); } catch(e) {}
            activePipeId = null;
            _stopRecvPoll();
        }
        panel.style.display = "flex";
        panel.style.flexDirection = "column";
        if (nameEl) nameEl.textContent = `\\\\.\\pipe\\${pipeName}`;
        panel.dataset.targetPipe = pipeName;
        if (recvArea) recvArea.innerHTML = "";
        _updatePipeClientUI(false);

        // Show pipe info hint in recv area header area
        const pInfo = pipeData.find(p => p.name === pipeName);
        const hintEl = document.getElementById("pipeHintBox");
        if (hintEl) {
            let html = "";
            if (pInfo && pInfo.hint) {
                html += `${_catBadge(pInfo.category)}<span style="color:var(--text-secondary); font-size:0.74rem;">${escHtml(pInfo.hint)}</span>`;
            }
            // DACL security detail: risk badge, owner, risky ACEs, and raw SDDL.
            if (pInfo && pInfo.risk) {
                const aces = (pInfo.risky_aces || [])
                    .map(a => `${escHtml(a.name)} (${escHtml(a.mask)})`).join(", ");
                html += `<div style="margin-top:5px; font-size:0.72rem; line-height:1.6;">`
                     +  `${_pipeDaclBadge(pInfo)} <span style="color:var(--text-secondary);">${escHtml(pInfo.risk_reason || "")}</span>`
                     +  (pInfo.owner ? `<br><span style="color:var(--text-tertiary);">owner:</span> <span style="color:var(--text-secondary);">${escHtml(pInfo.owner)}</span>` : "")
                     +  (aces ? `<br><span style="color:var(--text-tertiary);">risky ACEs:</span> <span style="color:#ff8c00;">${aces}</span>` : "")
                     +  (pInfo.sddl ? `<br><span style="color:var(--text-tertiary);">SDDL:</span> <code style="color:var(--text-secondary); font-size:0.7rem;">${escHtml(pInfo.sddl)}</code>` : "")
                     +  `</div>`;
            }
            hintEl.innerHTML = html;
            hintEl.style.display = html ? "block" : "none";
        }
    }

    function _updatePipeClientUI(connected) {
        const btnConn = document.getElementById("btnPipeConnect");
        const btnSend = document.getElementById("btnPipeSend");
        const statusEl = document.getElementById("pipeClientStatus");
        if (btnConn) {
            btnConn.textContent = connected ? "Disconnect" : "Connect";
            btnConn.className   = connected ? "btn btn-danger" : "btn btn-success";
        }
        if (btnSend) btnSend.disabled = !connected;
        if (statusEl) {
            statusEl.textContent = connected ? "Connected" : "Disconnected";
            statusEl.style.color = connected ? "#9ece6a" : "var(--text-tertiary)";
        }
    }

    function _appendRecv(text, isHex, rawHex) {
        const area = document.getElementById("pipeRecvArea");
        if (!area) return;
        if (rawHex) {
            const decoded = _msrpcDecode(rawHex);
            if (decoded) {
                const badge = document.createElement("div");
                badge.style.cssText = "padding:2px 6px; font-size:0.69rem; font-weight:700; color:#9ece6a; background:rgba(158,206,106,0.1); border-radius:3px; margin-bottom:2px; border:1px solid rgba(158,206,106,0.2); font-family:'Fira Code',monospace;";
                badge.textContent = "MSRPC: " + decoded;
                area.appendChild(badge);
            }
        }
        const line = document.createElement("div");
        line.style.cssText = "border-bottom:1px solid var(--border-color); padding:2px 0 4px; word-break:break-all; font-family:'Fira Code',monospace; font-size:0.75rem;";
        line.style.color = isHex ? "#7dcfff" : "var(--text-primary)";
        line.textContent = text;
        area.appendChild(line);
        area.scrollTop = area.scrollHeight;
    }

    function _stopRecvPoll() {
        if (pipeRecvTimer) { clearInterval(pipeRecvTimer); pipeRecvTimer = null; }
    }

    function _startRecvPoll() {
        _stopRecvPoll();
        pipeRecvTimer = setInterval(async () => {
            if (activePipeId === null) { _stopRecvPoll(); return; }
            try {
                const r = await fetch("/api/pipe/recv", {
                    method: "POST",
                    headers: {"Content-Type":"application/json"},
                    body: JSON.stringify({pipe_id: activePipeId})
                });
                const d = await r.json();
                if (d.bytes > 0) {
                    const rawHex = d.data_hex || "";
                    if (pipeSendFmt === "hex") {
                        const hexStr = rawHex.match(/.{1,2}/g).join(" ");
                        _appendRecv(hexStr, true, rawHex);
                    } else {
                        _appendRecv(d.data || "", false, rawHex);
                    }
                }
            } catch(e) {}
        }, 500);
    }

    const btnPipeConnect = document.getElementById("btnPipeConnect");
    if (btnPipeConnect) {
        btnPipeConnect.onclick = async () => {
            const panel = document.getElementById("pipeClientPanel");
            if (!panel) return;
            const pipeName = panel.dataset.targetPipe;
            if (activePipeId !== null) {
                // disconnect
                try { await fetch("/api/pipe/close", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({pipe_id: activePipeId})}); } catch(e) {}
                activePipeId = null;
                _stopRecvPoll();
                _updatePipeClientUI(false);
                return;
            }
            btnPipeConnect.disabled = true;
            try {
                const r = await fetch("/api/pipe/connect", {
                    method: "POST",
                    headers: {"Content-Type":"application/json"},
                    body: JSON.stringify({name: pipeName})
                });
                const d = await r.json();
                if (d.pipe_id !== undefined && d.pipe_id !== null) {
                    activePipeId = d.pipe_id;
                    _updatePipeClientUI(true);
                    _startRecvPoll();
                } else {
                    const statusEl = document.getElementById("pipeClientStatus");
                    if (statusEl) { statusEl.textContent = `Error: ${d.message || d.error || "connect failed"}`; statusEl.style.color="#f7768e"; }
                }
            } catch(e) {
                console.error("Pipe connect error:", e);
            } finally {
                btnPipeConnect.disabled = false;
            }
        };
    }

    const btnPipeSend = document.getElementById("btnPipeSend");
    if (btnPipeSend) {
        btnPipeSend.onclick = async () => {
            if (activePipeId === null) return;
            const area = document.getElementById("pipeSendArea");
            const raw = area ? area.value : "";
            if (!raw) return;
            const sendData = pipeSendFmt === "hex" ? raw.replace(/\s+/g, "") : raw;
            btnPipeSend.disabled = true;
            btnPipeSend.textContent = "Sending…";
            try {
                const r = await fetch("/api/pipe/send", {
                    method: "POST",
                    headers: {"Content-Type":"application/json"},
                    body: JSON.stringify({pipe_id: activePipeId, data: sendData, fmt: pipeSendFmt})
                });
                const d = await r.json();
                if (d.status === "ok") {
                    btnPipeSend.textContent = "Sent ✓";
                    setTimeout(() => { btnPipeSend.textContent = "Send"; btnPipeSend.disabled = false; }, 800);
                } else {
                    btnPipeSend.textContent = "Error";
                    setTimeout(() => { btnPipeSend.textContent = "Send"; btnPipeSend.disabled = false; }, 1500);
                }
            } catch(e) {
                console.error("Pipe send error:", e);
                btnPipeSend.textContent = "Error";
                setTimeout(() => { btnPipeSend.textContent = "Send"; btnPipeSend.disabled = false; }, 1500);
            }
        };
    }

    // Send format toggles — auto-convert textarea content on switch
    const pipeFmtUtf8 = document.getElementById("pipeSendFmtUtf8");
    const pipeFmtHex  = document.getElementById("pipeSendFmtHex");

    function _setPipeFmt(fmt) {
        if (fmt === pipeSendFmt) return;
        const area = document.getElementById("pipeSendArea");
        const val  = area ? area.value : "";
        if (area && val.trim()) {
            try {
                if (fmt === "hex" && pipeSendFmt === "utf8") {
                    // UTF-8 text → hex pairs
                    const bytes = new TextEncoder().encode(val);
                    area.value = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join(" ");
                } else if (fmt === "utf8" && pipeSendFmt === "hex") {
                    // hex pairs → UTF-8 text
                    const clean = val.replace(/\s+/g, "");
                    const pairs = clean.match(/.{1,2}/g) || [];
                    const bytes = new Uint8Array(pairs.map(h => parseInt(h, 16)));
                    area.value  = new TextDecoder("utf-8", {fatal: false}).decode(bytes);
                }
            } catch(e) { /* leave textarea unchanged if conversion fails */ }
        }
        pipeSendFmt = fmt;
        if (pipeFmtUtf8) { pipeFmtUtf8.className = fmt==="utf8" ? "btn btn-primary" : "btn btn-neutral"; }
        if (pipeFmtHex)  { pipeFmtHex.className  = fmt==="hex"  ? "btn btn-primary" : "btn btn-neutral"; }
    }
    if (pipeFmtUtf8) pipeFmtUtf8.onclick = () => _setPipeFmt("utf8");
    if (pipeFmtHex)  pipeFmtHex.onclick  = () => _setPipeFmt("hex");

    // ── Templates dropdown ────────────────────────────────────────────────────
    function _populateTemplates(currentPipeName) {
        const dd = document.getElementById("pipeTemplateDropdown");
        if (!dd) return;
        dd.innerHTML = "";
        const lower = (currentPipeName || "").toLowerCase();

        // Header
        const hdr = document.createElement("div");
        hdr.style.cssText = "padding:4px 10px; font-size:0.68rem; font-weight:700; color:var(--text-tertiary); text-transform:uppercase; letter-spacing:0.6px;";
        hdr.textContent = "MSRPC BIND Requests";
        dd.appendChild(hdr);

        Object.entries(_MSRPC_UUIDS).forEach(([key, def]) => {
            const match = lower.includes(key);
            const item = document.createElement("div");
            item.style.cssText = `padding:5px 10px; font-size:0.78rem; cursor:pointer; display:flex; align-items:center; gap:6px; color:${match ? "var(--text-primary)" : "var(--text-secondary)"};`;
            item.onmouseenter = () => item.style.background = "var(--bg-raised)";
            item.onmouseleave = () => item.style.background = "";
            if (match) {
                const dot = document.createElement("span");
                dot.textContent = "●";
                dot.style.cssText = "color:#9ece6a; font-size:0.6rem; flex-shrink:0;";
                item.appendChild(dot);
            }
            const lbl = document.createElement("span");
            lbl.textContent = def.label;
            item.appendChild(lbl);
            item.onclick = () => {
                const area = document.getElementById("pipeSendArea");
                if (area) {
                    area.value = _buildMsrpcBind(def.uuid, def.ver);
                    _setPipeFmt("hex");
                }
                dd.style.display = "none";
            };
            dd.appendChild(item);
        });
    }

    const btnPipeTemplates = document.getElementById("btnPipeTemplates");
    if (btnPipeTemplates) {
        btnPipeTemplates.onclick = (e) => {
            e.stopPropagation();
            const dd = document.getElementById("pipeTemplateDropdown");
            if (!dd) return;
            const panel = document.getElementById("pipeClientPanel");
            const pipeName = panel ? (panel.dataset.targetPipe || "") : "";
            _populateTemplates(pipeName);
            dd.style.display = dd.style.display === "none" ? "block" : "none";
        };
    }
    document.addEventListener("click", () => {
        const dd = document.getElementById("pipeTemplateDropdown");
        if (dd) dd.style.display = "none";
    });

    const btnPipeClearRecv = document.getElementById("btnPipeClearRecv");
    if (btnPipeClearRecv) btnPipeClearRecv.onclick = () => {
        const area = document.getElementById("pipeRecvArea");
        if (area) area.innerHTML = "";
    };

    const pipeClientCloseBtn = document.getElementById("pipeClientCloseBtn");
    if (pipeClientCloseBtn) pipeClientCloseBtn.onclick = async () => {
        if (activePipeId !== null) {
            try { await fetch("/api/pipe/close", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({pipe_id: activePipeId})}); } catch(e) {}
            activePipeId = null;
            _stopRecvPoll();
        }
        const panel = document.getElementById("pipeClientPanel");
        if (panel) panel.style.display = "none";
    };

    // ── Child Process Monitor ─────────────────────────────────────────────────

    function flashTabBtn(targetId) {
        const btn = document.querySelector(`.tab-btn[data-target="${targetId}"]`);
        if (!btn) return;
        btn.style.transition = "background 0.15s";
        btn.style.background = "rgba(255,107,107,0.35)";
        setTimeout(() => { btn.style.background = ""; }, 1800);
    }

    function _processMatchesFilter(ev) {
        if (processElevatedOnly && !ev.elevated) return false;
        if (!processSearchText) return true;
        const q = processSearchText.toLowerCase();
        return (ev.exe   || "").toLowerCase().includes(q)
            || (ev.args  || "").toLowerCase().includes(q)
            || (ev.caller_mod || "").toLowerCase().includes(q)
            || (ev.api   || "").toLowerCase().includes(q);
    }

    function renderProcessRow(ev) {
        const tbody = document.getElementById("tblProcessesBody");
        if (!tbody || !_processMatchesFilter(ev)) return;
        const rowId = "proc-row-" + processEvents.indexOf(ev);
        const tr = document.createElement("tr");
        tr.id = rowId;
        if (ev.elevated) tr.style.cssText = "background:rgba(255,107,107,0.10);";
        const verbBadge = ev.verb
            ? `<span style="margin-left:5px; padding:1px 5px; border-radius:3px; font-size:0.68rem; background:rgba(224,175,104,0.2); color:#e0af68;">${escHtml(ev.verb)}</span>`
            : "";
        tr.innerHTML = `
            <td>${processEvents.length}</td>
            <td>${escHtml(ev._ts || "")}</td>
            <td><span style="font-size:0.74rem; padding:1px 5px; border-radius:3px; background:var(--bg-raised); color:var(--text-secondary);">${escHtml(ev.api || "")}</span></td>
            <td style="font-family:var(--font-mono); font-size:0.77rem; word-break:break-all;">${escHtml(ev.exe || "")}</td>
            <td style="font-family:var(--font-mono); font-size:0.77rem; word-break:break-all; color:var(--text-secondary);">${escHtml(ev.args || "")}${verbBadge}</td>
            <td style="text-align:center;">${ev.elevated ? '<span style="color:#ff6b6b; font-weight:700;">YES</span>' : '<span style="color:var(--text-tertiary);">—</span>'}</td>
            <td style="font-size:0.77rem; color:var(--text-tertiary);">${escHtml(ev.caller_mod || "")}</td>`;
        tbody.appendChild(tr);
        while (tbody.rows.length > 1000) tbody.deleteRow(0);
        const countEl = document.getElementById("processCount");
        if (countEl) countEl.textContent = processEvents.length + " processes";
    }

    function rebuildProcessTable() {
        const tbody = document.getElementById("tblProcessesBody");
        if (!tbody) return;
        tbody.innerHTML = "";
        processEvents.forEach(ev => renderProcessRow(ev));
        const countEl = document.getElementById("processCount");
        if (countEl) countEl.textContent = processEvents.length + " processes";
    }

    const processSearchEl = document.getElementById("processSearch");
    if (processSearchEl) {
        processSearchEl.oninput = () => {
            processSearchText = processSearchEl.value.trim();
            rebuildProcessTable();
        };
    }

    const processElevatedOnlyEl = document.getElementById("processElevatedOnly");
    if (processElevatedOnlyEl) {
        processElevatedOnlyEl.onchange = () => {
            processElevatedOnly = processElevatedOnlyEl.checked;
            rebuildProcessTable();
        };
    }

    const btnClearProcesses = document.getElementById("btnClearProcesses");
    if (btnClearProcesses) {
        btnClearProcesses.onclick = () => {
            processEvents = [];
            const tbody = document.getElementById("tblProcessesBody");
            if (tbody) tbody.innerHTML = "";
            const countEl = document.getElementById("processCount");
            if (countEl) countEl.textContent = "0 processes";
        };
    }

    // ── Crypto Monitor (DPAPI / CNG / CryptoAPI plaintext) ────────────────────
    function _cryptoIsSecret(ev) { return ev.op === "unprotect" || ev.op === "decrypt"; }

    function _cryptoMatchesFilter(ev) {
        if (cryptoSecretsOnly && !_cryptoIsSecret(ev)) return false;
        if (!cryptoSearchText) return true;
        const q = cryptoSearchText.toLowerCase();
        return (ev.api || "").toLowerCase().includes(q)
            || (ev.op  || "").toLowerCase().includes(q)
            || (ev.body|| "").toLowerCase().includes(q);
    }

    function _cryptoPreview(ev) {
        // Prefer printable UTF-8; fall back to spaced hex for binary blobs.
        const raw = ev.body || "";
        if (raw) {
            const printable = (raw.match(/[\x20-\x7E]/g) || []).length;
            if (printable >= raw.length * 0.6) return raw.slice(0, 300);
        }
        const hex = ev.body_hex || "";
        return hex ? (hex.match(/../g) || []).join(" ").slice(0, 300) : "";
    }

    function renderCryptoRow(ev) {
        const tbody = document.getElementById("tblCryptoBody");
        if (!tbody || !_cryptoMatchesFilter(ev)) return;
        const secret = _cryptoIsSecret(ev);
        const tr = document.createElement("tr");
        if (secret) tr.style.cssText = "background:rgba(158,206,106,0.08);";
        const opColor = secret ? "#9ece6a" : "#7aa2f7";
        const opBadge = `<span style="padding:1px 6px; border-radius:3px; font-size:0.7rem; font-weight:600; background:${opColor}22; color:${opColor};">${escHtml(ev.op || "")}</span>`;
        let flags = "";
        if (ev.dpapi_local_machine) flags += ` <span title="DPAPI LOCAL_MACHINE scope: any user or process on this host can decrypt this blob" style="padding:1px 5px; border-radius:3px; font-size:0.66rem; background:rgba(255,68,68,0.18); color:#ff6b6b;">LOCAL_MACHINE</span>`;
        if (ev.dpapi_entropy === false && (ev.api || "").indexOf("Data") !== -1) flags += ` <span title="DPAPI called without secondary entropy — weaker protection" style="padding:1px 5px; border-radius:3px; font-size:0.66rem; background:rgba(224,175,104,0.18); color:#e0af68;">no-entropy</span>`;
        const idx = sessionCapture.cryptoEvents.indexOf(ev) + 1;
        tr.innerHTML = `
            <td>${idx}</td>
            <td>${escHtml(ev.ts || "")}</td>
            <td style="font-family:var(--font-mono); font-size:0.75rem; word-break:break-all;">${escHtml(ev.api || "")}</td>
            <td>${opBadge}</td>
            <td style="text-align:right; color:var(--text-secondary);">${ev.size | 0}</td>
            <td style="font-family:var(--font-mono); font-size:0.76rem; word-break:break-all; white-space:pre-wrap;">${escHtml(_cryptoPreview(ev))}${flags}</td>`;
        tbody.appendChild(tr);
        while (tbody.rows.length > 1000) tbody.deleteRow(0);
        const countEl = document.getElementById("cryptoCount");
        if (countEl) countEl.textContent = sessionCapture.cryptoEvents.length + " events";
    }

    function rebuildCryptoTable() {
        const tbody = document.getElementById("tblCryptoBody");
        if (!tbody) return;
        tbody.innerHTML = "";
        sessionCapture.cryptoEvents.forEach(ev => renderCryptoRow(ev));
        const countEl = document.getElementById("cryptoCount");
        if (countEl) countEl.textContent = sessionCapture.cryptoEvents.length + " events";
    }

    const cryptoSearchEl = document.getElementById("cryptoSearch");
    if (cryptoSearchEl) cryptoSearchEl.oninput = () => { cryptoSearchText = cryptoSearchEl.value.trim(); rebuildCryptoTable(); };

    const cryptoSecretsOnlyEl = document.getElementById("cryptoSecretsOnly");
    if (cryptoSecretsOnlyEl) cryptoSecretsOnlyEl.onchange = () => { cryptoSecretsOnly = cryptoSecretsOnlyEl.checked; rebuildCryptoTable(); };

    const btnClearCrypto = document.getElementById("btnClearCrypto");
    if (btnClearCrypto) btnClearCrypto.onclick = () => {
        sessionCapture.cryptoEvents = [];
        const tbody = document.getElementById("tblCryptoBody");
        if (tbody) tbody.innerHTML = "";
        const countEl = document.getElementById("cryptoCount");
        if (countEl) countEl.textContent = "0 events";
    };

    // ── Function Faker (live return-value / trace hooks) ──────────────────────
    function fakerTargetLabel(r) {
        return r.symbol ? ((r.module ? r.module + "!" : "") + r.symbol) : ((r.module || "") + "+" + (r.offset || ""));
    }

    function renderFakerRules() {
        const tbody = document.getElementById("tblFakerRules");
        if (!tbody) return;
        const ids = Object.keys(fakerRules);
        if (!ids.length) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-tertiary); padding:24px;">No faker hooks yet. Try <strong>kernel32.dll</strong> + <strong>IsDebuggerPresent</strong> with value <strong>0</strong>, or your app's <strong>IsLicenseValid</strong> with <strong>1</strong>, then <strong>Add hook</strong>.</td></tr>`;
            return;
        }
        tbody.innerHTML = "";
        ids.forEach(id => {
            const r = fakerRules[id];
            const modeBadge = r.mode === "return"
                ? `<span style="color:#ff8c00; font-weight:600;">force ret</span>`
                : `<span style="color:#7aa2f7;">trace</span>`;
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td style="font-family:var(--font-mono); font-size:0.77rem; word-break:break-all;">${escHtml(fakerTargetLabel(r))}</td>
                <td>${modeBadge}</td>
                <td style="font-family:var(--font-mono);">${r.mode === "return" ? escHtml(r.value) : "—"}</td>
                <td style="text-align:center;" id="faker-hits-${escHtml(id)}">${r.hits | 0}</td>
                <td style="font-family:var(--font-mono); font-size:0.72rem; color:var(--text-tertiary);">${escHtml(r.addr || "")}</td>
                <td style="text-align:center;"><button class="faker-remove-btn" data-id="${escHtml(id)}" style="background:none; border:1px solid var(--border-color); color:#ff6b6b; border-radius:4px; padding:1px 8px; font-size:0.72rem; cursor:pointer;">remove</button></td>`;
            tbody.appendChild(tr);
        });
        tbody.querySelectorAll(".faker-remove-btn").forEach(b => {
            b.onclick = () => { if (ws) ws.send(JSON.stringify({ action: "faker_remove", id: b.dataset.id })); };
        });
    }

    const btnFakerAdd = document.getElementById("btnFakerAdd");
    if (btnFakerAdd) btnFakerAdd.onclick = () => {
        const module = (document.getElementById("fakerModule").value || "").trim();
        const symbol = (document.getElementById("fakerSymbol").value || "").trim();
        const offset = (document.getElementById("fakerOffset").value || "").trim();
        const mode   = document.getElementById("fakerMode").value;
        const value  = (document.getElementById("fakerValue").value || "1").trim();
        if (!symbol && !offset) { showToast("Enter a function name or an offset.", "error"); return; }
        if (offset && !module) { showToast("An offset needs a module.", "error"); return; }
        if (!ws) { showToast("Not connected.", "error"); return; }
        const id = "f" + (++fakerRuleSeq);
        const st = document.getElementById("fakerStatus");
        if (st) { st.textContent = "installing " + (symbol || module + "+" + offset) + "..."; st.style.color = "var(--text-tertiary)"; }
        ws.send(JSON.stringify({ action: "faker_add", id, module, symbol, offset, mode, value }));
    };

    const btnFakerFind = document.getElementById("btnFakerFind");
    if (btnFakerFind) btnFakerFind.onclick = () => {
        const module = (document.getElementById("fakerModule").value || "").trim();
        const query  = (document.getElementById("fakerSymbol").value || "").trim();
        if (!module) { showToast("Enter a module to search its exports.", "error"); return; }
        const box = document.getElementById("fakerSearchBox");
        if (query.length < 2) {
            if (box) { box.style.display = "block"; box.innerHTML = `<span style="color:var(--text-tertiary); font-size:0.76rem;">Type at least 2 letters of the function name in the <strong>Function name</strong> field first, then Find fn — e.g. <code>Debugger</code>.</span>`; }
            return;
        }
        if (!ws) return;
        if (box) { box.style.display = "block"; box.innerHTML = `<span style="color:var(--text-tertiary); font-size:0.76rem;">searching ${escHtml(module)} for "${escHtml(query)}"...</span>`; }
        ws.send(JSON.stringify({ action: "faker_search", module, query }));
    };

    const btnFakerClearHits = document.getElementById("btnFakerClearHits");
    if (btnFakerClearHits) btnFakerClearHits.onclick = () => { const l = document.getElementById("fakerHitLog"); if (l) l.innerHTML = ""; };

    // Refresh the rules table from live Frida state whenever the tab is opened
    // (restores it after a browser reconnect — the hooks live in the process).
    const tabBtnFaker = document.getElementById("tabBtnFaker");
    if (tabBtnFaker) tabBtnFaker.addEventListener("click", () => { if (ws) ws.send(JSON.stringify({ action: "faker_list" })); });

    // ─────────────────────────────────────────────────────────────────────────

    const btnNewSession = document.getElementById("btnNewSession");
    if (btnNewSession) {
        btnNewSession.onclick = async () => {
            if (!confirm("Start a new session? This will clear all captured data.")) return;
            await fetch("/api/new_session", { method: "POST" });
        };
    }

    const btnSaveHistory = document.getElementById("btnSaveHistory");
    if (btnSaveHistory) {
        btnSaveHistory.onclick = async () => {
            try {
                btnSaveHistory.textContent = "Saving...";
                btnSaveHistory.disabled = true;
                const resp = await fetch("/api/export_session");
                if (!resp.ok) throw new Error(`Server returned HTTP ${resp.status}`);
                const data = await resp.json();
                data.vuln_findings = window.SafiyeUI.annotateFindings(data.vuln_findings || []);
                data.vuln_observations = window.SafiyeUI.annotateFindings(data.vuln_observations || []);
                Object.keys(data.vuln_sources || {}).forEach(source => {
                    data.vuln_sources[source] = window.SafiyeUI.annotateFindings(data.vuln_sources[source]);
                });
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                if (blob.size > 128 * 1024 * 1024) throw new Error("Session exceeds the 128 MiB archive limit.");
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
                a.download = `safiye_session_${ts}.json`;
                a.click();
                setTimeout(() => URL.revokeObjectURL(url), 1000);
                addVulnLog(`Session saved — ${data.session_events?.length || 0} events, ${data.vuln_findings?.length || 0} findings.`);
            } catch (e) {
                alert("Save failed: " + e.message);
            } finally {
                btnSaveHistory.textContent = "Save session";
                btnSaveHistory.disabled = false;
            }
        };
    }

    const btnLoadHistory = document.getElementById("btnLoadHistory");
    const loadHistoryInput = document.getElementById("loadHistoryInput");
    if (btnLoadHistory && loadHistoryInput) {
        btnLoadHistory.onclick = () => loadHistoryInput.click();
        loadHistoryInput.onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            try {
                btnLoadHistory.textContent = "Loading...";
                btnLoadHistory.disabled = true;
                if (file.size > 128 * 1024 * 1024) throw new Error("Session exceeds the 128 MiB import limit.");
                const text = await file.text();
                const data = JSON.parse(text);
                const resp = await fetch("/api/import_session", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(data)
                });
                const result = await resp.json();
                if (!resp.ok || result.status === "error") {
                    alert("Load failed: " + result.error);
                } else {
                    addVulnLog(`Session loaded from "${file.name}" — ${result.events} events, ${result.findings} findings.`);
                }
            } catch (e) {
                alert("Load failed: " + e.message);
            } finally {
                btnLoadHistory.textContent = "Load session";
                btnLoadHistory.disabled = false;
                loadHistoryInput.value = "";
            }
        };
    }

    // API Key save/load
    const apiKeyInput  = document.getElementById("apiKeyInput");
    const btnSaveApiKey = document.getElementById("btnSaveApiKey");
    const apiKeyStatus  = document.getElementById("apiKeyStatus");

    async function loadApiKey() {
        try {
            const r = await fetch("/api/config");
            const d = await r.json();
            if (d.api_key_set) {
                apiKeyStatus.textContent = "API key saved";
                apiKeyStatus.style.color = "var(--success, #4caf50)";
            }
        } catch (_) {}
    }

    if (btnSaveApiKey && apiKeyInput) {
        btnSaveApiKey.onclick = async () => {
            const key = apiKeyInput.value.trim();
            if (!key.startsWith("sk-")) {
                apiKeyStatus.textContent = "Invalid key — must start with sk-";
                apiKeyStatus.style.color = "var(--danger, #f44336)";
                return;
            }
            try {
                const r = await fetch("/api/config", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({api_key: key})
                });
                const d = await r.json();
                if (d.status === "ok") {
                    apiKeyInput.value = "";
                    apiKeyStatus.textContent = "API key saved";
                    apiKeyStatus.style.color = "var(--success, #4caf50)";
                } else {
                    apiKeyStatus.textContent = "Save failed";
                    apiKeyStatus.style.color = "var(--danger, #f44336)";
                }
            } catch (e) {
                apiKeyStatus.textContent = "Error: " + e.message;
                apiKeyStatus.style.color = "var(--danger, #f44336)";
            }
        };
        loadApiKey();
    }

    connectWebSocket();
});
