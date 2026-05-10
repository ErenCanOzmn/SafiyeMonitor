document.addEventListener("DOMContentLoaded", () => {
    // UI Elements
    const btnStart = document.getElementById("btnStart");
    const btnAttach = document.getElementById("btnAttach");
    const btnStop = document.getElementById("btnStop");
    const btnBrowseExe = document.getElementById("btnBrowseExe");
    const btnBrowseScript = document.getElementById("btnBrowseScript");
    const trapToggle = document.getElementById("trapToggle");
    const statusText = document.getElementById("statusText");
    const targetExeStr = document.getElementById("targetExe");
    const fridaScriptStr = document.getElementById("fridaScript");
    const targetArgsStr = document.getElementById("targetArgs");

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

    // Accumulates all captured events for AI analysis
    const sessionCapture = {
        tcpPackets:      [],
        dllEvents:       [],
        registryEvents:  [],
        fileEvents:      [],
        memoryStrings:   [],
        staticStrings:   []
    };

    // Vulnerability findings state
    let allVulnFindings = [];
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
    const interceptBodyArea = document.getElementById("interceptBodyArea");
    const interceptForwardBtn = document.getElementById("interceptForwardBtn");
    const interceptDropBtn = document.getElementById("interceptDropBtn");
    const interceptQueueCount = document.getElementById("interceptQueueCount");
    const interceptQueueList = document.getElementById("interceptQueueList");
    const interceptDestTitle = document.getElementById("interceptDestTitle");

    let interceptQueue = [];

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
        console.log("[CLIPBOARD] Copy as cURL clicked.");
        const raw = interceptBodyArea.value || "";
        if (!raw.trim()) {
            alert("Textarea is empty — there is nothing to copy.\nIntercept a packet first or paste content.");
            return;
        }
        const curlCmd = buildCurlFromText(raw);
        console.log("[CLIPBOARD] Generated cURL (" + curlCmd.length + " chars). Attempting copy...");

        const tryClipboard = navigator.clipboard && window.isSecureContext
            ? navigator.clipboard.writeText(curlCmd)
            : Promise.reject(new Error("clipboard api unavailable"));

        tryClipboard
            .then(() => { console.log("[CLIPBOARD] Native API succeeded."); flashCopied(); })
            .catch((err) => {
                console.warn("[CLIPBOARD] Native API failed, falling back. err=", err);
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
        interceptBodyArea.value = unifiedContent;
        // Save for modification checking
        interceptBodyArea._originalContent = unifiedContent;
        // Save the original hex so we can fall back to a bit-perfect replay if user makes no edits
        interceptBodyArea._originalHex = (current.body_hex || "").replace(/\s+/g, "").toLowerCase();

        interceptForwardBtn.disabled = false;
        interceptDropBtn.disabled = false;

        interceptQueue.forEach((pkg, idx) => {
            const div = document.createElement("div");
            div.className = "intercept-queue-item" + (idx === 0 ? " active" : "");
            div.innerHTML = `<span>#${pkg.id}</span><span>${pkg.dest}</span>`;
            interceptQueueList.appendChild(div);
        });
    }

    interceptForwardBtn.onclick = () => {
        console.log("[INTERCEPT] Forward button clicked. Queue size=" + interceptQueue.length);
        if (interceptQueue.length === 0) {
            console.warn("[INTERCEPT] Queue empty — nothing to forward.");
            return;
        }
        const pkg = interceptQueue.shift();

        const editedText = interceptBodyArea.value;
        const originalText = interceptBodyArea._originalContent || "";
        const originalHex = interceptBodyArea._originalHex || "";

        let finalHex;
        if (editedText === originalText && originalHex) {
            // No edit detected — replay the EXACT original bytes (bit-perfect)
            finalHex = originalHex;
            console.log("[INTERCEPT] No edit; replaying original hex (" + (finalHex.length / 2) + " bytes).");
        } else {
            // Edit detected — re-encode the textarea. Apply CRLF only if it looks like an HTTP request.
            let str = editedText;
            const looksHttp = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s/i.test(str);
            if (looksHttp) str = str.replace(/\r?\n/g, "\r\n");
            const bytes = new TextEncoder().encode(str);
            finalHex = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
            console.log("[INTERCEPT] Edit detected; sending modified hex (" + bytes.length + " bytes, http=" + looksHttp + ").");
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
            tr.innerHTML = `<td><span class="tag-success">${r.type}</span></td><td><code>${r.addr}</code></td><td>${r.val}</td>`;
            tblMemory.appendChild(tr);
        });
    }

    function renderStaticTable(results) {
        if (!tblStatic) return;
        tblStatic.innerHTML = "";
        results.forEach(r => {
            const tr = document.createElement("tr");
            tr.innerHTML = `<td><span class="tag-failed">${r.type}</span></td><td>${r.val}</td>`;
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
        createNewRepeaterTab(msg.dest, msg.body, msg.socket);
    }

    // Repeater Logic
    const repeaterTabsContainer = document.getElementById("repeaterTabsContainer");
    const btnNewRepeaterTab = document.getElementById("btnNewRepeaterTab");
    const repeaterSocketId = document.getElementById("repeaterSocketId");
    const repeaterReqArea = document.getElementById("repeaterReqArea");
    const repeaterResArea = document.getElementById("repeaterResArea");
    const btnRepeaterSend = document.getElementById("btnRepeaterSend");
    let repeaterTabs = [];
    let activeRepeaterTab = null;

    function createNewRepeaterTab(dest, body, socket) {
        const id = Date.now();
        const tab = { id, dest, body, socket, response: "" };
        repeaterTabs.push(tab);
        
        const btn = document.createElement("button");
        btn.className = "btn";
        btn.style.padding = "4px 12px";
        btn.textContent = dest || "New Tab";
        btn.onclick = () => selectRepeaterTab(id);
        tab.btn = btn;
        
        repeaterTabsContainer.appendChild(btn);
        selectRepeaterTab(id);
    }

    function selectRepeaterTab(id) {
        activeRepeaterTab = repeaterTabs.find(t => t.id === id);
        repeaterTabs.forEach(t => t.btn.classList.remove("active-repeater-tab"));
        activeRepeaterTab.btn.classList.add("active-repeater-tab");
        
        repeaterSocketId.value = activeRepeaterTab.socket || "";
        repeaterReqArea.value = activeRepeaterTab.body || "";
        repeaterResArea.value = activeRepeaterTab.response || "";
    }

    btnNewRepeaterTab.onclick = () => createNewRepeaterTab("Manual", "", "");

    btnRepeaterSend.onclick = () => {
        if (!activeRepeaterTab || !ws) return;
        activeRepeaterTab.body = repeaterReqArea.value;
        activeRepeaterTab.socket = repeaterSocketId.value;

        repeaterResArea.value = "Sending...";
        ws.send(JSON.stringify({
            action: "repeater_send",
            socket: activeRepeaterTab.socket,
            data: activeRepeaterTab.body
        }));
    };

    const btnRepeaterCopyCurl = document.getElementById("btnRepeaterCopyCurl");
    if (btnRepeaterCopyCurl) {
        btnRepeaterCopyCurl.onclick = () => {
            console.log("[CLIPBOARD] Repeater Copy as cURL clicked.");
            const raw = repeaterReqArea.value || "";
            if (!raw.trim()) {
                alert("Repeater request is empty — nothing to copy.");
                return;
            }
            const curlCmd = buildCurlFromText(raw);
            console.log("[CLIPBOARD] Repeater cURL (" + curlCmd.length + " chars).");

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
            repeaterResArea.value = "Executing cURL request...";
            console.log("[REPEATER] Send as cURL clicked. " + raw.length + " chars.");
            ws.send(JSON.stringify({
                action: "repeater_curl_send",
                data: raw
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

    function escHtml(s) {
        return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
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

    function buildHistoryRow(item) {
        const tr = document.createElement("tr");
        tr._msg = item;
        tr.innerHTML = `
            <td>${item._seq}</td>
            <td style="color:var(--text-tertiary); font-size:0.72rem;">${item._time}</td>
            <td>${endpointLabel(item)}</td>
            <td style="text-align:right;">${item.size || 0}</td>
            <td style="color:var(--text-tertiary);">${escHtml(item.dest || "Unknown")}</td>`;
        tr.onclick = () => {
            document.querySelectorAll("#tblHistory tbody tr").forEach(r => r.classList.remove("hist-selected"));
            tr.classList.add("hist-selected");
            selectedHistoryId = item._seq;
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
        buildHistoryRow(msg);

        if (!historySearch && historySortCol === "id") {
            const tbody = document.querySelector("#tblHistory tbody");
            if (tbody) tbody.appendChild(msg._tr);
            const countEl = document.getElementById("historyCount");
            if (countEl) countEl.textContent = `${historyData.length} requests`;
        } else {
            refreshHistoryTable();
        }
    }

    // ── Session state management ──────────────────────────────────────────────

    function clearAllState() {
        // History table
        historyData = [];
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

        // Monitor tables
        [tblRegistry, tblFile, tblDll, tblMemory, tblStatic].forEach(t => {
            if (t) while (t.firstChild) t.removeChild(t.firstChild);
        });

        // Memory / Strings
        fullMemoryResults = [];
        fullStaticResults = [];
        if (memoryStatus) memoryStatus.textContent = "Click to scan process RAM for sensitive strings.";
        if (staticStatus)  staticStatus.textContent  = "Static analysis of hardcoded strings in the .exe file.";

        // Vulnerability findings
        allVulnFindings = [];
        renderVulnFindings([]);
        const log = document.getElementById("vulnAnalysisLog");
        if (log) log.innerHTML = "";
        stopVulnTimer();

        // SQL Monitor
        sqlData = [];
        const sqlTbody = document.getElementById("tblSQLBody");
        if (sqlTbody) Array.from(sqlTbody.querySelectorAll("tr:not(#sqlEmptyRow)")).forEach(r => r.remove());
        const sqlEmptyRow = document.getElementById("sqlEmptyRow");
        if (sqlEmptyRow) sqlEmptyRow.style.display = "";
        const sqlBadge = document.getElementById("sqlCountBadge");
        if (sqlBadge) sqlBadge.style.display = "none";
        const sqlCountEl = document.getElementById("sqlCount");
        if (sqlCountEl) sqlCountEl.textContent = "0 queries";

        // Intercept queue
        interceptQueue = [];
        updateInterceptUI();

        addVulnLog("New session started — all previous data cleared.");
    }

    function processMessage(m) {
        console.log("Incoming WS:", m.type);

        if (m.type === "status") {
            statusText.textContent = m.message;
            const active = m.message === "Hook Active!";
            btnStart.disabled = active; btnStop.disabled = !active;
            if (active && targetExeStr.value) {
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
        else if (m.type === "repeater_response") {
            repeaterResArea.value = m.data || "";
            if (activeRepeaterTab) activeRepeaterTab.response = m.data || "";
        }
        else if (m.type === "tcp_out") {
            sessionCapture.tcpPackets.push({ direction: m.direction, dest: m.dest, size: m.size, body: m.body, body_hex: m.body_hex });
            if (sessionCapture.tcpPackets.length > 300) sessionCapture.tcpPackets.shift();
            renderHistoryMsg(m);
        }
        else if (m.type === "intercept_wait") {
            interceptQueue.push(m);
            updateInterceptUI();
        }
        else if (m.type === "dll_monitor" || m.type === "registry_file_monitor") {
            if (m.type === "dll_monitor") {
                sessionCapture.dllEvents.push({ api: m.api, status: m.status, dllName: m.dllName || m.target });
            } else if (m.api && m.api.includes("Reg")) {
                sessionCapture.registryEvents.push({ api: m.api, status: m.status, target: m.target });
            } else {
                sessionCapture.fileEvents.push({ api: m.api, status: m.status, target: m.target });
            }
            const targetTbl = m.type === "dll_monitor" ? tblDll : (m.api.includes("Reg") ? tblRegistry : tblFile);
            if (targetTbl) {
                const rowTime = m._ts || getTimeString();
                const tr = document.createElement("tr");
                tr.innerHTML = `<td>${Date.now().toString().slice(-4)}</td><td>${rowTime}</td><td>${m.api}</td><td class="${m.isFailed ? 'tag-failed' : 'tag-success'}">${m.status}</td><td>${m.target || m.dllName}</td>`;
                targetTbl.appendChild(tr);
            }
        }
        else if (m.type === "sql_monitor") {
            addSqlRow(m);
        }
        else if (m.type === "console_output") {
            const c = document.getElementById("consoleOut");
            if (c) { c.textContent += m.text; c.scrollTop = c.scrollHeight; }
        }
        else if (m.type === "vuln_findings") {
            const findings = m.findings || [];
            stopVulnTimer(`Analysis complete — ${findings.length} finding(s)`);
            renderVulnFindings(findings);
        }
        else if (m.type === "vuln_analysis_log") {
            addVulnLog(m.message || "");
        }
        else if (m.type === "vulnerability_report") {
            (m.vulnerabilities || []).forEach(v => {
                const existing = allVulnFindings.find(f => f.title === v.title);
                if (!existing) {
                    allVulnFindings.unshift({
                        severity: "HIGH",
                        title: v.title || "Runtime Alert",
                        description: v.description || "",
                        evidence: `${v.evidence_method || ""}\n${v.evidence_data || ""}`.trim(),
                        verification_steps: ["Verify with the Intercept tab — replay the captured packet.", "Check if exploitation is reproducible."],
                        exploitation_notes: v.evidence_impact || ""
                    });
                }
            });
            renderVulnFindings(allVulnFindings);
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
        ws = new WebSocket(`ws://${window.location.host}/ws`);
        ws.onopen = () => { statusText.textContent = "Connected (Ready)"; syncStatus(); };
        ws.onmessage = (e) => processMessage(JSON.parse(e.data));
        ws.onclose = () => setTimeout(connectWebSocket, 2000);
    }

    async function syncStatus() {
        try {
            const r = await fetch("/api/status");
            const d = await r.json();
            if (d.is_hooking) { statusText.textContent = "Hook Active!"; btnStart.disabled = true; btnStop.disabled = false; }
        } catch {}
    }

    btnStart.onclick = () => fetch("/api/start_hook", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({target_exe: targetExeStr.value, target_script: fridaScriptStr.value, target_args: targetArgsStr.value})});
    btnStop.onclick = () => fetch("/api/stop_hook", { method: "POST" });
    btnBrowseExe.onclick = async () => { const r = await fetch("/api/browse_file"); const d = await r.json(); if (d.path) targetExeStr.value = d.path; };
    btnBrowseScript.onclick = async () => { const r = await fetch("/api/browse_file"); const d = await r.json(); if (d.path) fridaScriptStr.value = d.path; };

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
        memorySearch.oninput = () => {
            const val = memorySearch.value.toLowerCase();
            const filtered = fullMemoryResults.filter(r => r.val.toLowerCase().includes(val) || r.addr.toLowerCase().includes(val));
            renderMemoryTable(filtered.slice(0, 500));
        };
    }

    if (staticSearch) {
        staticSearch.oninput = () => {
            const val = staticSearch.value.toLowerCase();
            const filtered = fullStaticResults.filter(r => r.val.toLowerCase().includes(val));
            renderStaticTable(filtered.slice(0, 500));
        };
    }

    // ── Vulnerability Analysis ────────────────────────────────

    function escHtml(s) {
        if (!s) return "";
        return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
    }

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
        const list = document.getElementById("vulnFindingsList");
        if (!list) return;
        const emptyState = document.getElementById("vulnEmptyState");

        const filtered = activeVulnFilter === "ALL"
            ? allVulnFindings
            : allVulnFindings.filter(f => f.severity === activeVulnFilter);

        // Clear dynamic cards (keep emptyState element)
        Array.from(list.children).forEach(el => { if (el.id !== "vulnEmptyState") el.remove(); });

        if (filtered.length === 0) {
            if (emptyState) emptyState.style.display = "flex";
            return;
        }
        if (emptyState) emptyState.style.display = "none";

        filtered.forEach(finding => {
            const cfg = SEVERITY_CFG[finding.severity] || SEVERITY_CFG.INFO;
            const steps = (finding.verification_steps || [])
                .map((s,i) => `<li style="margin-bottom:4px;">${escHtml(s)}</li>`).join("");
            const card = document.createElement("div");
            card.style.cssText = `background:${cfg.bg}; border:1px solid ${cfg.border}; border-radius:8px; padding:16px; animation: borderPulse 3s ease-in-out ${finding.severity==="CRITICAL"?"infinite":"1"};`;
            card.innerHTML = `
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
                    <span style="background:${cfg.color}; color:#0d1017; padding:2px 9px; border-radius:10px; font-size:0.68rem; font-weight:800; letter-spacing:0.8px;">${escHtml(finding.severity)}</span>
                    <span style="font-weight:600; font-size:0.92rem; color:var(--text-primary);">${escHtml(finding.title)}</span>
                </div>
                <div style="color:var(--text-secondary); font-size:0.83rem; margin-bottom:10px; line-height:1.6;">${escHtml(finding.description)}</div>
                ${finding.evidence ? `
                <details style="margin-bottom:8px;">
                    <summary style="cursor:pointer; color:${cfg.color}; font-size:0.78rem; font-weight:600; user-select:none;">▶ Evidence</summary>
                    <pre style="margin-top:6px; background:rgba(0,0,0,0.45); padding:10px 12px; border-radius:4px; font-size:0.76rem; font-family:var(--font-mono); color:var(--text-primary); white-space:pre-wrap; word-break:break-all; border:1px solid ${cfg.border};">${escHtml(finding.evidence)}</pre>
                </details>` : ""}
                ${steps ? `
                <details style="margin-bottom:8px;" open>
                    <summary style="cursor:pointer; color:${cfg.color}; font-size:0.78rem; font-weight:600; user-select:none;">▶ Verification Steps</summary>
                    <ol style="margin-top:6px; padding-left:18px; font-size:0.8rem; color:var(--text-secondary); line-height:1.7;">${steps}</ol>
                </details>` : ""}
                ${finding.exploitation_notes && finding.exploitation_notes !== "N/A" ? `
                <details>
                    <summary style="cursor:pointer; color:${cfg.color}; font-size:0.78rem; font-weight:600; user-select:none;">▶ Exploitation Notes</summary>
                    <div style="margin-top:6px; font-size:0.8rem; color:var(--text-secondary); line-height:1.6;">${escHtml(finding.exploitation_notes)}</div>
                </details>` : ""}
            `;
            list.appendChild(card);
        });
    }

    function renderVulnFindings(findings) {
        allVulnFindings = findings;
        updateVulnBadges();
        applyVulnFilter();
        const lastScan = document.getElementById("vulnLastScan");
        if (lastScan) lastScan.textContent = `Last scan: ${getTimeString()}`;
    }

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

    if (histSearchEl) {
        histSearchEl.addEventListener("input", () => {
            historySearch = histSearchEl.value.trim();
            refreshHistoryTable();
        });
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
                          sessionCapture.registryEvents.length + sessionCapture.staticStrings.length +
                          sessionCapture.memoryStrings.length;
            if (total === 0) {
                addVulnLog("No data captured yet. Start the hook and generate some traffic first.");
                return;
            }
            // Queue data in background
            const payload = {
                tcp_packets:     sessionCapture.tcpPackets.slice(-50).map(p => ({ direction: p.direction, dest: p.dest, size: p.size, body: (p.body||"").substring(0,1024), body_hex: (p.body_hex||"") })),
                dll_events:      sessionCapture.dllEvents.slice(-100),
                registry_events: sessionCapture.registryEvents.slice(-100),
                file_events:     sessionCapture.fileEvents.slice(-100),
                memory_strings:  sessionCapture.memoryStrings.slice(0,200).map(s => ({ type:s.type, val:s.val })),
                static_strings:  sessionCapture.staticStrings.slice(0,200).map(s => ({ val:s.val }))
            };
            fetch("/api/analyze_vulnerabilities", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            }).then(r => r.json()).then(result => {
                if (result.status !== "error") startVulnTimer();
            }).catch(() => {});
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
                          sessionCapture.memoryStrings.length;
            addVulnLog(`Rule-based scan started... (${total} captured events)`);
            btnAnalyzeRules.disabled = true;
            btnAnalyzeRules.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite;"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg> Scanning...`;
            try {
                const payload = {
                    tcp_packets:     sessionCapture.tcpPackets.slice(-50).map(p => ({ direction: p.direction, dest: p.dest, size: p.size, body: (p.body||"").substring(0,1024), body_hex: (p.body_hex||"") })),
                    dll_events:      sessionCapture.dllEvents.slice(-100),
                    registry_events: sessionCapture.registryEvents.slice(-100),
                    file_events:     sessionCapture.fileEvents.slice(-100),
                    memory_strings:  sessionCapture.memoryStrings.slice(0,200).map(s => ({ type:s.type, val:s.val })),
                    static_strings:  sessionCapture.staticStrings.slice(0,200).map(s => ({ val:s.val }))
                };
                const resp = await fetch("/api/rule_scan", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
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

    const btnRefreshPipes = document.getElementById("btnRefreshPipes");
    if (btnRefreshPipes) {
        btnRefreshPipes.onclick = async () => {
            btnRefreshPipes.disabled = true;
            btnRefreshPipes.textContent = "Loading...";
            try {
                const res = await fetch("/api/pipes");
                const data = await res.json();
                const tbody = document.getElementById("tblPipelistBody");
                const countEl = document.getElementById("pipeCount");
                tbody.innerHTML = "";
                const pipes = data.pipes || [];
                if (pipes.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="2" style="text-align:center; color:var(--text-tertiary); padding:32px;">No named pipes found.</td></tr>';
                } else {
                    pipes.forEach(p => {
                        const tr = document.createElement("tr");
                        tr.innerHTML = `<td>${p.index}</td><td style="font-family:monospace; font-size:0.82rem;">\\\\.\\pipe\\${p.name}</td>`;
                        tbody.appendChild(tr);
                    });
                }
                if (countEl) countEl.textContent = `${pipes.length} pipes`;
            } catch(e) {
                console.error("Pipes fetch error:", e);
            } finally {
                btnRefreshPipes.disabled = false;
                btnRefreshPipes.textContent = "Refresh";
            }
        };
    }

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
                const data = await resp.json();
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
                a.download = `safiye_session_${ts}.json`;
                a.click();
                URL.revokeObjectURL(url);
                addVulnLog(`Session saved — ${data.session_events?.length || 0} events, ${data.vuln_findings?.length || 0} findings.`);
            } catch (e) {
                alert("Save failed: " + e.message);
            } finally {
                btnSaveHistory.textContent = "💾 Save History";
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
                const text = await file.text();
                const data = JSON.parse(text);
                const resp = await fetch("/api/import_session", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(data)
                });
                const result = await resp.json();
                if (result.status === "error") {
                    alert("Load failed: " + result.error);
                } else {
                    addVulnLog(`Session loaded from "${file.name}" — ${result.events} events, ${result.findings} findings.`);
                }
            } catch (e) {
                alert("Load failed: " + e.message);
            } finally {
                btnLoadHistory.textContent = "📂 Load History";
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

    // ── SQL Monitor ───────────────────────────────────────────────────────────
    let sqlData = [];
    const SQL_TYPE_COLORS = {
        SELECT: "#89b4fa", INSERT: "#f9e2af", UPDATE: "#fab387",
        DELETE: "#f38ba8", DDL:    "#cba6f7", OTHER: "#a6adc8"
    };

    function sqlQueryType(q) {
        const s = (q || "").trimStart().toUpperCase();
        if (s.startsWith("SELECT"))  return "SELECT";
        if (s.startsWith("INSERT"))  return "INSERT";
        if (s.startsWith("UPDATE"))  return "UPDATE";
        if (s.startsWith("DELETE"))  return "DELETE";
        if (/^(CREATE|DROP|ALTER|TRUNCATE|RENAME)/.test(s)) return "DDL";
        return "OTHER";
    }

    function addSqlRow(m) {
        const entry = {
            ts:     m._ts || getTimeString(),
            type:   sqlQueryType(m.query),
            driver: (m.driver || "?").replace(/\.dll$/i, ""),
            api:    m.api || "?",
            status: m.status || "?",
            query:  m.query || "",
            sqli:   m.sqli || false
        };
        sqlData.push(entry);

        // Update driver filter dropdown
        const driverSel = document.getElementById("sqlFilterDriver");
        if (driverSel && !Array.from(driverSel.options).some(o => o.value === entry.driver)) {
            const opt = document.createElement("option");
            opt.value = entry.driver; opt.textContent = entry.driver;
            driverSel.appendChild(opt);
        }

        applySqlFilter();

        // Badge
        const badge = document.getElementById("sqlCountBadge");
        if (badge) { badge.textContent = sqlData.length; badge.style.display = "inline"; }
        document.getElementById("sqlCount").textContent = sqlData.length + " queries";
    }

    function applySqlFilter() {
        const typeF   = (document.getElementById("sqlFilterType")   || {}).value || "ALL";
        const driverF = (document.getElementById("sqlFilterDriver") || {}).value || "ALL";
        const search  = ((document.getElementById("sqlSearch")      || {}).value || "").toLowerCase();
        const tbody   = document.getElementById("tblSQLBody");
        const emptyRow = document.getElementById("sqlEmptyRow");
        if (!tbody) return;

        const filtered = sqlData.filter(e =>
            (typeF   === "ALL" || e.type   === typeF)   &&
            (driverF === "ALL" || e.driver === driverF) &&
            (!search || e.query.toLowerCase().includes(search) || e.driver.toLowerCase().includes(search))
        );

        Array.from(tbody.querySelectorAll("tr:not(#sqlEmptyRow)")).forEach(r => r.remove());

        if (filtered.length === 0) {
            if (emptyRow) emptyRow.style.display = "";
            return;
        }
        if (emptyRow) emptyRow.style.display = "none";

        filtered.forEach(e => {
            const color = SQL_TYPE_COLORS[e.type] || SQL_TYPE_COLORS.OTHER;
            const sqliTag = e.sqli ? `<span style="background:#f38ba8;color:#0d1017;padding:1px 5px;border-radius:3px;font-size:0.68rem;font-weight:800;margin-left:4px;">SQLi</span>` : "";
            const tr = document.createElement("tr");
            if (e.sqli) tr.style.background = "rgba(243,139,168,0.08)";
            tr.innerHTML = `
                <td style="font-size:0.76rem;color:var(--text-secondary);">${escHtml(e.ts)}</td>
                <td><span style="background:${color};color:#0d1017;padding:1px 7px;border-radius:10px;font-size:0.7rem;font-weight:700;">${e.type}</span></td>
                <td style="font-size:0.76rem;">${escHtml(e.driver)}</td>
                <td style="font-size:0.74rem;color:var(--text-secondary);">${escHtml(e.api)}</td>
                <td class="${e.status==="SUCCESS"?"tag-success":"tag-failed"}" style="font-size:0.76rem;">${escHtml(e.status)}</td>
                <td style="font-family:var(--font-mono);font-size:0.76rem;word-break:break-all;">${escHtml(e.query.substring(0,300))}${sqliTag}</td>`;
            tbody.appendChild(tr);
        });
    }

    ["sqlFilterType","sqlFilterDriver","sqlSearch"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener("input", applySqlFilter);
    });

    const btnClearSQL = document.getElementById("btnClearSQL");
    if (btnClearSQL) btnClearSQL.onclick = () => {
        sqlData = [];
        const tbody = document.getElementById("tblSQLBody");
        Array.from(tbody.querySelectorAll("tr:not(#sqlEmptyRow)")).forEach(r => r.remove());
        const emptyRow = document.getElementById("sqlEmptyRow");
        if (emptyRow) emptyRow.style.display = "";
        const badge = document.getElementById("sqlCountBadge");
        if (badge) badge.style.display = "none";
        document.getElementById("sqlCount").textContent = "0 queries";
        const driverSel = document.getElementById("sqlFilterDriver");
        while (driverSel.options.length > 1) driverSel.remove(1);
    };

    const btnExportSQL = document.getElementById("btnExportSQL");
    if (btnExportSQL) btnExportSQL.onclick = () => {
        const rows = [["Time","Type","Driver","API","Status","Query"]];
        sqlData.forEach(e => rows.push([e.ts, e.type, e.driver, e.api, e.status, '"' + e.query.replace(/"/g,'""') + '"']));
        const blob = new Blob([rows.map(r => r.join(",")).join("\n")], {type:"text/csv;charset=utf-8;"});
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a"); a.href = url; a.download = `safiye_sql_${Date.now()}.csv`;
        document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
    };

    connectWebSocket();
});
