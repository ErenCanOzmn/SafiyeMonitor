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
    let historyDirFilter  = "ALL"; // "ALL" | "OUT" | "IN"

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

    // Row density toggle (compact <-> comfortable), persisted across reloads.
    const btnDensity = document.getElementById("btnDensity");
    if (btnDensity) {
        const applyDensity = (compact) => {
            document.body.classList.toggle("density-compact", compact);
            btnDensity.textContent = compact ? "Comfortable" : "Compact";
        };
        applyDensity(localStorage.getItem("sf-density") === "compact");
        btnDensity.addEventListener("click", () => {
            const compact = !document.body.classList.contains("density-compact");
            localStorage.setItem("sf-density", compact ? "compact" : "comfortable");
            applyDensity(compact);
        });
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
        createNewRepeaterTab(msg.dest, msg.body, msg.socket);
    }

    // Repeater Logic
    const repeaterTabsContainer = document.getElementById("repeaterTabsContainer");
    const btnNewRepeaterTab = document.getElementById("btnNewRepeaterTab");
    const repeaterSocketId = document.getElementById("repeaterSocketId");
    const repeaterDest = document.getElementById("repeaterDest");
    const repeaterReqArea = document.getElementById("repeaterReqArea");
    const repeaterResArea = document.getElementById("repeaterResArea");
    const btnRepeaterSend = document.getElementById("btnRepeaterSend");
    const btnRepeaterTcpSend = document.getElementById("btnRepeaterTcpSend");
    const repeaterFmtUtf8 = document.getElementById("repeaterFmtUtf8");
    const repeaterFmtHex = document.getElementById("repeaterFmtHex");
    const repeaterHexHint = document.getElementById("repeaterHexHint");
    const repeaterResFmtUtf8 = document.getElementById("repeaterResFmtUtf8");
    const repeaterResFmtHex = document.getElementById("repeaterResFmtHex");
    let repeaterTabs = [];
    let activeRepeaterTab = null;

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

    function createNewRepeaterTab(dest, body, socket) {
        const id = Date.now();
        const tab = { id, dest, body, socket, response: "", responseHex: "", responseUtf8: "", reqMode: "utf8", resMode: "utf8" };
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
        // Prefill the TCP target from the captured destination (skip placeholders).
        const d = activeRepeaterTab.dest || "";
        if (repeaterDest) repeaterDest.value = /:\d+$/.test(d) ? d : "";
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
            repeaterResArea.value = "Opening new TCP connection to " + dest + " ...";
            ws.send(JSON.stringify({
                action: "repeater_tcp_send",
                dest: dest,
                data: activeRepeaterTab.body,
                is_hex: isHex,
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
            repeaterResArea.value = "Executing cURL request...";
            ws.send(JSON.stringify({
                action: "repeater_curl_send",
                data: raw
            }));
        };
    }

    // ── Intruder Logic ────────────────────────────────────────────────────────
    const intruderSocketId   = document.getElementById("intruderSocketId");
    const intruderTemplate   = document.getElementById("intruderTemplate");
    const intruderPayloads   = document.getElementById("intruderPayloads");
    const intruderFmtUtf8    = document.getElementById("intruderFmtUtf8");
    const intruderFmtHex     = document.getElementById("intruderFmtHex");
    const btnIntruderMark    = document.getElementById("btnIntruderMark");
    const btnIntruderAttack  = document.getElementById("btnIntruderAttack");
    const btnIntruderClear   = document.getElementById("btnIntruderClear");
    const intruderResultsBody = document.getElementById("intruderResultsBody");
    let intruderMode = "utf8";

    function updateIntruderModeUI(mode) {
        intruderFmtUtf8.className = "btn " + (mode === "utf8" ? "btn-primary" : "btn-neutral");
        intruderFmtHex.className  = "btn " + (mode === "hex"  ? "btn-primary" : "btn-neutral");
        intruderFmtUtf8.style.cssText = intruderFmtHex.style.cssText = "padding:2px 10px; font-size:0.8rem;";
    }

    if (intruderFmtUtf8) intruderFmtUtf8.onclick = () => { intruderMode = "utf8"; updateIntruderModeUI("utf8"); };
    if (intruderFmtHex)  intruderFmtHex.onclick  = () => { intruderMode = "hex";  updateIntruderModeUI("hex"); };

    if (btnIntruderMark) {
        btnIntruderMark.onclick = () => {
            if (!intruderTemplate) return;
            const start = intruderTemplate.selectionStart;
            const end   = intruderTemplate.selectionEnd;
            const val   = intruderTemplate.value;
            const selected = val.slice(start, end) || "payload";
            intruderTemplate.value = val.slice(0, start) + "§" + selected + "§" + val.slice(end);
            intruderTemplate.selectionStart = start;
            intruderTemplate.selectionEnd   = start + selected.length + 2;
            intruderTemplate.focus();
        };
    }

    if (btnIntruderAttack) {
        btnIntruderAttack.onclick = () => {
            if (!ws) { alert("WebSocket is not connected."); return; }
            const template = intruderTemplate ? intruderTemplate.value : "";
            const rawPayloads = intruderPayloads ? intruderPayloads.value : "";
            if (!template.includes("§payload§")) {
                alert("No §payload§ marker found in the template. Use the 'Mark §payload§' button.");
                return;
            }
            const payloads = rawPayloads.split("\n").map(l => l.trim()).filter(l => l.length > 0);
            if (!payloads.length) { alert("Payload list is empty."); return; }
            const sid = intruderSocketId ? intruderSocketId.value.trim() : "";
            if (!sid) { alert("Socket ID is required."); return; }
            const statusEl = document.getElementById("intruderStatus");
            if (statusEl) statusEl.textContent = "Starting attack...";
            ws.send(JSON.stringify({
                action: "intruder_attack",
                socket: sid,
                template,
                payloads,
                is_hex: intruderMode === "hex"
            }));
        };
    }

    if (btnIntruderClear) {
        btnIntruderClear.onclick = () => {
            if (intruderResultsBody) while (intruderResultsBody.firstChild) intruderResultsBody.removeChild(intruderResultsBody.firstChild);
            const statusEl = document.getElementById("intruderStatus");
            if (statusEl) statusEl.textContent = "";
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

        // Cap history so a long session can't grow the array and DOM without bound.
        const HISTORY_CAP = 2000;
        while (historyData.length > HISTORY_CAP) {
            const old = historyData.shift();
            if (old && old._tr && old._tr.parentNode) old._tr.parentNode.removeChild(old._tr);
        }

        if (!historySearch && historySortCol === "id" && historyDirFilter === "ALL") {
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

        // Intercept queue
        interceptQueue = [];
        updateInterceptUI();

        addVulnLog("New session started — all previous data cleared.");
    }

    function processMessage(m) {
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
        else if (m.type === "static_strings_error") {
            if (staticStatus) staticStatus.textContent = m.message || "Static strings failed.";
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
        else if (m.type === "intruder_status") {
            const el = document.getElementById("intruderStatus");
            if (el) el.textContent = m.message || "";
        }
        else if (m.type === "intruder_result") {
            const tbody = document.getElementById("intruderResultsBody");
            if (!tbody) return;
            const tr = document.createElement("tr");
            const pl = String(m.payload || "");
            const status = String(m.status || "");
            const isErr = status.startsWith("error");
            tr.innerHTML = `<td>${(m.index ?? "") + 1}</td>` +
                `<td style="font-family:var(--font-mono); font-size:0.8rem; word-break:break-all;">${escHtml(pl.length > 80 ? pl.slice(0,80)+"…" : pl)}</td>` +
                `<td class="${isErr ? "tag-failed" : "tag-success"}" style="font-size:0.78rem;">${escHtml(status)}</td>` +
                `<td style="font-size:0.78rem; color:var(--text-tertiary);">—</td>`;
            tbody.appendChild(tr);
            tr.scrollIntoView({ block: "nearest" });
        }
        else if (m.type === "tcp_out" || m.type === "tcp_in") {
            sessionCapture.tcpPackets.push({ direction: m.direction, dest: m.dest, size: m.size, body: m.body, body_hex: m.body_hex });
            if (sessionCapture.tcpPackets.length > 500) sessionCapture.tcpPackets.shift();
            renderHistoryMsg(m);
        }
        else if (m.type === "intercept_wait") {
            interceptQueue.push(m);
            updateInterceptUI();
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

    btnStart.onclick = () => {
        if (!targetExeStr.value) { showToast("Set a target executable first.", "error"); return; }
        fetch("/api/start_hook", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({target_exe: targetExeStr.value, target_script: fridaScriptStr.value, target_args: targetArgsStr.value})})
            .then(() => showToast("Spawning target and attaching hooks...", "info"))
            .catch(() => showToast("Failed to start hook.", "error"));
    };
    btnStop.onclick = () => {
        fetch("/api/stop_hook", { method: "POST" })
            .then(() => showToast("Hook stopped.", "info"))
            .catch(() => showToast("Failed to stop hook.", "error"));
    };
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
                        tr.innerHTML = `<td>${escHtml(p.index)}</td><td style="font-family:monospace; font-size:0.82rem;">\\\\.\\pipe\\${escHtml(p.name)}</td>`;
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

    connectWebSocket();
});
