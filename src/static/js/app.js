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

    closeModal.onclick = () => payloadModal.style.display = "none";
    function showModal(title, headers, body, bodyHex) {
        modalTitle.textContent = title;
        modalHeaders.textContent = headers || "(No Headers)";
        modalBodyUtf8.textContent = body || "(Empty)";
        modalBodyHex.textContent = bodyHex || "";
        payloadModal.style.display = "flex";
    }

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

    function renderHistoryMsg(msg) {
        counters.history++;
        const tr = document.createElement("tr");
        tr.innerHTML = `<td>${msg.id || counters.history}</td><td>${getTimeString()}</td><td>${msg.direction || 'Out'}</td><td>Binary</td><td>${msg.size || 0}</td><td>${msg.dest || 'Unknown'}</td>`;
        tr.onclick = () => showModal(`Packet Details`, msg.headers, msg.body, msg.body_hex);
        tblHistory.appendChild(tr);
    }

    // WebSocket
    function connectWebSocket() {
        ws = new WebSocket(`ws://${window.location.host}/ws`);
        ws.onopen = () => { statusText.textContent = "Connected (Ready)"; syncStatus(); };
        ws.onmessage = (e) => {
            const m = JSON.parse(e.data);
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
                memoryStatus.textContent = `Found ${fullMemoryResults.length} strings.`;
                btnDumpMemory.disabled = false;
                renderMemoryTable(fullMemoryResults.slice(0, 500));
            }
            else if (m.type === "static_strings") {
                fullStaticResults = m.data || [];
                staticStatus.textContent = `Found ${fullStaticResults.length} strings.`;
                renderStaticTable(fullStaticResults.slice(0, 500));
            }
            else if (m.type === "tcp_out") { renderHistoryMsg(m); }
            else if (m.type === "dll_monitor" || m.type === "registry_file_monitor") {
                const targetTbl = m.type === "dll_monitor" ? tblDll : (m.api.includes("Reg") ? tblRegistry : tblFile);
                if (targetTbl) {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `<td>${Date.now().toString().slice(-4)}</td><td>${getTimeString()}</td><td>${m.api}</td><td class="${m.isFailed ? 'tag-failed' : 'tag-success'}">${m.status}</td><td>${m.target || m.dllName}</td>`;
                    targetTbl.appendChild(tr);
                }
            }
            else if (m.type === "console_output") {
                const c = document.getElementById("consoleOut");
                if (c) { c.textContent += m.text; c.scrollTop = c.scrollHeight; }
            }
        };
        ws.onclose = () => setTimeout(connectWebSocket, 2000);
    }

    // Actions
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

    // Export Logic
    const btnExport = document.getElementById("btnExport");
    if (btnExport) {
        btnExport.onclick = () => {
            const activeTab = document.querySelector(".tab-content.active");
            if (!activeTab) return;
            const table = activeTab.querySelector("table");
            if (!table) { alert("No exportable table found in this tab."); return; }

            let csv = [];
            const rows = table.querySelectorAll("tr");
            for (let i = 0; i < rows.length; i++) {
                const row = [], cols = rows[i].querySelectorAll("td, th");
                for (let j = 0; j < cols.length; j++) row.push('"' + cols[j].innerText.replace(/"/g, '""') + '"');
                csv.push(row.join(","));
            }
            const csvContent = "data:text/csv;charset=utf-8," + csv.join("\n");
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", `safiye_export_${activeTab.id}_${Date.now()}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        };
    }

    connectWebSocket();
});
