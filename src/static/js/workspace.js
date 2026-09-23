/* Presentation only: retain the existing controls, IDs and application handlers. */
(() => {
    'use strict';
    const byId = id => document.getElementById(id);
    const make = (tag, className, text) => {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    };
    const prefs = {
        get(key, fallback) { try { return localStorage.getItem('safiye.ui.' + key) ?? fallback; } catch { return fallback; } },
        set(key, value) { try { localStorage.setItem('safiye.ui.' + key, String(value)); } catch {} }
    };
    let sessionActive = false, startedAt = null, selectedFinding = null;
    let archiveMetadata = null;
    const reviewStates = new Map();
    const findingKey = f => JSON.stringify([f.source || f.detector || '', f.title, f.evidence || '']);
    const reviewOptions = ['Unreviewed', 'In review', 'Confirmed', 'Dismissed'];
    const severity = f => ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(f.severity) ? f.severity : 'INFO';

    function setSession({ active, connected, targetPid, targetName, startedAt: serverStartedAt } = {}) {
        if (!byId('sessionState')) return;
        if (connected !== undefined) document.body.classList.toggle('server-connected', connected);
        if (active !== undefined) {
            if (active && !sessionActive) {
                archiveMetadata = null;
                startedAt = Date.now();
                updateTarget();
                byId('sessionSetup').close();
            }
            if (!active && sessionActive) startedAt = null;
            sessionActive = active;
            document.body.classList.toggle('session-active', active);
        }
        if (sessionActive) {
            if (targetName) { byId('sessionTarget').textContent = targetName; byId('sessionTarget').title = targetName; }
            if (targetPid) { byId('sessionPid').textContent = 'PID ' + targetPid; byId('sessionPid').title = 'Active process ID'; }
            if (Number.isFinite(serverStartedAt) && serverStartedAt > 0) {
                startedAt = serverStartedAt * 1000;
                byId('sessionElapsed').title = 'Elapsed time since this session started';
            }
        }
        const online = document.body.classList.contains('server-connected');
        byId('sessionState').textContent = !online ? 'Disconnected' : sessionActive ? 'Recording' : archiveMetadata ? 'Loaded' : 'Ready';
        byId('sessionState').dataset.state = !online ? 'offline' : sessionActive ? 'active' : 'ready';
        if (!startedAt) byId('sessionElapsed').textContent = '00:00:00';
    }

    function updateTarget() {
        if (sessionActive) return;
        const pidMode = byId('modePid').checked;
        const path = byId('targetExe').value.trim();
        const pid = byId('targetPid').value.trim();
        byId('sessionTarget').textContent = pidMode ? (pid ? 'Process ' + pid : 'No process selected') : (path.split(/[\\/]/).pop() || 'No target selected');
        byId('sessionTarget').title = path || 'Select a target in Session setup';
        byId('sessionPid').textContent = pidMode && pid ? 'PID ' + pid : 'PID —';
        byId('sessionPid').title = pidMode ? 'PID entered in session setup' : 'Available when the process starts';
    }

    function renderFindingDetail(finding) {
        const panel = byId('findingDetail');
        panel.replaceChildren();
        if (!finding) {
            panel.append(make('div', 'sf-empty', 'Select a finding to inspect its details.'));
            return;
        }
        const key = findingKey(finding);
        const eyebrow = make('div', 'finding-meta');
        eyebrow.append(make('span', 'severity-pill severity-' + severity(finding).toLowerCase(), severity(finding)), make('span', '', 'Source: ' + (finding.source || finding.detector || 'Not specified')));
        panel.append(eyebrow, make('h2', '', finding.title || 'Untitled finding'));
        const review = make('div', 'finding-review');
        const label = make('label', '', 'Review status');
        label.htmlFor = 'findingReviewStatus';
        const select = make('select');
        select.id = 'findingReviewStatus';
        reviewOptions.forEach(value => { const option = make('option', '', value); option.value = value; select.append(option); });
        select.value = reviewStates.get(key) || 'Unreviewed';
        select.addEventListener('change', async () => {
            reviewStates.set(key, select.value);
            document.querySelectorAll('.finding-row').forEach(row => {
                if (row.dataset.key === key) row.querySelector('.review-label').textContent = select.value;
            });
            select.disabled = true;
            try {
                const response = await fetch('/api/finding_review', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ title: finding.title || '', target: finding.target || '',
                                           evidence: finding.evidence || '', ui_review_status: select.value })
                });
                if (!response.ok) throw new Error('Server did not save the review');
                finding.ui_review_status = select.value;
                review.querySelector('small').textContent = 'Review synced. Use Save session to keep an archive.';
            } catch (_) {
                reviewStates.set(key, finding.ui_review_status || 'Unreviewed');
                select.value = finding.ui_review_status || 'Unreviewed';
                review.querySelector('small').textContent = 'Review was not saved. Reconnect and try again.';
            } finally { select.disabled = false; }
        });
        review.append(label, select, make('small', '', 'Use Save session to keep your review decisions.'));
        panel.append(review, make('p', 'finding-description', finding.description || 'No description provided.'));
        function section(title, value, code = false) {
            if (!value || value === 'N/A') return;
            const group = make('section', 'finding-section');
            group.append(make('h3', '', title), make(code ? 'pre' : 'p', '', value));
            panel.append(group);
        }
        section('Evidence', finding.evidence, true);
        section('Validation', finding.validation_basis || 'Security impact has not been verified.');
        if (Array.isArray(finding.verification_steps) && finding.verification_steps.length) {
            const group = make('section', 'finding-section');
            const list = make('ol');
            finding.verification_steps.forEach(step => list.append(make('li', '', step)));
            group.append(make('h3', '', 'Verification steps'), list);
            panel.append(group);
        }
        section('Notes', finding.exploitation_notes);
        section('Recommendation', finding.recommendation || finding.remediation);
    }

    function renderFindings(findings, total, view = 'confirmed') {
        const list = byId('vulnFindingsList');
        if (!list) return;
        list.replaceChildren();
        if (!total) { selectedFinding = null; }
        if (!findings.length) {
            const empty = make('div', 'sf-empty');
            empty.append(make('strong', '', total ? 'No findings match this filter' : view === 'confirmed' ? 'No confirmed vulnerabilities' : 'No observations to review'), make('p', '', total ? 'Choose All to see the complete list.' : view === 'confirmed' ? 'Automatic signals stay in Needs review until you confirm the evidence and impact.' : 'Scanner and AI observations will appear here without being counted as confirmed vulnerabilities.'));
            list.append(empty);
            renderFindingDetail(null);
            return;
        }
        findings.forEach(finding => {
            const key = findingKey(finding);
            if (reviewOptions.includes(finding.ui_review_status)) reviewStates.set(key, finding.ui_review_status);
        });
        if (!findings.some(f => findingKey(f) === selectedFinding)) selectedFinding = findingKey(findings[0]);
        findings.forEach(finding => {
            const key = findingKey(finding);
            const row = make('button', 'finding-row');
            row.type = 'button';
            row.dataset.key = key;
            row.classList.toggle('selected', key === selectedFinding);
            row.setAttribute('aria-pressed', String(key === selectedFinding));
            const heading = make('span', 'finding-row-heading');
            heading.append(make('span', 'severity-pill severity-' + severity(finding).toLowerCase(), severity(finding)), make('span', 'finding-row-title', finding.title || 'Untitled finding'));
            const meta = make('span', 'finding-row-meta');
            meta.append(make('span', '', finding.source || finding.detector || 'Source not specified'), make('span', 'review-label', reviewStates.get(key) || 'Unreviewed'));
            row.append(heading, meta);
            row.addEventListener('click', () => {
                selectedFinding = key;
                list.querySelectorAll('.finding-row').forEach(item => {
                    item.classList.toggle('selected', item === row);
                    item.setAttribute('aria-pressed', String(item === row));
                });
                renderFindingDetail(finding);
            });
            list.append(row);
        });
        renderFindingDetail(findings.find(f => findingKey(f) === selectedFinding));
    }
    function annotateFindings(findings) {
        return findings.map(finding => ({ ...finding, ui_review_status: reviewStates.get(findingKey(finding)) || (reviewOptions.includes(finding.ui_review_status) ? finding.ui_review_status : 'Unreviewed') }));
    }
    function showArchive(metadata) {
        archiveMetadata = metadata;
        setSession({ active: false });
        if (byId('sessionTarget')) byId('sessionTarget').textContent = metadata.target_name || 'Loaded session';
        if (byId('sessionPid')) byId('sessionPid').textContent = metadata.target_pid ? 'Saved PID ' + metadata.target_pid : 'PID —';
        if (byId('sessionState')) byId('sessionState').textContent = 'Loaded';
    }
    function clearArchive() {
        archiveMetadata = null;
        reviewStates.clear();
        setSession();
        updateTarget();
    }
    window.SafiyeUI = { setSession, renderFindings, annotateFindings, showArchive, clearArchive };

    document.addEventListener('DOMContentLoaded', () => {
        const main = document.querySelector('.main-content');
        const sidebar = document.querySelector('.sidebar');
        document.body.classList.add('workspace-ready');
        const header = make('header', 'session-bar');
        header.innerHTML = '<button type="button" class="btn btn-neutral nav-toggle" id="navToggle" aria-controls="workspaceNav" aria-expanded="false">Menu</button><div class="session-identity"><span class="eyebrow">Current session</span><strong id="sessionTarget">No target selected</strong></div><span class="session-pid" id="sessionPid">PID —</span><span class="session-state" id="sessionState" role="status" data-state="offline">Disconnected</span><time id="sessionElapsed" title="Elapsed recording time observed in this browser; resets on reload">00:00:00</time><div class="session-actions"><button type="button" id="openSessionSetup" class="btn btn-primary">Session setup</button></div>';
        main.prepend(header);
        const pageHeader = make('div', 'workspace-heading');
        pageHeader.innerHTML = '<div><span class="eyebrow" id="workspaceGroup">Traffic</span><h1 id="workspaceTitle">History</h1></div><p id="workspaceSubtitle">Follow the conversation, one event at a time.</p>';
        header.after(pageHeader);

        // Move the original controls so all existing event handlers keep working.
        const setup = make('dialog', 'session-setup');
        setup.id = 'sessionSetup';
        setup.setAttribute('aria-labelledby', 'setupTitle');
        setup.innerHTML = '<div class="setup-heading"><div><span class="eyebrow">Workspace</span><h2 id="setupTitle">Session setup</h2></div><button type="button" class="btn btn-neutral" id="closeSessionSetup" aria-label="Close session setup">Close</button></div><p class="setup-description">Choose your application and configure this session.</p>';
        setup.append(sidebar.querySelector('.control-panel'));
        document.body.append(setup);
        byId('openSessionSetup').addEventListener('click', () => setup.showModal());
        byId('closeSessionSetup').addEventListener('click', () => setup.close());
        setup.addEventListener('click', event => { if (event.target === setup) { const r = setup.getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) setup.close(); } });
        const stop = byId('btnStop');
        stop.parentElement.remove();
        header.querySelector('.session-actions').prepend(stop);
        byId('btnBrowseExe').textContent = 'Browse';
        byId('btnBrowseExe').setAttribute('aria-label', 'Browse for a target executable');
        byId('btnSaveHistory').textContent = 'Save session';
        byId('btnLoadHistory').textContent = 'Load session';
        byId('btnNewSession').textContent = 'New session';
        const sessionFiles = byId('btnNewSession').parentElement;
        sessionFiles.classList.add('session-files');
        sidebar.append(sessionFiles);

        const oldTabs = document.querySelector('.tabs');
        const nav = make('nav', 'workspace-nav');
        nav.id = 'workspaceNav';
        nav.setAttribute('aria-label', 'Workspace tools');
        const groups = [
            ['Traffic', ['history', 'intercept', 'repeater', 'bridge']],
            ['Runtime', ['registry', 'memory', 'static', 'dll', 'processes', 'crypto', 'pipelist', 'faker']],
            ['Findings', ['vulnerabilities', 'privesc', 'secrets', 'comrpc']]
        ];
        const descriptions = {
            Traffic: 'Inspect captured traffic and connection details.',
            Runtime: 'Explore what happens inside your application.',
            Findings: 'Inspect the evidence. Keep track of your review.'
        };
        groups.forEach(([name, ids]) => {
            const group = make('section', 'nav-group');
            group.append(make('h2', 'nav-group-label', name));
            ids.forEach(id => {
                const button = oldTabs.querySelector('[data-target="tab-' + id + '"]');
                if (!button) return;
                button.removeAttribute('style');
                button.dataset.group = name;
                button.setAttribute('aria-controls', 'tab-' + id);
                button.setAttribute('aria-current', id === 'history' ? 'page' : 'false');
                const panel = byId('tab-' + id);
                if (panel) panel.setAttribute('aria-label', button.textContent.trim());
                if (id === 'vulnerabilities') button.firstChild.textContent = 'All findings ';
                button.addEventListener('click', () => {
                    nav.querySelectorAll('.tab-btn').forEach(b => b.setAttribute('aria-current', b === button ? 'page' : 'false'));
                    byId('workspaceGroup').textContent = name;
                    byId('workspaceTitle').textContent = button.childNodes[0].textContent.trim();
                    byId('workspaceSubtitle').textContent = descriptions[name];
                    document.body.classList.remove('nav-open');
                    byId('navToggle').setAttribute('aria-expanded', 'false');
                });
                group.append(button);
            });
            nav.append(group);
        });
        sidebar.querySelector('.brand').after(nav);
        oldTabs.remove();
        byId('navToggle').addEventListener('click', () => {
            byId('navToggle').setAttribute('aria-expanded', String(document.body.classList.toggle('nav-open')));
        });
        document.addEventListener('keydown', event => {
            if (event.key === 'Escape') { document.body.classList.remove('nav-open'); byId('navToggle').setAttribute('aria-expanded', 'false'); }
        });

        // Safiye greets you in the empty workspace, leaving room for navigation.
        const art = sidebar.querySelector('.sidebar-art');
        const empty = make('div', 'history-welcome');
        empty.id = 'historyWelcome';
        empty.append(art, make('span', 'eyebrow', 'Safiye is ready'), make('h2', '', 'Your next session starts here.'), make('p', '', 'Set up an application or load a saved session to explore its activity.'));
        const welcomeActions = make('div', 'welcome-actions');
        const welcomeSetup = make('button', 'btn btn-primary', 'Set up a session');
        welcomeSetup.addEventListener('click', () => setup.showModal());
        const welcomeLoad = make('button', 'btn btn-neutral', 'Load saved session');
        welcomeLoad.addEventListener('click', () => byId('btnLoadHistory').click());
        welcomeActions.append(welcomeSetup, welcomeLoad);
        empty.append(welcomeActions);
        const tableArea = byId('historyTableArea');
        tableArea.append(empty);
        const noMatches = make('div', 'sf-empty', 'No matching events. Try another search or direction filter.');
        noMatches.hidden = true;
        tableArea.append(noMatches);
        const tbody = byId('tblHistory').querySelector('tbody');
        function updateEmpty() {
            const noRows = !tbody.children.length;
            const filtering = byId('historySearch').value.trim() || !byId('histDirAll').classList.contains('active-dir-btn');
            empty.hidden = !noRows || Boolean(filtering);
            noMatches.hidden = !noRows || !filtering;
            if (sessionActive && noRows && !filtering) {
                empty.querySelector('h2').textContent = 'Listening for activity…';
                empty.querySelector('p').textContent = 'Captured events will appear here as they arrive.';
                welcomeActions.hidden = true;
            } else {
                empty.querySelector('h2').textContent = 'Your next session starts here.';
                empty.querySelector('p').textContent = 'Set up an application or load a saved session to explore its activity.';
                welcomeActions.hidden = false;
            }
        }
        new MutationObserver(updateEmpty).observe(tbody, { childList: true });
        new MutationObserver(updateEmpty).observe(byId('sessionState'), { childList: true });
        byId('historySearch').addEventListener('input', updateEmpty);
        document.querySelectorAll('.hist-dir-btn').forEach(b => b.addEventListener('click', () => queueMicrotask(updateEmpty)));
        updateEmpty();

        // Resizable inspector, with independent saved sizes for each orientation.
        const history = byId('tab-history');
        const inspector = byId('historyDetailPanel');
        const split = make('div', 'history-split');
        tableArea.before(split);
        const handle = make('div', 'split-handle');
        handle.tabIndex = 0;
        handle.setAttribute('role', 'separator');
        handle.setAttribute('aria-label', 'Resize event inspector');
        handle.setAttribute('aria-controls', 'historyDetailPanel');
        split.append(tableArea, handle, inspector);
        const layoutButton = make('button', 'btn btn-neutral layout-toggle');
        layoutButton.id = 'historyLayoutToggle';
        history.firstElementChild.append(layoutButton);
        let layout = prefs.get('historyLayout', 'stacked');
        let ratio = 40;
        function setRatio(value) {
            ratio = Math.min(70, Math.max(25, value));
            split.style.setProperty('--inspector-size', ratio + '%');
            handle.setAttribute('aria-valuenow', String(Math.round(ratio)));
            handle.setAttribute('aria-valuemin', '25');
            handle.setAttribute('aria-valuemax', '70');
            handle.setAttribute('aria-valuetext', Math.round(ratio) + '% inspector');
        }
        function applyLayout() {
            if (!['stacked', 'side'].includes(layout)) layout = 'stacked';
            split.dataset.layout = layout;
            layoutButton.textContent = layout === 'side' ? 'Layout: side by side' : 'Layout: stacked';
            layoutButton.title = 'Switch inspector layout';
            handle.setAttribute('aria-orientation', layout === 'side' ? 'vertical' : 'horizontal');
            setRatio(Number(prefs.get('inspector.' + layout, '40')) || 40);
        }
        layoutButton.addEventListener('click', () => { layout = layout === 'side' ? 'stacked' : 'side'; prefs.set('historyLayout', layout); applyLayout(); });
        applyLayout();
        const resizeObserver = new ResizeObserver(() => {
            const side = layout === 'side' && window.innerWidth > 900;
            handle.setAttribute('aria-orientation', side ? 'vertical' : 'horizontal');
        });
        resizeObserver.observe(split);
        function syncInspector() { split.classList.toggle('has-inspector', inspector.style.display !== 'none'); }
        new MutationObserver(syncInspector).observe(inspector, { attributes: true, attributeFilter: ['style'] });
        syncInspector();
        handle.addEventListener('pointerdown', event => {
            if (event.button !== 0) return;
            handle.setPointerCapture(event.pointerId);
            handle.classList.add('dragging');
            event.preventDefault();
        });
        handle.addEventListener('pointermove', event => {
            if (!handle.hasPointerCapture(event.pointerId)) return;
            const box = split.getBoundingClientRect();
            const side = layout === 'side' && window.innerWidth > 900;
            setRatio(side ? (box.right - event.clientX) / box.width * 100 : (box.bottom - event.clientY) / box.height * 100);
        });
        const finishResize = () => { handle.classList.remove('dragging'); prefs.set('inspector.' + layout, ratio); };
        handle.addEventListener('pointerup', finishResize);
        handle.addEventListener('lostpointercapture', finishResize);
        handle.addEventListener('keydown', event => {
            if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            setRatio(event.key === 'Home' ? 25 : event.key === 'End' ? 70 : ratio + (['ArrowUp', 'ArrowLeft'].includes(event.key) ? 3 : -3));
            prefs.set('inspector.' + layout, ratio);
        });

        // Findings: scan the compact list while keeping the selected evidence open.
        const findings = make('div', 'findings-workspace');
        const findingList = byId('vulnFindingsList');
        findingList.before(findings);
        const detail = make('article', 'finding-detail');
        detail.id = 'findingDetail';
        detail.setAttribute('aria-label', 'Selected finding');
        findings.append(findingList, detail);
        renderFindings([], 0);
        const analysisLog = byId('vulnAnalysisLog').parentElement;
        analysisLog.classList.add('analysis-log');

        // A collapsible console gives the main workspace its height back.
        const consolePanel = document.querySelector('.console-panel');
        const consoleHeader = consolePanel.querySelector('.console-header');
        const consoleToggle = make('button', 'console-toggle');
        consoleToggle.setAttribute('aria-controls', 'consoleOut consoleIn');
        consoleHeader.replaceChildren(consoleToggle);
        let consoleOpen = prefs.get('consoleOpen', 'false') === 'true';
        function applyConsole() {
            consolePanel.classList.toggle('collapsed', !consoleOpen);
            consoleToggle.setAttribute('aria-expanded', String(consoleOpen));
            consoleToggle.textContent = 'System output log' + (consoleOpen ? '   −' : '   +');
        }
        consoleToggle.addEventListener('click', () => { consoleOpen = !consoleOpen; prefs.set('consoleOpen', consoleOpen); applyConsole(); });
        applyConsole();

        const motionLabel = make('label', 'motion-setting');
        const motion = make('input');
        motion.type = 'checkbox';
        motion.id = 'reduceMotion';
        motion.checked = prefs.get('reduceMotion', String(matchMedia('(prefers-reduced-motion: reduce)').matches)) === 'true';
        motionLabel.append(motion, document.createTextNode('Reduce motion'));
        sidebar.append(motionLabel);
        function applyMotion() {
            document.body.classList.toggle('reduce-motion', motion.checked);
            window.dispatchEvent(new CustomEvent('safiye:motion', { detail: { reduced: motion.checked } }));
        }
        motion.addEventListener('change', () => { prefs.set('reduceMotion', motion.checked); applyMotion(); });
        matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change', event => {
            if (prefs.get('reduceMotion', null) === null) { motion.checked = event.matches; applyMotion(); }
        });
        applyMotion();
        ['targetExe', 'targetPid', 'modePid', 'modeSpawn'].forEach(id => byId(id).addEventListener('input', updateTarget));
        setup.addEventListener('close', updateTarget);
        updateTarget();
        setInterval(() => {
            if (!startedAt) return;
            const elapsed = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
            byId('sessionElapsed').textContent = [Math.floor(elapsed / 3600), Math.floor(elapsed / 60) % 60, elapsed % 60].map(n => String(n).padStart(2, '0')).join(':');
        }, 1000);
    });
})();
