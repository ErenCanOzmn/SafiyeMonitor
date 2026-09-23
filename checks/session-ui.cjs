// UI persistence regression checks. All HTTP/WebSocket operations are mocked.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
    const root = path.resolve(__dirname, '..');
    const browser = await chromium.launch({ headless: true, ...(process.env.SAFIYE_TEST_CHROMIUM ? { executablePath: process.env.SAFIYE_TEST_CHROMIUM } : {}) });
    try {
        const page = await browser.newPage({ acceptDownloads: true });
        const errors = [], requests = [], dialogs = [];
        const finding = { title: 'Example observation', severity: 'INFO', source: 'rule', evidence: 'sample', ui_review_status: 'Unreviewed' };
        const archive = { format: 'safiye.session', version: 2, metadata: { target_name: 'Example.exe', target_pid: 1234 },
            coverage: { dropped_events: 0 }, analysis: { counts: { tcp_out: 1 } },
            session_events: [{ type: 'tcp_out', body: 'sample', dest: 'example.test:443', socket: 1 }],
            session_snapshot: {}, vuln_findings: [finding], vuln_sources: { rule: [{ ...finding }] } };
        page.on('pageerror', error => errors.push(error.message));
        page.on('dialog', dialog => { dialogs.push(dialog.message()); dialog.accept(); });
        await page.addInitScript(() => {
            window.WebSocket = class {
                static OPEN = 1;
                constructor() { this.readyState = 1; window.__socket = this; setTimeout(() => this.onopen?.(), 0); }
                send() {}
            };
        });
        await page.route('**/*', async route => {
            const url = new URL(route.request().url());
            if (url.hostname !== 'session.test') return route.abort();
            if (url.pathname.startsWith('/api/')) {
                const body = route.request().postDataJSON();
                requests.push({ path: url.pathname, body });
                let result = { status: 'ok' };
                if (url.pathname === '/api/status') result = { is_hooking: false };
                if (url.pathname === '/api/export_session') result = archive;
                if (url.pathname === '/api/import_session') result = { status: 'ok', events: 1, findings: 1 };
                if (url.pathname === '/api/finding_review') {
                    archive.vuln_findings[0].ui_review_status = body.ui_review_status;
                    archive.vuln_sources.rule[0].ui_review_status = body.ui_review_status;
                }
                return route.fulfill({ json: result });
            }
            const file = url.pathname === '/' ? path.join(root, 'src/templates/index.html') : path.join(root, 'src', url.pathname);
            if (!file.startsWith(path.join(root, 'src')) || !fs.existsSync(file)) return route.fulfill({ status: 404 });
            const mime = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.png': 'image/png' }[path.extname(file)];
            return route.fulfill({ body: fs.readFileSync(file), contentType: mime });
        });
        const receive = message => page.evaluate(message => window.__socket.onmessage({ data: JSON.stringify(message) }), message);
        await page.goto('http://session.test/');
        await page.waitForFunction(() => window.__socket?.onmessage);
        await receive({ type: 'vuln_findings', findings: [finding] });
        await page.locator('[data-target="tab-vulnerabilities"]').click();
        assert.equal(await page.locator('.finding-row').count(), 0, 'Unreviewed item must not enter confirmed list');
        await page.locator('#btnReviewObservations').click();
        await page.locator('#findingReviewStatus').selectOption('In review');
        await page.waitForFunction(() => !document.getElementById('findingReviewStatus').disabled);
        assert.equal(requests.find(r => r.path === '/api/finding_review').body.ui_review_status, 'In review');
        const downloadPromise = page.waitForEvent('download');
        await page.locator('#btnSaveHistory').click();
        const download = await downloadPromise;
        const saved = JSON.parse(fs.readFileSync(await download.path(), 'utf8'));
        assert.equal(saved.version, 2);
        assert.equal(saved.vuln_findings[0].ui_review_status, 'In review');
        assert.equal(saved.vuln_sources.rule[0].ui_review_status, 'In review');
        // A reviewed server result appears only after an explicit confirmation.
        await receive({ type: 'vuln_findings', findings: [{ ...finding, ui_review_status: 'Confirmed', validation_status: 'confirmed' }], observations: [] });
        await page.locator('#btnConfirmedFindings').click();
        assert.equal(await page.locator('.finding-row').count(), 1);
        // A legacy runtime alert cannot directly inject a vulnerability.
        await receive({ type: 'vulnerability_report', vulnerabilities: [{ title: 'Unverified signature', description: 'sample' }] });
        assert.equal(await page.locator('.finding-row').count(), 1);
        await page.locator('#loadHistoryInput').setInputFiles({ name: 'sample.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(saved)) });
        await page.waitForFunction(() => !document.getElementById('btnLoadHistory').disabled);
        assert.equal(requests.find(r => r.path === '/api/import_session').body.metadata.target_name, 'Example.exe');
        await receive({ type: 'process_spawn', api: 'CreateProcessW', exe: 'Example.exe', args: '' });
        await receive({ type: 'session_cleared' });
        assert.equal(await page.locator('#tblProcessesBody tr').count(), 0);
        await receive({ type: 'session_loaded', metadata: saved.metadata });
        await receive({ type: 'session_replay', events: saved.session_events });
        assert.equal(await page.locator('#sessionState').textContent(), 'Loaded');
        assert.equal(await page.locator('#sessionTarget').textContent(), 'Example.exe');
        await receive({ type: 'artifact_inventory', metadata: { is_dotnet: false, native: { scanned_bytes: 100 } }, data: [
            { tier: 'native', category: 'url', severity: 'INFO', masked: 'https://example.test/api', validation_status: 'inventory', offset: 4 },
            { tier: 'native', category: 'ip', severity: 'INFO', masked: '10.2.3.4', validation_status: 'inventory', offset: 20 }
        ] });
        assert.equal(await page.locator('#tblNativeSecretsBody tr').count(), 2);
        assert.equal(await page.locator('#btnSecretsToVuln').isDisabled(), true, 'Endpoint inventory cannot be queued as a credential vulnerability');
        await page.locator('#btnAnalyzeAI').click();
        await page.waitForTimeout(100);
        assert.deepEqual(requests.find(r => r.path === '/api/analyze_vulnerabilities').body, {});
        assert.deepEqual(errors, []);
        assert.deepEqual(dialogs, []);
        console.log('PASS: save/load, review sync, confirmation gate, legacy alert isolation, endpoint inventory, archive display, clear, AI snapshot request. All network mocked.');
    } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
