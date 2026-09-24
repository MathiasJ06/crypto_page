// npm install --no-save playwright, then: node tests/browser.cjs
// Start a static server first (default http://127.0.0.1:8000).
const path = require('node:path');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES ? path.join(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES, 'playwright') : 'playwright');
const fixture = require('./keys-fixture.json');
(async () => {
 const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_EXECUTABLE || undefined, args: ['--disable-dev-shm-usage'] });
 try {
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();
  const requests = [], errors = [];
  page.on('request', r => requests.push(r.url()));
  page.on('pageerror', e => errors.push(e.message));
  page.on('dialog', d => d.accept());
  const base = process.env.TEST_URL || 'http://127.0.0.1:8000';
  await page.goto(base);
  await page.waitForFunction(() => !document.getElementById('app').disabled);
  assert.equal(requests.length, 4, `Only HTML/CSS/two JS requests expected: ${requests}`);
  const initialRequests = requests.length;
  // All sensitive operations below take place with the browser network offline.
  await context.setOffline(true);
  await page.locator('#generate').click();
  await page.waitForFunction(() => document.getElementById('my-state').textContent.includes('3072'));
  const fp = await page.locator('#my-fingerprint').textContent();
  const publicDownload = page.waitForEvent('download');
  await page.locator('#export-public').click();
  const pub = await publicDownload;
  const publicText = fs.readFileSync(await pub.path(), 'utf8');
  await page.locator('#backup-password').fill('Une phrase secrète de test !');
  await page.locator('#backup-confirm').fill('Une phrase secrète de test !');
  const privateDownload = page.waitForEvent('download');
  await page.locator('#export-private').click();
  const priv = await privateDownload;
  const privateText = fs.readFileSync(await priv.path(), 'utf8');
  await page.waitForFunction(() => !document.getElementById('app').disabled);
  assert.equal(await page.locator('#backup-password').inputValue(), '');
  await page.locator('[data-panel=encrypt]').click();
  await page.locator('#recipient-file').setInputFiles({ name: 'recipient.json', mimeType: 'application/json', buffer: Buffer.from(publicText) });
  await page.waitForFunction(() => !document.getElementById('encrypt').disabled);
  const message = '  Message privé éè 🔐\n  Espaces préservés.\n';
  await page.locator('#encrypt-input').fill(message);
  await page.locator('#encrypt').click();
  await page.waitForFunction(() => document.getElementById('encrypt-output').value.length > 0);
  const encrypted = await page.locator('#encrypt-output').inputValue();
  assert.match(encrypted, /^[A-Za-z0-9_-]+$/);
  await page.locator('[data-panel=decrypt]').click();
  await page.locator('#sender-identity-file').setInputFiles({ name: 'sender.json', mimeType: 'application/json', buffer: Buffer.from(publicText) });
  await page.locator('#decrypt-input').fill(encrypted);
  await page.locator('#decrypt').click();
  await page.waitForFunction(() => document.getElementById('decrypt-output').value.length > 0);
  assert.equal(await page.locator('#decrypt-output').inputValue(), message);
  await page.waitForFunction(() => document.getElementById('sender-verification').textContent.includes('identité chargée reconnue'));
  await page.locator('[data-panel=keys]').click();
  await page.locator('#clear').click();
  assert.equal(await page.locator('#decrypt-output').inputValue(), '');
  assert.equal(await page.locator('#encrypt-input').inputValue(), '');
  assert.equal(await page.locator('#recipient-fingerprint').textContent(), '');
  // Regression: file first, missing phrase, incorrect phrase, then retry with the same file.
  await page.locator('#private-file').setInputFiles({ name: 'backup.json', mimeType: 'application/json', buffer: Buffer.from(privateText) });
  assert.equal(await page.locator('#my-state').textContent(), 'Aucune clé chargée');
  assert.equal(await page.locator('#private-file').evaluate(e => e.files.length), 1);
  await page.locator('#import-private').click();
  await page.waitForFunction(() => !document.getElementById('app').disabled);
  assert.ok((await page.locator('#restore-feedback').textContent()).includes('Saisissez la phrase secrète'));
  assert.equal(await page.locator('#private-file').evaluate(e => e.files.length), 1);
  await page.locator('#restore-password').fill('Mauvaise phrase secrète');
  await page.locator('#import-private').click();
  await page.waitForFunction(() => !document.getElementById('app').disabled);
  assert.ok((await page.locator('#restore-feedback').textContent()).includes('phrase secrète incorrecte'));
  assert.equal(await page.locator('#private-file').evaluate(e => e.files.length), 1);
  await page.locator('#restore-password').fill('Une phrase secrète de test !');
  await page.locator('#restore-password').press('Enter');
  await page.waitForFunction(() => document.getElementById('my-state').textContent.includes('3072'));
  assert.equal(await page.locator('#my-fingerprint').textContent(), fp);
  // Wrong file gets an actionable message without replacing the successfully loaded identity.
  await page.locator('#private-file').setInputFiles({ name: 'public.pem', mimeType: 'text/plain', buffer: Buffer.from(publicText) });
  await page.locator('#import-private').click();
  await page.waitForFunction(() => !document.getElementById('app').disabled);
  assert.ok((await page.locator('#restore-feedback').textContent()).includes('clé publique'));
  assert.equal(await page.locator('#my-fingerprint').textContent(), fp);
  // Independently generated PKCS#8 key remains importable.
  await page.locator('#private-file').setInputFiles({ name: 'old.key', mimeType: 'text/plain', buffer: Buffer.from(fixture.private) });
  await page.locator('#import-private').click();
  await page.waitForFunction(() => document.getElementById('my-state').textContent.includes('2048'));
  await page.locator('[data-panel=decrypt]').click();
  await page.locator('#decrypt-input').fill('invalid');
  await page.locator('#decrypt').click();
  await page.waitForFunction(() => document.getElementById('status').classList.contains('error'));
  assert.equal(await page.locator('#decrypt-output').inputValue(), '');
  assert.equal(requests.length, initialRequests, 'No requests during private operations');
  assert.deepEqual(errors, []);
  const storage = await page.evaluate(async () => ({ local: localStorage.length, session: sessionStorage.length, cookies: document.cookie, databases: await indexedDB.databases() }));
  assert.deepEqual(storage, { local: 0, session: 0, cookies: '', databases: [] });
  await context.setOffline(false);
  const blocked = await page.evaluate(async () => {
   try { await fetch('/should-never-leave?probe=public-test'); return false; } catch { return true; }
  });
  assert.ok(blocked, 'CSP blocks even same-origin fetch');
  await page.locator('[data-panel=keys]').click(); await page.locator('#clear').click();
  await page.setViewportSize({ width: 1360, height: 1050 });
  const output = process.env.TEST_OUTPUT_DIR || path.join(__dirname, '..', 'test-results');
  fs.mkdirSync(output, { recursive: true });
  await page.screenshot({ path: path.join(output, 'desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: path.join(output, 'mobile.png'), fullPage: true });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No mobile overflow');
  console.log(JSON.stringify({ result: 'PASS', startupRequests: initialRequests, requestsDuringSensitiveOperations: 0, offline: 'generation, public export, protected backup, import, opaque signed v3 encrypt/decrypt and sender verification', csp: 'fetch blocked', storage, pageErrors: errors, mobile: 'no overflow' }, null, 2));
 } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exitCode = 1; });
