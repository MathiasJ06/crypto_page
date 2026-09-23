import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as engine from '../crypto-engine.js';

const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const fixture = name => readFileSync(join(fixtures, name), 'utf-8');

test('backup JSON round-trip: generate, protect, restore, decrypt', async () => {
    const pair = await engine.generateKeys();
    const envelope = await engine.encrypt(pair.publicKey, 'Bonjour secret.');
    const backup = await engine.protectPrivate(pair.privateKey, 'une phrase secrete longue');
    const restored = await engine.restorePrivate(backup, 'une phrase secrete longue');
    const decrypted = await engine.decrypt(restored, envelope);
    if (decrypted !== 'Bonjour secret.') throw new Error('round-trip failed');
});

test('backup JSON: wrong passphrase rejected', async () => {
    const pair = await engine.generateKeys();
    const backup = await engine.protectPrivate(pair.privateKey, 'une phrase secrete longue');
    let threw = false;
    try { await engine.restorePrivate(backup, 'mauvaise phrase'); } catch { threw = true; }
    if (!threw) throw new Error('wrong passphrase accepted');
});

test('PKCS#8 PEM import and decrypt of v2 message', async () => {
    const pair = await engine.generateKeys();
    const envelope = await engine.encrypt(pair.publicKey, 'Message PKCS#8.');
    const raw = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
    const b64 = btoa(String.fromCharCode(...raw));
    const pem = `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----\n`;
    const key = await engine.restorePrivate(pem, '');
    if (await engine.decrypt(key, envelope) !== 'Message PKCS#8.') throw new Error('decrypt failed');
});

test('legacy Python key imports and decrypts real legacy binary message', async () => {
    const key = await engine.restorePrivate(fixture('legacy-private.pem'), '');
    const decrypted = await engine.decrypt(key, fixture('legacy-message.txt'));
    if (decrypted !== 'Message historique de test.') throw new Error(`unexpected: ${decrypted}`);
});

test('PKCS#1 PEM (BEGIN RSA PRIVATE KEY) imports and decrypts', async () => {
    const key = await engine.restorePrivate(fixture('legacy-private-pkcs1.pem'), '');
    if (await engine.decrypt(key, fixture('legacy-message.txt')) !== 'Message historique de test.') throw new Error('decrypt failed');
});

test('JSON file containing private_key (old generate_rsa_keys output) imports', async () => {
    const json = JSON.stringify({ public_key: 'x', private_key: fixture('legacy-private.pem'), key_size: 2048 });
    const key = await engine.restorePrivate(json, '');
    if (await engine.decrypt(key, fixture('legacy-message.txt')) !== 'Message historique de test.') throw new Error('decrypt failed');
});

test('PEM with UTF-8 BOM and CRLF imports', async () => {
    const text = '\uFEFF' + fixture('legacy-private.pem').replace(/\n/g, '\r\n');
    const key = await engine.restorePrivate(text, '');
    if (await engine.decrypt(key, fixture('legacy-message.txt')) !== 'Message historique de test.') throw new Error('decrypt failed');
});

test('password-protected PEM gives a clear unsupported error', async () => {
    let message = '';
    try { await engine.restorePrivate(fixture('legacy-private-encrypted.pem'), 'phrase-de-test-1234'); }
    catch (error) { message = error.message; }
    if (!message.includes('non prise en charge')) throw new Error(`unexpected message: ${message}`);
});

test('unreadable file gives a clear error', async () => {
    let message = '';
    try { await engine.restorePrivate('ceci n est pas une cle', ''); }
    catch (error) { message = error.message; }
    if (!message.includes('Aucune clé privée')) throw new Error(`unexpected message: ${message}`);
});

test('old Python public key imports and v2 cross-decrypt works', async () => {
    const pub = await engine.importPublic(fixture('legacy-public.pem'));
    const key = await engine.restorePrivate(fixture('legacy-private.pem'), '');
    if (await engine.decrypt(key, fixture('legacy-public-v2-message.json')) !== 'Message v2 chiffre pour une cle ancienne.') throw new Error('cross decrypt failed');
});

test('old raw-JSON format (ca76dd9..ea20c28) decrypts', async () => {
    const key = await engine.restorePrivate(fixture('old-format-private.pem'), '');
    if (await engine.decrypt(key, fixture('old-json-message.json')) !== 'Message ancien format.') throw new Error('decrypt failed');
});

test('old base64(JSON) format (9a5bd2d) decrypts', async () => {
    const key = await engine.restorePrivate(fixture('old-format-private.pem'), '');
    if (await engine.decrypt(key, fixture('old-b64json-message.txt')) !== 'Message ancien format.') throw new Error('decrypt failed');
});

test('old separator format (abd52fc) decrypts', async () => {
    const key = await engine.restorePrivate(fixture('old-format-private.pem'), '');
    if (await engine.decrypt(key, fixture('old-separator-message.txt')) !== 'Message ancien format.') throw new Error('decrypt failed');
});

test('public PEM export round-trips', async () => {
    const pair = await engine.generateKeys();
    const pem = await engine.publicPEM(pair.publicKey);
    if ((await engine.fingerprint(await engine.importPublic(pem))) !== (await engine.fingerprint(pair.publicKey))) throw new Error('fingerprint mismatch');
});
