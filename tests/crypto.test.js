import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as e from '../crypto-engine.js';
const fixture = JSON.parse(await readFile(new URL('./legacy-fixture.json', import.meta.url)));
const privateKey = await e.importPrivate(fixture.private);
const publicKey = await e.importPublic(fixture.public);
const phrase = 'Une phrase de test très longue !';
const pair = await e.generateKeys();

test('RSA generation uses 3072 bits and matching public/private keys', async () => {
    assert.equal(pair.privateKey.algorithm.modulusLength, 3072);
    assert.equal(await e.fingerprint(pair.publicKey), await e.fingerprint(await e.publicFromPrivate(pair.privateKey)));
});
test('PEM public export/import preserves fingerprint', async () => {
    assert.equal(await e.fingerprint(await e.importPublic(await e.publicPEM(pair.publicKey))), await e.fingerprint(pair.publicKey));
});
test('v2 round trips exact text, unicode, quotes, whitespace and long messages', async () => {
    for (const message of ['  éè 🔐\n\n', '""" \\ <script> Ω', ' ', 'a'.repeat(100000)]) {
        const token = await e.encrypt(publicKey, message);
        assert.equal(await e.decrypt(privateKey, token), message);
    }
});
test('message size limit applies to UTF-8 bytes', async () => {
    await assert.rejects(e.encrypt(publicKey, ''));
    await assert.rejects(e.encrypt(publicKey, 'é'.repeat(e.MAX_TEXT_BYTES / 2 + 1)));
});
test('same message produces distinct ciphertexts and nonces', async () => {
    const a = JSON.parse(await e.encrypt(publicKey, 'message')), b = JSON.parse(await e.encrypt(publicKey, 'message'));
    assert.notEqual(a.iv, b.iv); assert.notEqual(a.ek, b.ek); assert.notEqual(a.ct, b.ct);
});
test('wrong recipient key is rejected', async () => {
    await assert.rejects(e.decrypt(pair.privateKey, await e.encrypt(publicKey, 'secret')));
});
test('tampering with ciphertext, nonce, wrapped key, recipient, version or algorithm fails', async () => {
    const o = JSON.parse(await e.encrypt(publicKey, 'secret'));
    for (const field of ['iv', 'ek', 'ct']) {
        const bytes = e.decode(o[field]); bytes[0] ^= 1;
        await assert.rejects(e.decrypt(privateKey, JSON.stringify({ ...o, [field]: e.encode(bytes) })));
    }
    for (const [field, value] of [['kid', 'wrong'], ['v', 999], ['alg', 'wrong']]) {
        await assert.rejects(e.decrypt(privateKey, JSON.stringify({ ...o, [field]: value })));
    }
});
test('malformed envelopes are rejected', async () => {
    for (const token of ['', '{}', 'null', '[]', '{broken', '***', 'A'.repeat(9 * 1024 * 1024)]) await assert.rejects(e.decrypt(privateKey, token));
});
test('Python-generated legacy Fernet message is readable exactly', async () => {
    assert.equal(await e.decrypt(privateKey, fixture.token), fixture.message);
});
test('legacy tampering, truncation and wrong key fail', async () => {
    const data = e.decode(fixture.token);
    const len = new DataView(data.buffer).getUint32(0);
    const token = e.decode(new TextDecoder().decode(data.subarray(4, 4 + len)));
    token[30] ^= 1;
    // Preserve padding expected by the old serialized envelope.
    const b64 = e.encode(token); const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
    data.set(new TextEncoder().encode(padded), 4);
    await assert.rejects(e.decrypt(privateKey, e.encode(data)));
    await assert.rejects(e.decrypt(privateKey, fixture.token.slice(0, 100)));
    await assert.rejects(e.decrypt(pair.privateKey, fixture.token));
});
test('protected backup restores identity and rejects wrong passphrase', async () => {
    const backup = await e.protectPrivate(privateKey, phrase);
    assert.ok(!backup.includes('PRIVATE KEY'));
    const restored = await e.restorePrivate(backup, phrase);
    assert.equal(await e.fingerprint(await e.publicFromPrivate(restored)), await e.fingerprint(publicKey));
    await assert.rejects(e.restorePrivate(backup, 'wrong passphrase'));
    assert.equal(await e.decrypt(restored, fixture.token), fixture.message);
});
test('backup rejects weak password, modified metadata, ciphertext and hostile work factor', async () => {
    await assert.rejects(e.protectPrivate(privateKey, 'short'));
    const o = JSON.parse(await e.protectPrivate(privateKey, phrase));
    for (const patch of [{ iterations: 2000000000 }, { v: 2 }, { kdf: 'wrong' }, { ct: 'AAAA' }, { salt: 'AA' }, { iv: 'AA' }]) {
        await assert.rejects(e.restorePrivate(JSON.stringify({ ...o, ...patch }), phrase));
    }
    const correctKid = await e.fingerprint(await e.publicFromPrivate(privateKey));
    assert.equal(
        await e.fingerprint(await e.publicFromPrivate(await e.restorePrivate(JSON.stringify({ ...o, kid: correctKid }), phrase))),
        correctKid,
    );
    await assert.rejects(e.restorePrivate(JSON.stringify({ ...o, kid: '0000'.repeat(16) }), phrase));
});
test('old unencrypted private PEM can be restored', async () => {
    assert.equal(await e.decrypt(await e.restorePrivate(fixture.private, ''), fixture.token), fixture.message);
});
test('invalid, non-RSA and short RSA keys are rejected', async () => {
    await assert.rejects(e.importPublic('-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----'));
    const ec = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    await assert.rejects(e.importPublic(await e.publicPEM(ec.publicKey)));
    const small = await crypto.subtle.generateKey({ name: 'RSA-OAEP', hash: 'SHA-256', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]) }, true, ['encrypt', 'decrypt']);
    await assert.rejects(e.importPublic(await e.publicPEM(small.publicKey)));
});
test('HTML blocks network connections and only loads local code', async () => {
    const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
    assert.ok(html.includes("connect-src 'none'"));
    assert.ok(html.includes("form-action 'none'"));
    assert.ok(html.includes("worker-src 'none'"));
    assert.ok(!/<script[^>]*src=["']https?:/i.test(html));
});
