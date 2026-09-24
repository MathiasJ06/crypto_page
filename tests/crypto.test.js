import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as e from '../crypto-engine.js';
const fixture = JSON.parse(await readFile(new URL('./keys-fixture.json', import.meta.url)));
const privateKey = await e.importPrivate(fixture.private);
const publicKey = await e.importPublic(fixture.public);
const unpack = token => JSON.parse(new TextDecoder().decode(e.decode(token)));
const pack = envelope => e.encode(new TextEncoder().encode(JSON.stringify(envelope)));
const phrase = 'Une phrase de test très longue !';
const pair = await e.generateKeys();

test('RSA generation uses 3072 bits and matching public/private keys', async () => {
    assert.equal(pair.privateKey.algorithm.modulusLength, 3072);
    assert.equal(await e.fingerprint(pair.publicKey), await e.fingerprint(await e.publicFromPrivate(pair.privateKey)));
});
test('PEM public export/import preserves fingerprint', async () => {
    assert.equal(await e.fingerprint(await e.importPublic(await e.publicPEM(pair.publicKey))), await e.fingerprint(pair.publicKey));
});
test('signed v3 round trips exact text, unicode, quotes, whitespace and long messages', async () => {
    for (const message of ['  éè 🔐\n\n', '""" \\ <script> Ω', ' ', 'a'.repeat(100000)]) {
        const token = await e.encrypt(publicKey, message, pair);
        assert.match(token, /^[A-Za-z0-9_-]+$/);
        assert.ok(!token.startsWith('{'));
        assert.ok(!token.includes('"ct"'));
        const result = await e.decrypt(privateKey, token);
        assert.equal(result.message, message);
        assert.equal(result.senderTrusted, false);
        assert.equal(result.senderFingerprint, await e.fingerprint(pair.signingPublicKey));
    }
});
test('only the re-encoded envelope format is accepted', async () => {
    const current = unpack(await e.encrypt(publicKey, 'format encodé', pair));
    await assert.rejects(e.decrypt(privateKey, JSON.stringify(current)));
});
test('message size limit applies to UTF-8 bytes', async () => {
    await assert.rejects(e.encrypt(publicKey, '', pair));
    await assert.rejects(e.encrypt(publicKey, 'é'.repeat(e.MAX_TEXT_BYTES / 2 + 1), pair));
});
test('same message produces distinct ciphertexts and nonces', async () => {
    const a = unpack(await e.encrypt(publicKey, 'message', pair)), b = unpack(await e.encrypt(publicKey, 'message', pair));
    assert.notEqual(a.iv, b.iv); assert.notEqual(a.ek, b.ek); assert.notEqual(a.ct, b.ct);
});
test('wrong recipient key is rejected', async () => {
    await assert.rejects(e.decrypt(pair.privateKey, await e.encrypt(publicKey, 'secret', pair)));
});
test('tampering with ciphertext, nonce, wrapped key, recipient, version or algorithm fails', async () => {
    const o = unpack(await e.encrypt(publicKey, 'secret', pair));
    for (const field of ['iv', 'ek', 'ct']) {
        const bytes = e.decode(o[field]); bytes[0] ^= 1;
        await assert.rejects(e.decrypt(privateKey, pack({ ...o, [field]: e.encode(bytes) })));
    }
    for (const [field, value] of [['kid', 'wrong'], ['v', 999], ['alg', 'wrong']]) {
        await assert.rejects(e.decrypt(privateKey, pack({ ...o, [field]: value })));
    }
});
test('a signed message verifies against its advertised sender identity', async () => {
    const token = await e.encrypt(publicKey, 'message signé', pair);
    const identity = await e.importPublicIdentity(await e.publicIdentity(pair));
    const result = await e.decrypt(privateKey, token, identity.signingPublicKey);
    assert.equal(result.message, 'message signé');
    assert.equal(result.senderTrusted, true);
});
test('a different expected sender key and modified signature are rejected', async () => {
    const token = await e.encrypt(publicKey, 'secret', pair);
    const other = await e.generateKeys();
    await assert.rejects(e.decrypt(privateKey, token, other.signingPublicKey));
    const envelope = unpack(token), signature = e.decode(envelope.sig);
    signature[0] ^= 1;
    await assert.rejects(e.decrypt(privateKey, pack({ ...envelope, sig: e.encode(signature) })));
    await assert.rejects(e.decrypt(privateKey, pack({ ...envelope, senderKey: e.encode(new Uint8Array(await crypto.subtle.exportKey('spki', other.signingPublicKey))) })));
});
test('public identity bundle contains encryption and signing public keys', async () => {
    const identity = await e.importPublicIdentity(await e.publicIdentity(pair));
    assert.equal(await e.fingerprint(identity.publicKey), await e.fingerprint(pair.publicKey));
    assert.equal(await e.fingerprint(identity.signingPublicKey), await e.fingerprint(pair.signingPublicKey));
    assert.equal((await e.importPublicIdentity(fixture.public)).signingPublicKey, null);
});
test('malformed envelopes are rejected', async () => {
    for (const token of ['', '{}', 'null', '[]', '{broken', '***', 'not-an-envelope', 'A'.repeat(9 * 1024 * 1024)]) await assert.rejects(e.decrypt(privateKey, token));
});
test('protected backup restores identity and rejects wrong passphrase', async () => {
    const backup = await e.protectPrivate(pair, phrase);
    assert.ok(!backup.includes('PRIVATE KEY'));
    const restored = await e.restorePrivate(backup, phrase);
    const token = await e.encrypt(pair.publicKey, 'message de contrôle', pair);
    assert.equal(await e.fingerprint(await e.publicFromPrivate(restored.privateKey)), await e.fingerprint(pair.publicKey));
    assert.equal(await e.fingerprint(await e.publicSigningFromPrivate(restored.signingPrivateKey)), await e.fingerprint(pair.signingPublicKey));
    await assert.rejects(e.restorePrivate(backup, 'wrong passphrase'));
    assert.equal((await e.decrypt(restored.privateKey, token)).message, 'message de contrôle');
});
test('legacy encrypted RSA-only v1 private backup is rejected', async () => {
    const password = 'Phrase secrète historique de test';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    const aes = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
    const aad = new TextEncoder().encode('crypto-page/private-key/v1/PBKDF2-SHA256/600000/A256GCM');
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, aes, pkcs8));
    const backup = JSON.stringify({ type: 'crypto-page-private-key', v: 1, kdf: 'PBKDF2-SHA256', iterations: 600000, alg: 'A256GCM', salt: e.encode(salt), iv: e.encode(iv), ct: e.encode(ct) });
    await assert.rejects(e.restorePrivate(backup, password));
});
test('backup rejects weak password, modified metadata, ciphertext and hostile work factor', async () => {
    await assert.rejects(e.protectPrivate(pair, 'short'));
    const o = JSON.parse(await e.protectPrivate(pair, phrase));
    for (const patch of [{ iterations: 2000000000 }, { v: 1 }, { kdf: 'wrong' }, { ct: 'AAAA' }, { salt: 'AA' }, { iv: 'AA' }]) {
        await assert.rejects(e.restorePrivate(JSON.stringify({ ...o, ...patch }), phrase));
    }
    const correctKid = await e.fingerprint(pair.publicKey);
    assert.equal(await e.fingerprint(await e.publicFromPrivate((await e.restorePrivate(JSON.stringify(o), phrase)).privateKey)), correctKid);
});
test('private backups cannot be restored without a passphrase and raw PEM is rejected', async () => {
    await assert.rejects(e.restorePrivate(JSON.stringify({}), ''));
    await assert.rejects(e.restorePrivate(fixture.private, phrase));
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
test('private-key import requires a passphrase and only accepts encrypted JSON backups', async () => {
    const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
    const script = await readFile(new URL('../script.js', import.meta.url), 'utf8');
    assert.match(html, /id="restore-password"[^>]*required/);
    assert.match(html, /Sauvegarde de clé privée chiffrée/);
    assert.match(html, /phrase secrète de la sauvegarde \(obligatoire\)/i);
    assert.match(script, /!\$\('restore-password'\)\.value\.length/);
    assert.match(script, /Les clés privées PEM ne sont pas acceptées/);
    assert.match(script, /backup\.v !== 2/);
});
