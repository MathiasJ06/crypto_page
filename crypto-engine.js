/* All operations use the browser's Web Crypto API. No network or persistence. */
export const MAX_TEXT_BYTES = 2 * 1024 * 1024;
const MAX_ENVELOPE = 8 * 1024 * 1024;
const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });
const rsa = { name: 'RSA-OAEP', hash: 'SHA-256' };
const ecdsa = { name: 'ECDSA', namedCurve: 'P-256' };
const alg = 'RSA-OAEP-256+A256GCM+ECDSA-P256-SHA256';
const rounds = 600000;
const fail = () => { throw new Error('Format invalide ou non pris en charge.'); };
export function encode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode(...bytes.subarray(i, i + 32768));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function decode(s) {
    if (typeof s !== 'string' || s.length > MAX_ENVELOPE || !/^[A-Za-z0-9_+\/-]*={0,2}$/.test(s)) fail();
    try { return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); }
    catch { fail(); }
}
function parse(text) {
    if (typeof text !== 'string' || text.length > MAX_ENVELOPE) fail();
    try { const o = JSON.parse(text); if (!o || typeof o !== 'object' || Array.isArray(o)) fail(); return o; }
    catch { fail(); }
}
function pemBytes(text, type) {
    if (typeof text !== 'string' || text.length > 65536) fail();
    const m = text.trim().match(new RegExp(`^-----BEGIN ${type}-----([\\s\\S]+)-----END ${type}-----$`));
    if (!m) fail();
    return decode(m[1].replace(/\s/g, ''));
}
function checkRSA(key) {
    if (key.algorithm.name !== 'RSA-OAEP' || key.algorithm.modulusLength < 2048 || key.algorithm.modulusLength > 8192) {
        throw new Error('Clé RSA attendue : entre 2048 et 8192 bits.');
    }
    return key;
}
export async function importPublic(pem) {
    return checkRSA(await crypto.subtle.importKey('spki', pemBytes(pem, 'PUBLIC KEY'), rsa, true, ['encrypt']));
}
export async function importPrivate(pem) {
    return checkRSA(await crypto.subtle.importKey('pkcs8', pemBytes(pem, 'PRIVATE KEY'), rsa, true, ['decrypt']));
}
export async function importSigningPublic(encoded) {
    const key = await crypto.subtle.importKey('spki', decode(encoded), ecdsa, true, ['verify']);
    if (key.algorithm.name !== 'ECDSA' || key.algorithm.namedCurve !== 'P-256' || key.type !== 'public') fail();
    return key;
}
export async function publicSigningFromPrivate(key) {
    if (key.algorithm.name !== 'ECDSA' || key.algorithm.namedCurve !== 'P-256' || key.type !== 'private') fail();
    const j = await crypto.subtle.exportKey('jwk', key);
    return crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: j.x, y: j.y, ext: true }, ecdsa, true, ['verify']);
}
export async function publicFromPrivate(key) {
    const j = await crypto.subtle.exportKey('jwk', key);
    return crypto.subtle.importKey('jwk', { kty: 'RSA', n: j.n, e: j.e, ext: true }, rsa, true, ['encrypt']);
}
export function generateSigningKeys() {
    return crypto.subtle.generateKey(ecdsa, true, ['sign', 'verify']);
}
export async function generateKeys() {
    const [encryption, signing] = await Promise.all([
        crypto.subtle.generateKey({ ...rsa, modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]) }, true, ['encrypt', 'decrypt']),
        generateSigningKeys(),
    ]);
    return {
        publicKey: encryption.publicKey,
        privateKey: encryption.privateKey,
        signingPublicKey: signing.publicKey,
        signingPrivateKey: signing.privateKey,
    };
}
export async function publicPEM(key) {
    const b = new Uint8Array(await crypto.subtle.exportKey('spki', key));
    const s = encode(b).replace(/-/g, '+').replace(/_/g, '/');
    const padded = s + '='.repeat((4 - s.length % 4) % 4);
    return `-----BEGIN PUBLIC KEY-----\n${padded.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`;
}
export async function fingerprint(key) {
    const raw = await crypto.subtle.exportKey('spki', key);
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', raw)), b => b.toString(16).padStart(2, '0')).join('').match(/.{4}/g).join(' ');
}
export async function publicIdentity(identity) {
    if (!identity?.publicKey || !identity?.signingPublicKey) fail();
    const signingSpki = new Uint8Array(await crypto.subtle.exportKey('spki', identity.signingPublicKey));
    return JSON.stringify({
        type: 'crypto-page-public-identity', v: 1,
        encryptionPublicKey: await publicPEM(identity.publicKey),
        signingAlgorithm: 'ECDSA-P256-SHA256',
        signingPublicKey: encode(signingSpki),
    });
}
export async function importPublicIdentity(text) {
    const trimmed = text.trim();
    if (!trimmed.startsWith('{')) return { publicKey: await importPublic(trimmed), signingPublicKey: null };
    const bundle = parse(trimmed);
    if (bundle.type !== 'crypto-page-public-identity' || bundle.v !== 1 || bundle.signingAlgorithm !== 'ECDSA-P256-SHA256') fail();
    return {
        publicKey: await importPublic(bundle.encryptionPublicKey),
        signingPublicKey: await importSigningPublic(bundle.signingPublicKey),
    };
}
function aad(kid) { return te.encode(JSON.stringify({ v: 3, alg, kid })); }
function signedFields(o) {
    return JSON.stringify({
        v: o.v, alg: o.alg, kid: o.kid, iv: o.iv, ek: o.ek, ct: o.ct,
        senderKid: o.senderKid, senderKey: o.senderKey,
    });
}
export async function encrypt(key, message, identity) {
    if (!identity?.signingPrivateKey || !identity?.signingPublicKey) throw new Error('Aucune clé de signature personnelle chargée.');
    const data = te.encode(message);
    if (!data.length || data.length > MAX_TEXT_BYTES) throw new Error('Message attendu : de 1 octet à 2 Mio.');
    const aes = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const kid = await fingerprint(key);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(kid) }, aes, data);
    const ek = await crypto.subtle.encrypt(rsa, key, await crypto.subtle.exportKey('raw', aes));
    const envelope = {
        v: 3, alg, kid, iv: encode(iv), ek: encode(new Uint8Array(ek)), ct: encode(new Uint8Array(ct)),
        senderKid: await fingerprint(identity.signingPublicKey),
        senderKey: encode(new Uint8Array(await crypto.subtle.exportKey('spki', identity.signingPublicKey))),
    };
    envelope.sig = encode(new Uint8Array(await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' }, identity.signingPrivateKey, te.encode(signedFields(envelope)),
    )));
    return encode(te.encode(JSON.stringify(envelope)));
}
export async function decrypt(key, text, expectedSenderKey = null) {
    try {
        if (text.length > MAX_ENVELOPE) fail();
        const envelopeText = td.decode(decode(text.trim()));
        const o = parse(envelopeText);
        if (o.v !== 3 || o.alg !== alg || o.kid !== await fingerprint(await publicFromPrivate(key))) fail();
        const iv = decode(o.iv), ek = decode(o.ek), ct = decode(o.ct);
        if (iv.length !== 12 || ek.length !== key.algorithm.modulusLength / 8 || ct.length < 16 || ct.length > MAX_TEXT_BYTES + 16) fail();
        const senderKey = await importSigningPublic(o.senderKey);
        const senderFingerprint = await fingerprint(senderKey);
        const signature = decode(o.sig);
        if (signature.length !== 64 || senderFingerprint !== o.senderKid) fail();
        if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, senderKey, signature, te.encode(signedFields(o)))) fail();
        if (expectedSenderKey && senderFingerprint !== await fingerprint(expectedSenderKey)) fail();
        const raw = await crypto.subtle.decrypt(rsa, key, ek);
        if (raw.byteLength !== 32) fail();
        const aes = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
        return {
            message: td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad(o.kid) }, aes, ct)),
            senderFingerprint,
            senderTrusted: Boolean(expectedSenderKey),
        };
    } catch { throw new Error('Déchiffrement impossible : mauvaise clé, message altéré ou format non pris en charge.'); }
}
async function passwordKey(password, salt, usages) {
    const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: rounds }, base, { name: 'AES-GCM', length: 256 }, false, usages);
}
const backupAADv1 = te.encode('crypto-page/private-key/v1/PBKDF2-SHA256/600000/A256GCM');
const backupAADv2 = te.encode('crypto-page/private-identity/v2/PBKDF2-SHA256/600000/A256GCM');
export async function protectPrivate(identity, password) {
    if (password.length < 12) throw new Error('Choisis une phrase secrète d’au moins 12 caractères.');
    const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    if (!identity?.privateKey || !identity?.signingPrivateKey) throw new Error('L’identité doit comporter ses clés de chiffrement et de signature.');
    const raw = new Uint8Array(await crypto.subtle.exportKey('pkcs8', identity.privateKey));
    const signingRaw = new Uint8Array(await crypto.subtle.exportKey('pkcs8', identity.signingPrivateKey));
    try {
        const payload = te.encode(JSON.stringify({ encryption: encode(raw), signing: encode(signingRaw) }));
        const aes = await passwordKey(password, salt, ['encrypt']);
        const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: backupAADv2 }, aes, payload);
        return JSON.stringify({ type: 'crypto-page-private-key', v: 2, kdf: 'PBKDF2-SHA256', iterations: rounds, alg: 'A256GCM', salt: encode(salt), iv: encode(iv), ct: encode(new Uint8Array(ct)) });
    } finally { raw.fill(0); signingRaw.fill(0); }
}
export async function restorePrivate(text, password) {
    if (text.trim().startsWith('-----BEGIN PRIVATE KEY-----')) return { privateKey: await importPrivate(text), signingPrivateKey: null };
    try {
        if (text.length > 65536) fail();
        const o = parse(text);
        if (o.type !== 'crypto-page-private-key' || ![1, 2].includes(o.v) || o.kdf !== 'PBKDF2-SHA256' || o.iterations !== rounds || o.alg !== 'A256GCM') fail();
        const salt = decode(o.salt), iv = decode(o.iv);
        if (salt.length !== 16 || iv.length !== 12) fail();
        const aes = await passwordKey(password, salt, ['decrypt']);
        const raw = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: o.v === 1 ? backupAADv1 : backupAADv2 }, aes, decode(o.ct)));
        let encryptionRaw = raw;
        let signingRaw = null;
        try {
            if (o.v === 2) {
                const payload = JSON.parse(td.decode(raw));
                encryptionRaw = decode(payload.encryption);
                signingRaw = decode(payload.signing);
            }
            const privateKey = checkRSA(await crypto.subtle.importKey('pkcs8', encryptionRaw, rsa, true, ['decrypt']));
            if (o.v === 1 && Object.hasOwn(o, 'kid') && await fingerprint(await publicFromPrivate(privateKey)) !== o.kid) fail();
            const signingPrivateKey = signingRaw
                ? await crypto.subtle.importKey('pkcs8', signingRaw, ecdsa, true, ['sign'])
                : null;
            if (signingPrivateKey && (signingPrivateKey.algorithm.name !== 'ECDSA' || signingPrivateKey.algorithm.namedCurve !== 'P-256')) fail();
            return { privateKey, signingPrivateKey };
        }
        finally {
            raw.fill(0);
            if (encryptionRaw !== raw) encryptionRaw.fill(0);
            signingRaw?.fill(0);
        }
    } catch { throw new Error('Sauvegarde invalide ou phrase secrète incorrecte.'); }
}
