/*
 * Crypto Page — moteur cryptographique local.
 *
 * Formats pris en charge :
 * - clé publique : PEM SPKI RSA-OAEP
 * - sauvegarde privée : JSON Crypto Page v1, protégée par PBKDF2-SHA-256 + AES-256-GCM
 * - message : JSON Crypto Page v2, RSA-OAEP/SHA-256 + AES-256-GCM
 *
 * Aucune rétrocompatibilité n'est volontairement implémentée.
 * Aucune opération réseau ni persistance navigateur n'est utilisée ici.
 */

export const MAX_TEXT_BYTES = 2 * 1024 * 1024;
export const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;
export const MAX_KEY_FILE_BYTES = 64 * 1024;

export const MESSAGE_TYPE = 'crypto-page-message';
export const MESSAGE_VERSION = 2;
export const MESSAGE_ALGORITHM = 'RSA-OAEP-256+A256GCM';

export const BACKUP_TYPE = 'crypto-page-private-key';
export const BACKUP_VERSION = 1;
export const BACKUP_KDF = 'PBKDF2-SHA256';
export const BACKUP_ALGORITHM = 'A256GCM';
export const BACKUP_ITERATIONS = 600_000;

const MIN_PBKDF2_ITERATIONS = 100_000;
const MAX_PBKDF2_ITERATIONS = 2_000_000;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

const RSA_IMPORT = { name: 'RSA-OAEP', hash: 'SHA-256' };
const RSA_GENERATE = {
    name: 'RSA-OAEP',
    hash: 'SHA-256',
    modulusLength: 3072,
    publicExponent: new Uint8Array([1, 0, 1]),
};

function fail(message = 'Format invalide ou non pris en charge.') {
    throw new Error(message);
}

function assertPlainObject(value, message = 'Objet JSON invalide.') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail(message);
}

function assertExactKeys(object, expected, label) {
    const actual = Object.keys(object).sort();
    const wanted = [...expected].sort();

    if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
        fail(`${label} contient des champs absents, inattendus ou incorrects.`);
    }
}

function assertString(value, field) {
    if (typeof value !== 'string' || value.length === 0) fail(`Champ « ${field} » invalide.`);
}

function parseJson(text, maxLength, label) {
    if (typeof text !== 'string' || text.length === 0 || text.length > maxLength) {
        fail(`${label} absent ou trop volumineux.`);
    }

    try {
        const object = JSON.parse(text);
        assertPlainObject(object, `${label} invalide.`);
        return object;
    } catch (error) {
        if (error instanceof Error && error.message !== 'Objet JSON invalide.') {
            if (error.message.includes('invalide') || error.message.includes('volumineux')) throw error;
        }
        fail(`${label} n’est pas un JSON valide.`);
    }
}

export function encodeBase64Url(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);

    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 32_768) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + 32_768));
    }

    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
}

export function decodeBase64Url(value, field = 'donnée') {
    if (
        typeof value !== 'string' ||
        value.length === 0 ||
        value.length > MAX_MESSAGE_BYTES ||
        !/^[A-Za-z0-9_-]+$/.test(value)
    ) {
        fail(`Encodage Base64URL invalide pour « ${field} ».`);
    }

    try {
        let base64 = value.replace(/-/g, '+').replace(/_/g, '/');
        base64 += '='.repeat((4 - (base64.length % 4)) % 4);
        const binary = atob(base64);
        const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));

        // Refuse les représentations Base64URL non canoniques qui décoderaient
        // vers les mêmes octets à cause des bits de bourrage inutilisés.
        if (encodeBase64Url(bytes) !== value) {
            fail(`Encodage Base64URL non canonique pour « ${field} ».`);
        }

        return bytes;
    } catch (error) {
        if (error instanceof Error && error.message.includes('non canonique')) throw error;
        fail(`Encodage Base64URL invalide pour « ${field} ».`);
    }
}

function decodePemBody(value) {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) fail('Clé publique PEM invalide.');

    try {
        const binary = atob(value);
        return Uint8Array.from(binary, char => char.charCodeAt(0));
    } catch {
        fail('Clé publique PEM invalide.');
    }
}

function pemBytes(text, type) {
    if (typeof text !== 'string' || text.length === 0 || text.length > MAX_KEY_FILE_BYTES) {
        fail('Fichier de clé publique absent ou trop volumineux.');
    }

    const pattern = new RegExp(
        `^-----BEGIN ${type}-----\\s+([A-Za-z0-9+/=\\r\\n]+?)\\s+-----END ${type}-----$`
    );
    const match = text.trim().match(pattern);

    if (!match) fail(`Seule une clé PEM « ${type} » est acceptée.`);
    return decodePemBody(match[1].replace(/\s+/g, ''));
}

function checkRsaKey(key, expectedType) {
    if (!(key instanceof CryptoKey)) fail('Clé cryptographique invalide.');
    if (key.type !== expectedType) fail(`Une clé RSA ${expectedType === 'public' ? 'publique' : 'privée'} est attendue.`);

    const algorithm = key.algorithm;
    if (
        algorithm.name !== 'RSA-OAEP' ||
        algorithm.hash?.name !== 'SHA-256' ||
        algorithm.modulusLength < 2048 ||
        algorithm.modulusLength > 8192
    ) {
        fail('Clé RSA-OAEP/SHA-256 attendue, entre 2048 et 8192 bits.');
    }

    return key;
}

export async function importPublic(pem) {
    try {
        const key = await crypto.subtle.importKey(
            'spki',
            pemBytes(pem, 'PUBLIC KEY'),
            RSA_IMPORT,
            true,
            ['encrypt']
        );
        return checkRsaKey(key, 'public');
    } catch (error) {
        if (error instanceof Error && error.message.includes('Seule une clé PEM')) throw error;
        if (error instanceof Error && error.message.includes('trop volumineux')) throw error;
        throw new Error('Clé publique invalide : un PEM SPKI RSA-OAEP compatible est attendu.');
    }
}

export async function publicFromPrivate(privateKey) {
    checkRsaKey(privateKey, 'private');

    const jwk = await crypto.subtle.exportKey('jwk', privateKey);
    if (!jwk.n || !jwk.e) fail('Impossible de reconstruire la clé publique correspondante.');

    return checkRsaKey(
        await crypto.subtle.importKey(
            'jwk',
            { kty: 'RSA', n: jwk.n, e: jwk.e, ext: true },
            RSA_IMPORT,
            true,
            ['encrypt']
        ),
        'public'
    );
}

export async function generateKeys() {
    return crypto.subtle.generateKey(RSA_GENERATE, true, ['encrypt', 'decrypt']);
}

function toStandardBase64(bytes) {
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 32_768) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + 32_768));
    }
    return btoa(binary);
}

export async function publicPEM(publicKey) {
    checkRsaKey(publicKey, 'public');

    const bytes = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
    const base64 = toStandardBase64(bytes);
    const lines = base64.match(/.{1,64}/g) ?? [];

    return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----\n`;
}

export async function fingerprint(publicKey) {
    checkRsaKey(publicKey, 'public');

    const raw = await crypto.subtle.exportKey('spki', publicKey);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw));
    const hex = Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
    return (hex.match(/.{4}/g) ?? []).join(' ');
}

function messageAad(kid) {
    return encoder.encode(JSON.stringify({
        type: MESSAGE_TYPE,
        v: MESSAGE_VERSION,
        alg: MESSAGE_ALGORITHM,
        kid,
    }));
}

function validateMessageEnvelope(object) {
    assertPlainObject(object, 'Message chiffré invalide.');
    assertExactKeys(object, ['type', 'v', 'alg', 'kid', 'iv', 'ek', 'ct'], 'Le message chiffré');

    if (object.type !== MESSAGE_TYPE) fail('Ce fichier n’est pas un message Crypto Page.');
    if (object.v !== MESSAGE_VERSION) fail(`Version de message non prise en charge : ${String(object.v)}.`);
    if (object.alg !== MESSAGE_ALGORITHM) fail(`Algorithme de message non pris en charge : ${String(object.alg)}.`);

    assertString(object.kid, 'kid');
    assertString(object.iv, 'iv');
    assertString(object.ek, 'ek');
    assertString(object.ct, 'ct');

    if (!/^(?:[0-9a-f]{4} ){15}[0-9a-f]{4}$/.test(object.kid)) {
        fail('Empreinte destinataire « kid » invalide.');
    }

    const iv = decodeBase64Url(object.iv, 'iv');
    const ek = decodeBase64Url(object.ek, 'ek');
    const ct = decodeBase64Url(object.ct, 'ct');

    if (iv.length !== 12) fail('IV AES-GCM invalide.');
    if (ek.length < 256 || ek.length > 1024) fail('Clé de session chiffrée invalide.');
    if (ct.length < 17 || ct.length > MAX_TEXT_BYTES + 16) fail('Corps chiffré absent ou trop volumineux.');

    return { object, iv, ek, ct };
}

export function inspectMessage(text, expectedKid = null) {
    const object = parseJson(text, MAX_MESSAGE_BYTES, 'Message chiffré');
    const { iv, ek, ct } = validateMessageEnvelope(object);

    return {
        type: object.type,
        version: object.v,
        algorithm: object.alg,
        kid: object.kid,
        matchesKey: expectedKid == null ? null : object.kid === expectedKid,
        ivBytes: iv.length,
        wrappedKeyBytes: ek.length,
        ciphertextBytes: ct.length,
    };
}

export async function encrypt(publicKey, message) {
    checkRsaKey(publicKey, 'public');

    if (typeof message !== 'string') throw new Error('Le message doit être du texte.');
    const clear = encoder.encode(message);

    if (clear.length === 0 || clear.length > MAX_TEXT_BYTES) {
        throw new Error('Message attendu : de 1 octet à 2 Mio en UTF-8.');
    }

    const aesKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const kid = await fingerprint(publicKey);

    const ciphertext = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv,
            tagLength: 128,
            additionalData: messageAad(kid),
        },
        aesKey,
        clear
    );

    const rawAesKey = new Uint8Array(await crypto.subtle.exportKey('raw', aesKey));

    try {
        const wrappedKey = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            publicKey,
            rawAesKey
        );

        return JSON.stringify({
            type: MESSAGE_TYPE,
            v: MESSAGE_VERSION,
            alg: MESSAGE_ALGORITHM,
            kid,
            iv: encodeBase64Url(iv),
            ek: encodeBase64Url(new Uint8Array(wrappedKey)),
            ct: encodeBase64Url(new Uint8Array(ciphertext)),
        });
    } finally {
        rawAesKey.fill(0);
    }
}

export async function decrypt(privateKey, text) {
    checkRsaKey(privateKey, 'private');

    const publicKey = await publicFromPrivate(privateKey);
    const localKid = await fingerprint(publicKey);
    const object = parseJson(text, MAX_MESSAGE_BYTES, 'Message chiffré');
    const { iv, ek, ct } = validateMessageEnvelope(object);

    if (object.kid !== localKid) {
        throw new Error(
            `Ce message n’est pas destiné à la clé privée chargée. ` +
            `Empreinte attendue : ${object.kid}. Empreinte chargée : ${localKid}.`
        );
    }

    const expectedWrappedLength = privateKey.algorithm.modulusLength / 8;
    if (ek.length !== expectedWrappedLength) {
        throw new Error('La taille de la clé de session chiffrée ne correspond pas à la clé RSA chargée.');
    }

    let rawAesKey;
    try {
        rawAesKey = new Uint8Array(
            await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, ek)
        );
    } catch {
        throw new Error('Impossible de déchiffrer la clé de session : le message est invalide ou altéré.');
    }

    try {
        if (rawAesKey.length !== 32) {
            throw new Error('La clé de session AES obtenue n’a pas la taille attendue.');
        }

        const aesKey = await crypto.subtle.importKey(
            'raw',
            rawAesKey,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        let clear;
        try {
            clear = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv,
                    tagLength: 128,
                    additionalData: messageAad(object.kid),
                },
                aesKey,
                ct
            );
        } catch {
            throw new Error('Authentification AES-GCM échouée : le message a été altéré ou est invalide.');
        }

        if (clear.byteLength > MAX_TEXT_BYTES) {
            throw new Error('Le message déchiffré dépasse la taille maximale autorisée.');
        }

        try {
            return decoder.decode(clear);
        } catch {
            throw new Error('Le contenu déchiffré n’est pas un texte UTF-8 valide.');
        }
    } finally {
        rawAesKey.fill(0);
    }
}

async function deriveBackupKey(password, salt, iterations, usages) {
    const baseKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            hash: 'SHA-256',
            salt,
            iterations,
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        usages
    );
}

function backupAad({ kid, iterations }) {
    return encoder.encode(JSON.stringify({
        type: BACKUP_TYPE,
        v: BACKUP_VERSION,
        kdf: BACKUP_KDF,
        iterations,
        alg: BACKUP_ALGORITHM,
        kid,
    }));
}

function validateBackupEnvelope(object) {
    assertPlainObject(object, 'Sauvegarde privée invalide.');
    assertExactKeys(
        object,
        ['type', 'v', 'kdf', 'iterations', 'alg', 'kid', 'salt', 'iv', 'ct'],
        'La sauvegarde privée'
    );

    if (object.type !== BACKUP_TYPE) fail('Ce fichier n’est pas une sauvegarde privée Crypto Page.');
    if (object.v !== BACKUP_VERSION) fail(`Version de sauvegarde privée non prise en charge : ${String(object.v)}.`);
    if (object.kdf !== BACKUP_KDF) fail(`KDF non pris en charge : ${String(object.kdf)}.`);
    if (object.alg !== BACKUP_ALGORITHM) fail(`Algorithme de sauvegarde non pris en charge : ${String(object.alg)}.`);

    if (
        !Number.isInteger(object.iterations) ||
        object.iterations < MIN_PBKDF2_ITERATIONS ||
        object.iterations > MAX_PBKDF2_ITERATIONS
    ) {
        fail('Nombre d’itérations PBKDF2 invalide.');
    }

    assertString(object.kid, 'kid');
    assertString(object.salt, 'salt');
    assertString(object.iv, 'iv');
    assertString(object.ct, 'ct');

    if (!/^(?:[0-9a-f]{4} ){15}[0-9a-f]{4}$/.test(object.kid)) {
        fail('Empreinte de sauvegarde « kid » invalide.');
    }

    const salt = decodeBase64Url(object.salt, 'salt');
    const iv = decodeBase64Url(object.iv, 'iv');
    const ct = decodeBase64Url(object.ct, 'ct');

    if (salt.length !== 16) fail('Sel PBKDF2 invalide.');
    if (iv.length !== 12) fail('IV de sauvegarde AES-GCM invalide.');
    if (ct.length < 17 || ct.length > MAX_KEY_FILE_BYTES) fail('Contenu de sauvegarde invalide.');

    return { object, salt, iv, ct };
}

export async function protectPrivate(privateKey, password) {
    checkRsaKey(privateKey, 'private');

    if (typeof password !== 'string' || password.length < 12) {
        throw new Error('Choisissez une phrase secrète d’au moins 12 caractères.');
    }

    const publicKey = await publicFromPrivate(privateKey);
    const kid = await fingerprint(publicKey);
    const iterations = BACKUP_ITERATIONS;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const rawPrivateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));

    try {
        const aesKey = await deriveBackupKey(password, salt, iterations, ['encrypt']);
        const ciphertext = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv,
                tagLength: 128,
                additionalData: backupAad({ kid, iterations }),
            },
            aesKey,
            rawPrivateKey
        );

        return JSON.stringify({
            type: BACKUP_TYPE,
            v: BACKUP_VERSION,
            kdf: BACKUP_KDF,
            iterations,
            alg: BACKUP_ALGORITHM,
            kid,
            salt: encodeBase64Url(salt),
            iv: encodeBase64Url(iv),
            ct: encodeBase64Url(new Uint8Array(ciphertext)),
        });
    } finally {
        rawPrivateKey.fill(0);
    }
}

export async function restorePrivate(text, password) {
    if (typeof password !== 'string' || password.length === 0) {
        throw new Error('Saisissez la phrase secrète de la sauvegarde.');
    }

    const object = parseJson(text, MAX_KEY_FILE_BYTES, 'Sauvegarde privée');
    const { salt, iv, ct } = validateBackupEnvelope(object);

    let rawPrivateKey;
    try {
        const aesKey = await deriveBackupKey(password, salt, object.iterations, ['decrypt']);
        rawPrivateKey = new Uint8Array(
            await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv,
                    tagLength: 128,
                    additionalData: backupAad({ kid: object.kid, iterations: object.iterations }),
                },
                aesKey,
                ct
            )
        );
    } catch {
        throw new Error('Phrase secrète incorrecte ou sauvegarde privée altérée.');
    }

    try {
        let privateKey;
        try {
            privateKey = await crypto.subtle.importKey(
                'pkcs8',
                rawPrivateKey,
                RSA_IMPORT,
                true,
                ['decrypt']
            );
        } catch {
            throw new Error('La sauvegarde ne contient pas une clé privée RSA-OAEP valide.');
        }

        checkRsaKey(privateKey, 'private');

        const publicKey = await publicFromPrivate(privateKey);
        const restoredKid = await fingerprint(publicKey);
        if (restoredKid !== object.kid) {
            throw new Error('L’empreinte de la clé restaurée ne correspond pas à la sauvegarde.');
        }

        return privateKey;
    } finally {
        rawPrivateKey.fill(0);
    }
}

export async function selfTest() {
    const pair = await crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            hash: 'SHA-256',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
        },
        true,
        ['encrypt', 'decrypt']
    );

    const probe = 'crypto-page-self-test';
    const envelope = await encrypt(pair.publicKey, probe);
    const clear = await decrypt(pair.privateKey, envelope);

    if (clear !== probe) throw new Error('Échec de l’autotest cryptographique.');
    return true;
}
