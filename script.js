import * as engine from './crypto-engine.js?v=20260923-3';

const $ = id => document.getElementById(id);

let identity = null;
let recipient = null;
let identitySaved = true;
let busy = false;
let epoch = 0;

function setStatus(message, kind = 'ok') {
    const node = $('status');
    node.textContent = message;
    node.classList.toggle('error', kind === 'error');
    node.classList.toggle('warning', kind === 'warning');
}

function setDecryptInfo(message = '', kind = 'neutral') {
    const node = $('decrypt-info');
    node.textContent = message;
    node.classList.toggle('error', kind === 'error');
    node.classList.toggle('warning', kind === 'warning');
    node.classList.toggle('ok', kind === 'ok');
}


function setFileReadStatus(prefix, { title, name = '', detail = '', kind = 'neutral' }) {
    const box = $(`${prefix}-read-status`);
    $(`${prefix}-read-title`).textContent = title;
    $(`${prefix}-read-name`).textContent = name ? `Fichier : ${name}` : '';
    $(`${prefix}-read-detail`).textContent = detail;

    box.classList.toggle('ok', kind === 'ok');
    box.classList.toggle('error', kind === 'error');
    box.classList.toggle('loading', kind === 'loading');
    box.classList.toggle('neutral', kind === 'neutral');
}

function utf8Size(text) {
    return new TextEncoder().encode(text).length;
}

function sync() {
    const encryptInput = $('encrypt-input').value;
    const decryptInput = $('decrypt-input').value.trim();

    $('export-public').disabled = !identity;
    $('export-private').disabled = !identity;
    $('encrypt').disabled = !recipient || utf8Size(encryptInput) === 0 || utf8Size(encryptInput) > engine.MAX_TEXT_BYTES;
    $('decrypt').disabled = !identity || decryptInput.length === 0;
    $('copy-encrypted').disabled = !$('encrypt-output').value;
    $('save-encrypted').disabled = !$('encrypt-output').value;
}

async function run(action) {
    if (busy) return;

    busy = true;
    const generation = epoch;
    $('app').disabled = true;
    setStatus('Traitement cryptographique local en cours…');

    try {
        await action(generation);
    } catch (error) {
        if (generation === epoch) {
            setStatus(error?.message || 'Opération impossible.', 'error');
        }
    } finally {
        if (generation === epoch) {
            busy = false;
            $('app').disabled = false;
            sync();
        }
    }
}

function stillCurrent(generation) {
    if (epoch !== generation) throw new Error('Opération annulée.');
}

function replaceAllowed() {
    return (
        !identity ||
        identitySaved ||
        confirm(
            'La clé privée actuelle n’a pas été sauvegardée. ' +
            'La remplacer rendra ses messages illisibles si vous n’en avez aucune copie. Continuer ?'
        )
    );
}

async function setIdentity(pair, generation, isSaved) {
    const fingerprint = await engine.fingerprint(pair.publicKey);
    stillCurrent(generation);

    identity = { ...pair, fingerprint };
    identitySaved = isSaved;

    $('my-state').textContent = `Clés chargées · RSA ${pair.publicKey.algorithm.modulusLength} bits`;
    $('my-fingerprint').textContent = fingerprint;
    $('decrypt-output').value = '';

    refreshDecryptInfo();
}

function safeId(fingerprint) {
    return fingerprint.replace(/\s+/g, '').slice(0, 16);
}

function download(text, name, mime = 'application/octet-stream') {
    const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
    const anchor = document.createElement('a');

    anchor.href = url;
    anchor.download = name;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function fileText(file, maxBytes, label) {
    if (!file) throw new Error(`${label} absent.`);
    if (file.size === 0) throw new Error(`${label} vide.`);
    if (file.size > maxBytes) throw new Error(`${label} trop volumineux.`);
    return file.text();
}

function refreshDecryptInfo() {
    const text = $('decrypt-input').value.trim();

    if (!text) {
        setDecryptInfo('');
        sync();
        return;
    }

    try {
        const info = engine.inspectMessage(text, identity?.fingerprint ?? null);
        let keyState = 'clé privée non chargée';
        let kind = 'neutral';

        if (info.matchesKey === true) {
            keyState = 'destinataire correspondant à la clé chargée';
            kind = 'ok';
        } else if (info.matchesKey === false) {
            keyState = 'ATTENTION : ce message vise une autre clé';
            kind = 'warning';
        }

        setDecryptInfo(
            `Crypto Page v${info.version} · ${info.algorithm} · ${keyState} · ` +
            `${info.ciphertextBytes} octets chiffrés`,
            kind
        );
    } catch (error) {
        setDecryptInfo(error?.message || 'Message chiffré invalide.', 'error');
    }

    sync();
}

function clearAll() {
    epoch += 1;
    busy = false;
    identity = null;
    recipient = null;
    identitySaved = true;

    for (const element of document.querySelectorAll('textarea, input')) {
        element.value = '';
    }

    $('my-state').textContent = 'Aucune clé chargée';
    $('recipient-state').textContent = 'Aucun destinataire chargé';
    $('my-fingerprint').textContent = '';
    $('recipient-fingerprint').textContent = '';
    setFileReadStatus('private', { title: 'Aucune sauvegarde privée lue' });
    setFileReadStatus('recipient', { title: 'Aucune clé publique lue' });
    setDecryptInfo('');

    $('app').disabled = !globalThis.crypto?.subtle;
    sync();
    setStatus('Onglet verrouillé : références aux clés libérées et textes effacés de l’interface.');
}

for (const button of document.querySelectorAll('[data-panel]')) {
    button.addEventListener('click', () => {
        for (const other of document.querySelectorAll('[data-panel]')) {
            const active = other === button;
            other.setAttribute('aria-pressed', String(active));
            $(`${other.dataset.panel}-panel`).hidden = !active;
        }
    });
}

$('generate').addEventListener('click', () => {
    if (!replaceAllowed()) return;

    run(async generation => {
        const pair = await engine.generateKeys();
        await setIdentity(pair, generation, false);
        setStatus('Nouvelle identité créée. Sauvegardez la clé privée chiffrée avant de fermer cet onglet.');
    });
});

$('export-public').addEventListener('click', () => {
    run(async generation => {
        const text = await engine.publicPEM(identity.publicKey);
        stillCurrent(generation);

        download(
            text,
            `cle-publique-${safeId(identity.fingerprint)}.pem`,
            'application/x-pem-file'
        );
        setStatus('Clé publique exportée. Elle peut être partagée avec vos correspondants.');
    });
});

$('export-private').addEventListener('click', () => {
    run(async generation => {
        let password = $('backup-password').value;

        try {
            if (password !== $('backup-confirm').value) {
                throw new Error('Les deux phrases secrètes ne correspondent pas.');
            }

            const text = await engine.protectPrivate(identity.privateKey, password);
            stillCurrent(generation);

            download(
                text,
                `cle-privee-${safeId(identity.fingerprint)}.json`,
                'application/json'
            );

            identitySaved = true;
            setStatus('Sauvegarde privée chiffrée exportée. Conservez séparément le fichier et sa phrase secrète.');
        } finally {
            password = '';
            $('backup-password').value = '';
            $('backup-confirm').value = '';
        }
    });
});

$('private-file').addEventListener('change', event => {
    const file = event.target.files?.[0];
    event.target.value = '';

    if (!file || !replaceAllowed()) return;

    setFileReadStatus('private', {
        title: 'Lecture de la sauvegarde privée…',
        name: file.name,
        detail: `${file.size.toLocaleString('fr-FR')} octets`,
        kind: 'loading',
    });

    run(async generation => {
        let password = $('restore-password').value;
        $('restore-password').value = '';

        try {
            const text = await fileText(
                file,
                engine.MAX_KEY_FILE_BYTES,
                'Sauvegarde privée'
            );
            const privateKey = await engine.restorePrivate(text, password);
            const publicKey = await engine.publicFromPrivate(privateKey);

            await setIdentity({ privateKey, publicKey }, generation, true);
            stillCurrent(generation);

            setFileReadStatus('private', {
                title: 'Clé privée lue correctement',
                name: file.name,
                detail: `RSA ${privateKey.algorithm.modulusLength} bits · empreinte publique ${identity.fingerprint}`,
                kind: 'ok',
            });
            setStatus('Sauvegarde privée restaurée. La clé publique correspondante a été reconstruite localement.');
        } catch (error) {
            if (generation === epoch) {
                setFileReadStatus('private', {
                    title: 'Échec de lecture de la clé privée',
                    name: file.name,
                    detail: error?.message || 'Sauvegarde privée invalide.',
                    kind: 'error',
                });
            }
            throw error;
        } finally {
            password = '';
        }
    });
});

$('recipient-file').addEventListener('change', event => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;

    recipient = null;
    $('recipient-state').textContent = 'Aucun destinataire chargé';
    $('recipient-fingerprint').textContent = '';
    $('encrypt-output').value = '';
    setFileReadStatus('recipient', {
        title: 'Lecture de la clé publique…',
        name: file.name,
        detail: `${file.size.toLocaleString('fr-FR')} octets`,
        kind: 'loading',
    });
    sync();

    run(async generation => {
        try {
            const pem = await fileText(file, engine.MAX_KEY_FILE_BYTES, 'Clé publique');
            const publicKey = await engine.importPublic(pem);
            const fingerprint = await engine.fingerprint(publicKey);
            stillCurrent(generation);

            recipient = { publicKey, fingerprint, fileName: file.name };
            $('recipient-state').textContent = `Destinataire chargé · RSA ${publicKey.algorithm.modulusLength} bits`;
            $('recipient-fingerprint').textContent = fingerprint;
            setFileReadStatus('recipient', {
                title: 'Clé publique lue correctement',
                name: file.name,
                detail: `RSA ${publicKey.algorithm.modulusLength} bits · empreinte ${fingerprint}`,
                kind: 'ok',
            });
            setStatus('Clé publique du destinataire chargée. Vérifiez son empreinte par un canal indépendant.');
        } catch (error) {
            if (generation === epoch) {
                setFileReadStatus('recipient', {
                    title: 'Échec de lecture de la clé publique',
                    name: file.name,
                    detail: error?.message || 'Clé publique invalide.',
                    kind: 'error',
                });
            }
            throw error;
        }
    });
});

$('encrypt').addEventListener('click', () => {
    run(async generation => {
        $('encrypt-output').value = '';

        const encrypted = await engine.encrypt(
            recipient.publicKey,
            $('encrypt-input').value
        );
        stillCurrent(generation);

        $('encrypt-output').value = encrypted;
        sync();
        setStatus('Message chiffré localement et authentifié par AES-GCM.');
    });
});

$('decrypt').addEventListener('click', () => {
    run(async generation => {
        $('decrypt-output').value = '';

        const info = engine.inspectMessage(
            $('decrypt-input').value,
            identity.fingerprint
        );

        if (info.matchesKey === false) {
            throw new Error(
                `Ce message est destiné à une autre clé. ` +
                `Empreinte du message : ${info.kid}. Empreinte chargée : ${identity.fingerprint}.`
            );
        }

        const plaintext = await engine.decrypt(
            identity.privateKey,
            $('decrypt-input').value
        );
        stillCurrent(generation);

        $('decrypt-output').value = plaintext;
        setStatus('Message déchiffré et intégrité AES-GCM vérifiée localement.');
    });
});

$('message-file').addEventListener('change', event => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;

    $('decrypt-input').value = '';
    $('decrypt-output').value = '';
    setDecryptInfo('');

    run(async generation => {
        const text = await fileText(
            file,
            engine.MAX_MESSAGE_BYTES,
            'Message chiffré'
        );
        stillCurrent(generation);

        $('decrypt-input').value = text;
        refreshDecryptInfo();
        setStatus('Message chiffré importé localement.');
    });
});

$('copy-encrypted').addEventListener('click', () => {
    run(async () => {
        if (!navigator.clipboard?.writeText) {
            throw new Error('Copie automatique indisponible : sélectionnez le texte chiffré et copiez-le manuellement.');
        }

        await navigator.clipboard.writeText($('encrypt-output').value);
        setStatus('Message chiffré copié dans le presse-papiers.');
    });
});

$('save-encrypted').addEventListener('click', () => {
    download(
        $('encrypt-output').value,
        'message-chiffre.crypto',
        'application/json'
    );
    setStatus('Message chiffré exporté.');
});

$('clear').addEventListener('click', () => {
    if (
        identitySaved ||
        confirm('Votre clé privée actuelle n’a pas été sauvegardée. Effacer quand même ?')
    ) {
        clearAll();
    }
});

$('encrypt-input').addEventListener('input', () => {
    $('encrypt-output').value = '';
    const size = utf8Size($('encrypt-input').value);
    $('encrypt-size').textContent = `${size.toLocaleString('fr-FR')} / ${engine.MAX_TEXT_BYTES.toLocaleString('fr-FR')} octets`;
    sync();
});

$('decrypt-input').addEventListener('input', () => {
    $('decrypt-output').value = '';
    refreshDecryptInfo();
});

window.addEventListener('beforeunload', event => {
    if (identity && !identitySaved) {
        event.preventDefault();
        event.returnValue = '';
    }
});

window.addEventListener('pagehide', clearAll);
window.addEventListener('pageshow', event => {
    if (event.persisted) clearAll();
});

async function init() {
    if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
        setStatus(
            'Web Crypto est indisponible. Ouvrez cette page en HTTPS ou depuis localhost avec un navigateur récent.',
            'error'
        );
        return;
    }

    setStatus('Autotest cryptographique local…');

    try {
        await engine.selfTest();
        $('app').disabled = false;
        sync();
        setStatus('Prêt · RSA-OAEP/SHA-256 et AES-256-GCM opérationnels · aucune donnée envoyée.');
    } catch {
        $('app').disabled = true;
        setStatus('Autotest cryptographique échoué. Ce navigateur ne peut pas être utilisé avec cette page.', 'error');
    }
}

// Aucun fetch, XHR, WebSocket, sendBeacon, cookie, localStorage,
// sessionStorage ou IndexedDB n’est utilisé volontairement.
init();
