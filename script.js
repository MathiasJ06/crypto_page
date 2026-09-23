import * as engine from './crypto-engine.js?v=20260923-4';

const $ = id => document.getElementById(id);

let identity = null;
let pendingIdentityFile = null;
let generatedIdentity = null;
let recipient = null;
let decryptReady = false;
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

function safeId(fingerprint) {
    return fingerprint.replace(/\s+/g, '').slice(0, 16);
}

function sync() {
    const encryptInput = $('encrypt-input').value;
    const backupPassword = $('backup-password').value;
    const backupConfirm = $('backup-confirm').value;

    $('load-identity').disabled = !pendingIdentityFile || $('restore-password').value.length === 0;
    $('identity-export-public').disabled = !identity;
    $('lock-identity').disabled = !identity;

    $('generated-export-public').disabled = !generatedIdentity;
    $('generated-export-private').disabled = !generatedIdentity || backupPassword.length < 12 || backupPassword !== backupConfirm;
    $('activate-generated').disabled = !generatedIdentity?.saved;

    $('encrypt').disabled = !recipient || utf8Size(encryptInput) === 0 || utf8Size(encryptInput) > engine.MAX_TEXT_BYTES;
    $('decrypt').disabled = !identity || !decryptReady;
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

function showMainPanel(name) {
    for (const button of document.querySelectorAll('[data-panel]')) {
        const active = button.dataset.panel === name;
        button.setAttribute('aria-pressed', String(active));
        $(`${button.dataset.panel}-panel`).hidden = !active;
    }
}

function showKeyPanel(name) {
    for (const button of document.querySelectorAll('[data-key-panel]')) {
        const active = button.dataset.keyPanel === name;
        button.setAttribute('aria-selected', String(active));
        $(`${button.dataset.keyPanel}-subpanel`).hidden = !active;
    }
}

function renderIdentity() {
    const box = $('identity-status');

    box.classList.toggle('active', Boolean(identity));
    box.classList.toggle('inactive', !identity);

    if (!identity) {
        $('identity-status-title').textContent = 'Aucune identité chargée';
        $('identity-status-source').textContent = 'Chargez votre sauvegarde privée pour pouvoir déchiffrer.';
        $('identity-fingerprint').textContent = '';
        return;
    }

    $('identity-status-title').textContent = `Identité active · RSA ${identity.publicKey.algorithm.modulusLength} bits`;
    $('identity-status-source').textContent = identity.sourceName
        ? `Origine : ${identity.sourceName}`
        : 'Origine : identité chargée dans cet onglet';
    $('identity-fingerprint').textContent = identity.fingerprint;
}

function renderGeneratedIdentity() {
    const box = $('generated-status');
    box.classList.remove('active', 'inactive', 'saved', 'unsaved');

    if (!generatedIdentity) {
        box.classList.add('inactive');
        $('generated-status-title').textContent = 'Aucune nouvelle identité générée';
        $('generated-status-detail').textContent = '';
        $('generated-fingerprint').textContent = '';
        setFileReadStatus('generated-backup', {
            title: 'Aucune sauvegarde privée téléchargée',
        });
        return;
    }

    box.classList.add(generatedIdentity.saved ? 'saved' : 'unsaved');
    $('generated-status-title').textContent = generatedIdentity.saved
        ? `Identité générée et sauvegardée · RSA ${generatedIdentity.publicKey.algorithm.modulusLength} bits`
        : `Identité générée · NON SAUVEGARDÉE · RSA ${generatedIdentity.publicKey.algorithm.modulusLength} bits`;
    $('generated-status-detail').textContent = generatedIdentity.saved
        ? 'La sauvegarde privée a été téléchargée. Cette identité peut maintenant être activée.'
        : 'Téléchargez la sauvegarde privée avant de fermer l’onglet ou de remplacer cette identité.';
    $('generated-fingerprint').textContent = generatedIdentity.fingerprint;

    if (generatedIdentity.saved) {
        setFileReadStatus('generated-backup', {
            title: 'Sauvegarde privée téléchargée',
            name: generatedIdentity.backupName,
            detail: 'Conservez ce fichier et sa phrase secrète séparément.',
            kind: 'ok',
        });
    } else {
        setFileReadStatus('generated-backup', {
            title: 'Sauvegarde privée non encore téléchargée',
            detail: 'Cette nouvelle identité serait perdue si vous fermiez maintenant l’onglet.',
            kind: 'loading',
        });
    }
}

async function setActiveIdentity(pair, generation, sourceName) {
    const fingerprint = await engine.fingerprint(pair.publicKey);
    stillCurrent(generation);

    identity = {
        privateKey: pair.privateKey,
        publicKey: pair.publicKey,
        fingerprint,
        sourceName,
    };

    $('decrypt-output').value = '';
    renderIdentity();
    refreshDecryptInfo();
}

function refreshDecryptInfo() {
    const text = $('decrypt-input').value.trim();
    decryptReady = false;

    if (!text) {
        setDecryptInfo('');
        sync();
        return;
    }

    try {
        const info = engine.inspectMessage(text, identity?.fingerprint ?? null);
        let keyState = 'identité privée non chargée';
        let kind = 'neutral';

        if (info.matchesKey === true) {
            keyState = 'destinataire correspondant à l’identité active';
            kind = 'ok';
            decryptReady = true;
        } else if (info.matchesKey === false) {
            keyState = 'ATTENTION : ce message vise une autre identité';
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

function lockIdentity() {
    epoch += 1;
    busy = false;
    identity = null;
    pendingIdentityFile = null;
    decryptReady = false;

    $('private-file').value = '';
    $('restore-password').value = '';
    $('decrypt-output').value = '';

    setFileReadStatus('private', {
        title: 'Aucune sauvegarde sélectionnée',
    });
    renderIdentity();
    refreshDecryptInfo();

    $('app').disabled = !globalThis.crypto?.subtle;
    sync();
    setStatus('Identité verrouillée : la référence à la clé privée a été libérée de l’interface.');
}

function clearSensitiveReferences() {
    epoch += 1;
    busy = false;
    identity = null;
    pendingIdentityFile = null;
    generatedIdentity = null;
    recipient = null;
    decryptReady = false;

    for (const id of ['restore-password', 'backup-password', 'backup-confirm', 'decrypt-output']) {
        const node = $(id);
        if (node) node.value = '';
    }
}

for (const button of document.querySelectorAll('[data-panel]')) {
    button.addEventListener('click', () => showMainPanel(button.dataset.panel));
}

for (const button of document.querySelectorAll('[data-key-panel]')) {
    button.addEventListener('click', () => showKeyPanel(button.dataset.keyPanel));
}

$('private-file').addEventListener('change', event => {
    const file = event.target.files?.[0] ?? null;
    pendingIdentityFile = file;

    if (!file) {
        setFileReadStatus('private', { title: 'Aucune sauvegarde sélectionnée' });
        sync();
        return;
    }

    setFileReadStatus('private', {
        title: 'Sauvegarde sélectionnée · pas encore ouverte',
        name: file.name,
        detail: `${file.size.toLocaleString('fr-FR')} octets · saisissez la phrase secrète puis cliquez sur « Charger mon identité »`,
        kind: 'neutral',
    });
    sync();
});

$('restore-password').addEventListener('input', sync);

$('load-identity').addEventListener('click', () => {
    if (!pendingIdentityFile) return;

    const file = pendingIdentityFile;

    setFileReadStatus('private', {
        title: 'Lecture de la sauvegarde privée…',
        name: file.name,
        detail: `${file.size.toLocaleString('fr-FR')} octets`,
        kind: 'loading',
    });

    run(async generation => {
        let password = $('restore-password').value;

        try {
            const text = await fileText(file, engine.MAX_KEY_FILE_BYTES, 'Sauvegarde privée');
            const privateKey = await engine.restorePrivate(text, password);
            const publicKey = await engine.publicFromPrivate(privateKey);

            await setActiveIdentity({ privateKey, publicKey }, generation, file.name);
            stillCurrent(generation);

            setFileReadStatus('private', {
                title: 'Clé privée lue correctement',
                name: file.name,
                detail: `RSA ${privateKey.algorithm.modulusLength} bits · empreinte publique ${identity.fingerprint}`,
                kind: 'ok',
            });

            pendingIdentityFile = null;
            $('private-file').value = '';
            $('restore-password').value = '';

            setStatus('Identité chargée. La clé privée est maintenant disponible uniquement en mémoire dans cet onglet.');
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

$('identity-export-public').addEventListener('click', () => {
    run(async generation => {
        const text = await engine.publicPEM(identity.publicKey);
        stillCurrent(generation);

        download(
            text,
            `cle-publique-${safeId(identity.fingerprint)}.pem`,
            'application/x-pem-file'
        );
        setStatus('Clé publique de l’identité active exportée. Elle peut être partagée avec vos correspondants.');
    });
});

$('lock-identity').addEventListener('click', lockIdentity);

$('generate').addEventListener('click', () => {
    if (
        generatedIdentity &&
        !generatedIdentity.saved &&
        !confirm('La nouvelle identité actuellement générée n’a pas été sauvegardée. La remplacer quand même ?')
    ) {
        return;
    }

    run(async generation => {
        const pair = await engine.generateKeys();
        const fingerprint = await engine.fingerprint(pair.publicKey);
        stillCurrent(generation);

        generatedIdentity = {
            ...pair,
            fingerprint,
            saved: false,
            backupName: null,
        };

        $('backup-password').value = '';
        $('backup-confirm').value = '';
        renderGeneratedIdentity();
        setStatus('Nouvelle identité générée. Téléchargez sa sauvegarde privée avant de fermer cet onglet.', 'warning');
    });
});

$('generated-export-public').addEventListener('click', () => {
    run(async generation => {
        const text = await engine.publicPEM(generatedIdentity.publicKey);
        stillCurrent(generation);

        download(
            text,
            `cle-publique-${safeId(generatedIdentity.fingerprint)}.pem`,
            'application/x-pem-file'
        );

        setStatus(
            generatedIdentity.saved
                ? 'Clé publique exportée.'
                : 'Clé publique exportée. Pensez à sauvegarder la clé privée avant d’utiliser ou de diffuser durablement cette identité.',
            generatedIdentity.saved ? 'ok' : 'warning'
        );
    });
});

function syncBackupInputs() {
    sync();
}

$('backup-password').addEventListener('input', syncBackupInputs);
$('backup-confirm').addEventListener('input', syncBackupInputs);

$('generated-export-private').addEventListener('click', () => {
    run(async generation => {
        let password = $('backup-password').value;

        try {
            if (!generatedIdentity) throw new Error('Générez d’abord une nouvelle identité.');
            if (password !== $('backup-confirm').value) {
                throw new Error('Les deux phrases secrètes ne correspondent pas.');
            }

            const text = await engine.protectPrivate(generatedIdentity.privateKey, password);
            stillCurrent(generation);

            const backupName = `cle-privee-${safeId(generatedIdentity.fingerprint)}.json`;
            download(text, backupName, 'application/json');

            generatedIdentity.saved = true;
            generatedIdentity.backupName = backupName;
            renderGeneratedIdentity();
            setStatus('Sauvegarde privée chiffrée téléchargée. Conservez séparément le fichier et sa phrase secrète.');
        } finally {
            password = '';
            $('backup-password').value = '';
            $('backup-confirm').value = '';
        }
    });
});

$('activate-generated').addEventListener('click', () => {
    if (!generatedIdentity?.saved) return;

    run(async generation => {
        const pair = {
            privateKey: generatedIdentity.privateKey,
            publicKey: generatedIdentity.publicKey,
        };
        const sourceName = generatedIdentity.backupName;

        await setActiveIdentity(pair, generation, sourceName);
        stillCurrent(generation);

        // La même clé privée ne reste pas référencée dans deux états différents.
        generatedIdentity = null;
        renderGeneratedIdentity();
        showKeyPanel('identity');
        setStatus('Nouvelle identité activée. Sa clé privée est disponible uniquement en mémoire dans cet onglet.');
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

        if (info.matchesKey !== true) {
            throw new Error('Ce message n’est pas destiné à l’identité actuellement chargée.');
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
    decryptReady = false;

    setFileReadStatus('message', {
        title: 'Lecture du message chiffré…',
        name: file.name,
        detail: `${file.size.toLocaleString('fr-FR')} octets`,
        kind: 'loading',
    });

    run(async generation => {
        try {
            const text = await fileText(file, engine.MAX_MESSAGE_BYTES, 'Message chiffré');
            const info = engine.inspectMessage(text, identity?.fingerprint ?? null);
            stillCurrent(generation);

            $('decrypt-input').value = text;

            setFileReadStatus('message', {
                title: 'Message chiffré lu correctement',
                name: file.name,
                detail: `Crypto Page v${info.version} · ${info.ciphertextBytes} octets chiffrés · destinataire ${info.kid}`,
                kind: 'ok',
            });

            refreshDecryptInfo();
            setStatus('Message chiffré importé localement.');
        } catch (error) {
            if (generation === epoch) {
                setFileReadStatus('message', {
                    title: 'Échec de lecture du message chiffré',
                    name: file.name,
                    detail: error?.message || 'Message chiffré invalide.',
                    kind: 'error',
                });
            }
            throw error;
        }
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

$('encrypt-input').addEventListener('input', () => {
    $('encrypt-output').value = '';
    const size = utf8Size($('encrypt-input').value);
    $('encrypt-size').textContent = `${size.toLocaleString('fr-FR')} / ${engine.MAX_TEXT_BYTES.toLocaleString('fr-FR')} octets`;
    sync();
});

$('decrypt-input').addEventListener('input', () => {
    $('decrypt-output').value = '';
    setFileReadStatus('message', {
        title: $('decrypt-input').value.trim() ? 'Message saisi ou collé manuellement' : 'Aucun fichier de message lu',
    });
    refreshDecryptInfo();
});

window.addEventListener('beforeunload', event => {
    if (generatedIdentity && !generatedIdentity.saved) {
        event.preventDefault();
        event.returnValue = '';
    }
});

window.addEventListener('pagehide', clearSensitiveReferences);
window.addEventListener('pageshow', event => {
    if (event.persisted) {
        clearSensitiveReferences();
        renderIdentity();
        renderGeneratedIdentity();
        recipient = null;
        $('recipient-state').textContent = 'Aucun destinataire chargé';
        $('recipient-fingerprint').textContent = '';
        setFileReadStatus('recipient', { title: 'Aucune clé publique lue' });
        refreshDecryptInfo();
    }
});

async function init() {
    renderIdentity();
    renderGeneratedIdentity();

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
