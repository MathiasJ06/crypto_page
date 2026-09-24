import * as engine from './crypto-engine.js?v=20260924-pass-required';
const $ = id => document.getElementById(id);
let identity = null, recipient = null, trustedSenderSigningKey = null, saved = true, busy = false, epoch = 0;
function status(message, error = false) { $('status').textContent = message; $('status').classList.toggle('error', error); }
function sync() {
    $('import-private').disabled = !$('private-file').files.length || !$('restore-password').value.length;
    $('export-public').disabled = !identity;
    $('export-private').disabled = !identity;
    const encryptBytes = new TextEncoder().encode($('encrypt-input').value).length;
    $('encrypt').disabled = !recipient || encryptBytes === 0 || encryptBytes > engine.MAX_TEXT_BYTES;
    $('decrypt').disabled = !identity || !$('decrypt-input').value.trim();
    $('copy-encrypted').disabled = !$('encrypt-output').value;
    $('save-encrypted').disabled = !$('encrypt-output').value;
    $('decrypt-key-state').textContent = identity ? 'Votre clé privée est chargée. Vous pouvez déchiffrer un message destiné à cette clé.' : 'Aucune clé privée chargée. Importez-la dans « Mes clés ».';
}
async function run(action) {
    if (busy) return;
    busy = true; const generation = epoch;
    $('app').disabled = true;
    status('Traitement local en cours…');
    try { await action(generation); }
    catch (error) { if (generation === epoch) status(error.message || 'Opération impossible.', true); }
    finally { if (generation === epoch) { busy = false; $('app').disabled = false; sync(); } }
}
function stillCurrent(generation) { if (epoch !== generation) throw new Error('Opération annulée.'); }
function replaceAllowed() { return !identity || saved || confirm('La clé actuelle n’a pas été sauvegardée. La remplacer rendra ses messages illisibles si vous n’en avez aucune copie. Continuer ?'); }
async function setIdentity(pair, generation, isSaved) {
    const [fp, signingFp] = await Promise.all([
        engine.fingerprint(pair.publicKey), engine.fingerprint(pair.signingPublicKey),
    ]);
    stillCurrent(generation);
    identity = pair; saved = isSaved;
    $('my-state').textContent = `Clés chargées · RSA ${pair.publicKey.algorithm.modulusLength} bits`;
    $('my-fingerprint').textContent = fp;
    $('my-signing-fingerprint').textContent = `Signature · ${signingFp}`;
    $('decrypt-output').value = '';
    $('sender-verification').textContent = 'Signature de l’expéditeur non vérifiée.';
}
function download(text, name) {
    const url = URL.createObjectURL(new Blob([text], { type: 'application/octet-stream' }));
    const a = document.createElement('a'); a.href = url; a.download = name;
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function keyFilenameSuffix() {
    const value = $('key-filename-suffix').value.normalize('NFC').trim();
    const safe = value
        .replace(/[^\p{L}\p{N}._-]+/gu, '-')
        .replace(/-{2,}/g, '-')
        .replace(/^[-._]+|[-._]+$/g, '')
        .slice(0, 48)
        .replace(/[-._]+$/g, '');
    return safe ? `-${safe}` : '';
}
async function fileText(file, max) {
    if (!file || file.size === 0 || file.size > max) throw new Error('Fichier absent, vide ou trop volumineux.');
    return file.text();
}
function clear() {
    epoch++; busy = false; identity = null; recipient = null; trustedSenderSigningKey = null; saved = true;
    for (const el of document.querySelectorAll('textarea, input')) el.value = '';
    $('my-state').textContent = 'Aucune clé chargée'; $('recipient-state').textContent = 'Aucun destinataire chargé';
    $('my-fingerprint').textContent = ''; $('my-signing-fingerprint').textContent = ''; $('recipient-fingerprint').textContent = '';
    $('restore-feedback').textContent = 'Aucun fichier sélectionné.';
    $('sender-identity-state').textContent = 'Aucune identité d’expéditeur chargée.';
    $('sender-verification').textContent = 'Signature de l’expéditeur non vérifiée.';
    $('app').disabled = !globalThis.crypto?.subtle; sync();
    status('Onglet verrouillé : clés libérées et textes effacés de l’interface.');
}
for (const button of document.querySelectorAll('[data-panel]')) button.addEventListener('click', () => {
    for (const b of document.querySelectorAll('[data-panel]')) {
        const active = b === button; b.setAttribute('aria-pressed', String(active)); $(b.dataset.panel + '-panel').hidden = !active;
    }
});
const keyTabs = [...document.querySelectorAll('[data-key-tab]')];
function activateKeyTab(button) {
    for (const tab of keyTabs) {
        const active = tab === button;
        tab.setAttribute('aria-selected', String(active));
        $(tab.getAttribute('aria-controls')).hidden = !active;
    }
}
for (const button of keyTabs) {
    button.addEventListener('click', () => activateKeyTab(button));
    button.addEventListener('keydown', event => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        const current = keyTabs.indexOf(button);
        const next = event.key === 'Home' ? 0
            : event.key === 'End' ? keyTabs.length - 1
            : (current + (event.key === 'ArrowRight' ? 1 : keyTabs.length - 1)) % keyTabs.length;
        keyTabs[next].focus();
        activateKeyTab(keyTabs[next]);
    });
}
$('generate').addEventListener('click', () => {
    if (!replaceAllowed()) return;
    run(async generation => { const pair = await engine.generateKeys(); await setIdentity(pair, generation, false); status('Clés créées. Téléchargez votre sauvegarde privée chiffrée avant de fermer cet onglet.'); });
});
$('export-public').addEventListener('click', () => run(async generation => {
    const text = await engine.publicIdentity(identity); stillCurrent(generation);
    download(text, `mon-identite-publique${keyFilenameSuffix()}.json`); status('Identité publique prête à partager.');
}));
$('export-private').addEventListener('click', () => run(async generation => {
    let password = $('backup-password').value;
    try {
        if (password !== $('backup-confirm').value) throw new Error('Les deux phrases secrètes ne correspondent pas.');
        const text = await engine.protectPrivate(identity, password); stillCurrent(generation);
        download(text, `ma-cle-privee-protegee${keyFilenameSuffix()}.json`); saved = true;
        status('Téléchargement demandé. Vérifiez que la sauvegarde est bien présente avant de fermer l’onglet.');
    } finally { password = ''; $('backup-password').value = ''; $('backup-confirm').value = ''; }
}));
$('private-file').addEventListener('change', () => {
    $('restore-feedback').textContent = $('private-file').files.length
        ? 'Fichier sélectionné. Saisissez sa phrase secrète si nécessaire, puis cliquez sur « Importer ma clé privée ».'
        : 'Aucun fichier sélectionné.';
    sync();
});
$('import-private').addEventListener('click', () => {
    const file = $('private-file').files[0];
    if (busy || !file || !replaceAllowed()) return;
    run(async generation => {
        let password = $('restore-password').value; $('restore-password').value = '';
        $('restore-feedback').textContent = 'Importation locale en cours…';
        $('decrypt-output').value = '';
        try {
            const text = await fileText(file, 65536);
            const trimmed = text.trim();
            if (!password.length) throw new Error('La phrase secrète de la sauvegarde est obligatoire.');
            if (trimmed.startsWith('-----BEGIN PUBLIC KEY-----')) throw new Error('Ce fichier contient une clé publique. Choisissez votre sauvegarde privée chiffrée pour déchiffrer.');
            if (trimmed.startsWith('-----BEGIN')) throw new Error('Les clés privées PEM ne sont pas acceptées. Importez la sauvegarde JSON chiffrée créée par cette application.');
            if (!trimmed.startsWith('{')) throw new Error('Format non reconnu : choisissez la sauvegarde privée JSON chiffrée créée par cette application.');
            let backup;
            try { backup = JSON.parse(trimmed); } catch { throw new Error('Le fichier JSON est incomplet ou invalide.'); }
            if (!backup || backup.type !== 'crypto-page-private-key') throw new Error('Ce JSON n’est pas une sauvegarde de clé privée de cette application.');
            if (backup.v !== 2) throw new Error('Format de sauvegarde non pris en charge. Seule la sauvegarde JSON v2 produite par l’interface est acceptée.');
            const restored = await engine.restorePrivate(text, password);
            const signing = { signingPrivateKey: restored.signingPrivateKey, signingPublicKey: await engine.publicSigningFromPrivate(restored.signingPrivateKey) };
            const pair = { ...restored, ...signing, publicKey: await engine.publicFromPrivate(restored.privateKey) };
            await setIdentity(pair, generation, true);
            $('private-file').value = '';
            $('restore-feedback').textContent = 'Identité importée. Ouvrez « Déchiffrer » pour lire un message signé.';
            status('Identité chargée localement, avec ses clés de chiffrement et de signature.');
        } catch (error) {
            if (generation === epoch) {
                $('restore-feedback').textContent = `${error.message || 'Clé privée invalide.'} Le fichier reste sélectionné pour réessayer.${identity ? ' La clé précédente reste chargée.' : ''}`;
            }
            throw error;
        } finally { password = ''; }
    });
});
$('restore-password').addEventListener('keydown', event => {
    if (event.key === 'Enter') { event.preventDefault(); $('import-private').click(); }
});
$('restore-password').addEventListener('input', sync);
$('recipient-file').addEventListener('change', event => {
    const file = event.target.files[0]; event.target.value = ''; if (!file) return;
    recipient = null; $('recipient-state').textContent = 'Aucun destinataire chargé'; $('recipient-fingerprint').textContent = ''; $('encrypt-output').value = '';
    run(async generation => {
        const bundle = await engine.importPublicIdentity(await fileText(file, 65536));
        const key = bundle.publicKey;
        const fp = await engine.fingerprint(key); stillCurrent(generation);
        recipient = key; $('recipient-state').textContent = `Destinataire chargé · RSA ${key.algorithm.modulusLength} bits`;
        $('recipient-fingerprint').textContent = fp;
        status('Clé du destinataire chargée. Comparez son empreinte avant le premier échange.');
    });
});
$('encrypt').addEventListener('click', () => run(async generation => {
    $('encrypt-output').value = '';
    const encrypted = await engine.encrypt(recipient, $('encrypt-input').value, identity); stillCurrent(generation);
    $('encrypt-output').value = encrypted; status('Message chiffré localement. Vous pouvez transmettre le résultat.');
}));
$('sender-identity-file').addEventListener('change', event => {
    const file = event.target.files[0]; trustedSenderSigningKey = null;
    $('sender-identity-state').textContent = 'Aucune identité d’expéditeur chargée.';
    $('sender-verification').textContent = 'Signature de l’expéditeur non vérifiée.';
    if (!file) return;
    run(async generation => {
        const bundle = await engine.importPublicIdentity(await fileText(file, 65536));
        if (!bundle.signingPublicKey) throw new Error('Ce fichier ne contient pas de clé de signature. Choisissez une identité publique JSON.');
        const fingerprint = await engine.fingerprint(bundle.signingPublicKey); stillCurrent(generation);
        trustedSenderSigningKey = bundle.signingPublicKey;
        $('sender-identity-state').textContent = `Identité de signature chargée · ${fingerprint}`;
        $('sender-verification').textContent = 'La signature sera comparée à cette identité.';
    });
});
$('decrypt').addEventListener('click', () => run(async generation => {
    $('decrypt-output').value = '';
    $('sender-verification').textContent = 'Vérification de la signature…';
    const result = await engine.decrypt(identity.privateKey, $('decrypt-input').value, trustedSenderSigningKey); stillCurrent(generation);
    $('decrypt-output').value = result.message;
    $('sender-verification').textContent = result.senderTrusted
        ? `Signature valide · identité chargée reconnue · ${result.senderFingerprint}`
        : `Signature valide · clé ${result.senderFingerprint} · identité humaine à confirmer`;
    status('Message déchiffré et signature vérifiée localement.');
}));
$('message-file').addEventListener('change', event => {
    const file = event.target.files[0]; event.target.value = ''; if (!file) return;
    $('decrypt-input').value = ''; $('decrypt-output').value = '';
    sync();
    run(async generation => { const text = await fileText(file, 8 * 1024 * 1024); stillCurrent(generation); $('decrypt-input').value = text; sync(); status('Message importé localement.'); });
});
$('copy-encrypted').addEventListener('click', () => run(async () => {
    if (!navigator.clipboard?.writeText) throw new Error('Copie indisponible : sélectionnez le texte chiffré et copiez-le manuellement.');
    await navigator.clipboard.writeText($('encrypt-output').value); status('Message chiffré copié.');
}));
$('save-encrypted').addEventListener('click', () => download($('encrypt-output').value, 'message-chiffre.crypto'));
$('clear').addEventListener('click', () => { if (saved || confirm('Votre clé privée n’a pas été sauvegardée. Effacer quand même ?')) clear(); });
$('encrypt-input').addEventListener('input', () => { $('encrypt-output').value = ''; sync(); });
$('decrypt-input').addEventListener('input', () => { $('decrypt-output').value = ''; $('sender-verification').textContent = 'Signature de l’expéditeur non vérifiée.'; sync(); });
window.addEventListener('beforeunload', event => { if (identity && !saved) { event.preventDefault(); event.returnValue = ''; } });
window.addEventListener('pagehide', clear);
window.addEventListener('pageshow', event => { if (event.persisted) clear(); });
// There is intentionally no fetch, XHR, WebSocket, beacon, cookie or browser storage.
if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
    status('Web Crypto est indisponible. Ouvrez cette page en HTTPS ou depuis http://localhost:8000 avec un navigateur récent.', true);
} else {
    $('app').disabled = false; sync(); status('Prêt. Toutes les opérations s’effectuent sur votre appareil.');
}
