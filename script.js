import * as engine from './crypto-engine.js';
const $ = id => document.getElementById(id);
let identity = null, recipient = null, saved = true, busy = false, epoch = 0;
function status(message, error = false) { $('status').textContent = message; $('status').classList.toggle('error', error); }
function sync() {
    $('export-public').disabled = !identity;
    $('export-private').disabled = !identity;
    $('encrypt').disabled = !recipient;
    $('decrypt').disabled = !identity;
    $('copy-encrypted').disabled = !$('encrypt-output').value;
    $('save-encrypted').disabled = !$('encrypt-output').value;
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
    const fp = await engine.fingerprint(pair.publicKey);
    stillCurrent(generation);
    identity = pair; saved = isSaved;
    $('my-state').textContent = `Clés chargées · RSA ${pair.publicKey.algorithm.modulusLength} bits`;
    $('my-fingerprint').textContent = fp;
    $('decrypt-output').value = '';
}
function download(text, name) {
    const url = URL.createObjectURL(new Blob([text], { type: 'application/octet-stream' }));
    const a = document.createElement('a'); a.href = url; a.download = name;
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function fileText(file, max) {
    if (!file || file.size > max) throw new Error('Fichier absent ou trop volumineux.');
    return file.text();
}
function clear() {
    epoch++; busy = false; identity = null; recipient = null; saved = true;
    for (const el of document.querySelectorAll('textarea, input')) el.value = '';
    $('my-state').textContent = 'Aucune clé chargée'; $('recipient-state').textContent = 'Aucun destinataire chargé';
    $('my-fingerprint').textContent = ''; $('recipient-fingerprint').textContent = '';
    $('app').disabled = !globalThis.crypto?.subtle; sync();
    status('Onglet verrouillé : clés libérées et textes effacés de l’interface.');
}
for (const button of document.querySelectorAll('[data-panel]')) button.addEventListener('click', () => {
    for (const b of document.querySelectorAll('[data-panel]')) {
        const active = b === button; b.setAttribute('aria-pressed', String(active)); $(b.dataset.panel + '-panel').hidden = !active;
    }
});
$('generate').addEventListener('click', () => {
    if (!replaceAllowed()) return;
    run(async generation => { const pair = await engine.generateKeys(); await setIdentity(pair, generation, false); status('Clés créées. Téléchargez votre sauvegarde privée chiffrée avant de fermer cet onglet.'); });
});
$('export-public').addEventListener('click', () => run(async generation => {
    const text = await engine.publicPEM(identity.publicKey); stillCurrent(generation);
    download(text, 'ma-cle-publique.pem'); status('Clé publique prête à partager.');
}));
$('export-private').addEventListener('click', () => run(async generation => {
    let password = $('backup-password').value;
    try {
        if (password !== $('backup-confirm').value) throw new Error('Les deux phrases secrètes ne correspondent pas.');
        const text = await engine.protectPrivate(identity.privateKey, password); stillCurrent(generation);
        download(text, 'ma-cle-privee-protegee.json'); saved = true;
        status('Téléchargement demandé. Vérifiez que la sauvegarde est bien présente avant de fermer l’onglet.');
    } finally { password = ''; $('backup-password').value = ''; $('backup-confirm').value = ''; }
}));
$('private-file').addEventListener('change', event => {
    const file = event.target.files[0]; event.target.value = '';
    if (!file || !replaceAllowed()) return;
    run(async generation => {
        let password = $('restore-password').value; $('restore-password').value = '';
        try {
            const text = await fileText(file, 65536);
            const key = await engine.restorePrivate(text, password);
            const pub = await engine.publicFromPrivate(key);
            await setIdentity({ privateKey: key, publicKey: pub }, generation, true);
            status('Clé privée chargée localement. La clé publique correspondante est disponible.');
        } finally { password = ''; }
    });
});
$('recipient-file').addEventListener('change', event => {
    const file = event.target.files[0]; event.target.value = ''; if (!file) return;
    recipient = null; $('recipient-state').textContent = 'Aucun destinataire chargé'; $('recipient-fingerprint').textContent = ''; $('encrypt-output').value = '';
    run(async generation => {
        const key = await engine.importPublic(await fileText(file, 65536));
        const fp = await engine.fingerprint(key); stillCurrent(generation);
        recipient = key; $('recipient-state').textContent = `Destinataire chargé · RSA ${key.algorithm.modulusLength} bits`;
        $('recipient-fingerprint').textContent = fp;
        status('Clé du destinataire chargée. Comparez son empreinte avant le premier échange.');
    });
});
$('encrypt').addEventListener('click', () => run(async generation => {
    $('encrypt-output').value = '';
    const encrypted = await engine.encrypt(recipient, $('encrypt-input').value); stillCurrent(generation);
    $('encrypt-output').value = encrypted; status('Message chiffré localement. Vous pouvez transmettre le résultat.');
}));
$('decrypt').addEventListener('click', () => run(async generation => {
    $('decrypt-output').value = '';
    const plaintext = await engine.decrypt(identity.privateKey, $('decrypt-input').value); stillCurrent(generation);
    $('decrypt-output').value = plaintext; status('Message déchiffré localement.');
}));
$('message-file').addEventListener('change', event => {
    const file = event.target.files[0]; event.target.value = ''; if (!file) return;
    $('decrypt-input').value = ''; $('decrypt-output').value = '';
    run(async generation => { const text = await fileText(file, 8 * 1024 * 1024); stillCurrent(generation); $('decrypt-input').value = text; status('Message importé localement.'); });
});
$('copy-encrypted').addEventListener('click', () => run(async () => {
    if (!navigator.clipboard?.writeText) throw new Error('Copie indisponible : sélectionnez le texte chiffré et copiez-le manuellement.');
    await navigator.clipboard.writeText($('encrypt-output').value); status('Message chiffré copié.');
}));
$('save-encrypted').addEventListener('click', () => download($('encrypt-output').value, 'message-chiffre.crypto'));
$('clear').addEventListener('click', () => { if (saved || confirm('Votre clé privée n’a pas été sauvegardée. Effacer quand même ?')) clear(); });
$('encrypt-input').addEventListener('input', () => { $('encrypt-output').value = ''; sync(); });
$('decrypt-input').addEventListener('input', () => { $('decrypt-output').value = ''; });
window.addEventListener('beforeunload', event => { if (identity && !saved) { event.preventDefault(); event.returnValue = ''; } });
window.addEventListener('pagehide', clear);
window.addEventListener('pageshow', event => { if (event.persisted) clear(); });
// There is intentionally no fetch, XHR, WebSocket, beacon, cookie or browser storage.
if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
    status('Web Crypto est indisponible. Ouvrez cette page en HTTPS ou depuis http://localhost:8000 avec un navigateur récent.', true);
} else {
    $('app').disabled = false; sync(); status('Prêt. Toutes les opérations s’effectuent sur votre appareil.');
}
