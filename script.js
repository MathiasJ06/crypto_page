/*
 * Crypto Page
 * ===========
 *
 * Interface JavaScript pour :
 *   - charger Pyodide
 *   - charger le module Python de cryptographie
 *   - générer une paire RSA
 *   - protéger la clé privée par mot de passe
 *   - chiffrer un message avec RSA-OAEP + Fernet
 *   - déchiffrer un message
 *   - copier / télécharger les résultats
 *
 * API Python attendue :
 *
 *   generate_rsa_keys(key_size=3072, password=None)
 *   encrypt_hybrid(public_key_pem, message)
 *   decrypt_hybrid(private_key_pem, encrypted_data, password=None)
 *   validate_rsa_public_key_pem(public_key_pem)
 *   validate_rsa_private_key_pem(private_key_pem, password=None)
 */


"use strict";


// ============================================================================
// CONFIGURATION
// ============================================================================

const PYODIDE_VERSION = "0.29.4";

const PYODIDE_INDEX_URL =
    `https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;

const PYTHON_SCRIPT = "crypto_complete.py";

const DEFAULT_RSA_KEY_SIZE = 3072;

const MAX_MESSAGE_LENGTH = 100 * 1024 * 1024;


// ============================================================================
// ÉTAT DE L'APPLICATION
// ============================================================================

const state = {
    pyodide: null,
    pythonReady: false,
    loadingPromise: null,

    publicKey: "",
    privateKey: "",

    privateKeyPassword: null,
    privateKeyEncrypted: false,

    lastCiphertext: "",
};


// ============================================================================
// UTILITAIRES DOM
// ============================================================================

function $(id) {
    return document.getElementById(id);
}


function setText(id, text) {
    const element = $(id);

    if (!element) {
        return;
    }

    element.textContent = text;
}


function show(id) {
    const element = $(id);

    if (element) {
        element.hidden = false;
    }
}


function hide(id) {
    const element = $(id);

    if (element) {
        element.hidden = true;
    }
}


function setDisabled(id, disabled) {
    const element = $(id);

    if (element) {
        element.disabled = disabled;
    }
}


function getValue(id) {
    const element = $(id);

    return element ? element.value : "";
}


function setValue(id, value) {
    const element = $(id);

    if (element) {
        element.value = value;
    }
}


// ============================================================================
// NOTIFICATIONS
// ============================================================================

function showStatus(message, type = "info") {
    /*
     * Cette fonction essaie d'utiliser les éléments existants du HTML.
     * Si aucun élément de statut n'existe, elle utilise la console.
     */

    const candidates = [
        "status",
        "message",
        "statusMessage",
        "notification"
    ];

    let element = null;

    for (const id of candidates) {
        element = $(id);

        if (element) {
            break;
        }
    }

    if (!element) {
        console[type === "error" ? "error" : "log"](message);
        return;
    }

    element.textContent = message;

    element.classList.remove(
        "success",
        "error",
        "warning",
        "info"
    );

    element.classList.add(type);
}


function showError(error) {
    console.error(error);

    let message = "Une erreur est survenue.";

    if (error instanceof Error && error.message) {
        message = error.message;
    } else if (typeof error === "string") {
        message = error;
    }

    showStatus(message, "error");
}


// ============================================================================
// PYODIDE
// ============================================================================

async function loadPyodideRuntime() {
    if (state.pyodide) {
        return state.pyodide;
    }

    if (state.loadingPromise) {
        return state.loadingPromise;
    }

    state.loadingPromise = (async () => {
        showStatus("Chargement du moteur cryptographique…", "info");

        if (typeof loadPyodide !== "function") {
            throw new Error(
                "Pyodide n'est pas disponible. Vérifiez son chargement."
            );
        }

        const pyodide = await loadPyodide({
            indexURL: PYODIDE_INDEX_URL
        });

        state.pyodide = pyodide;

        showStatus(
            "Chargement de la bibliothèque cryptographique…",
            "info"
        );

        /*
         * cryptography est généralement disponible comme package Pyodide.
         *
         * On essaie d'abord l'import direct.
         * Si nécessaire, micropip peut être utilisé comme solution de secours.
         */

        try {
            await pyodide.loadPackage([
                "micropip"
            ]);

            await pyodide.runPythonAsync(`
import cryptography
`);
        } catch (error) {
            /*
             * Ne pas afficher le contenu complet de l'erreur à
             * l'utilisateur si la première tentative échoue.
             */
            console.warn(
                "Import direct de cryptography échoué.",
                error
            );

            try {
                await pyodide.runPythonAsync(`
import micropip
await micropip.install("cryptography")
`);
            } catch (installError) {
                console.error(
                    "Impossible d'installer cryptography.",
                    installError
                );

                throw new Error(
                    "Impossible de charger la bibliothèque cryptographique."
                );
            }
        }

        await loadPythonCryptoModule(pyodide);

        state.pythonReady = true;

        showStatus(
            "Moteur cryptographique prêt.",
            "success"
        );

        updateUI();

        return pyodide;
    })();

    try {
        return await state.loadingPromise;
    } catch (error) {
        state.loadingPromise = null;
        state.pyodide = null;
        state.pythonReady = false;

        showError(error);

        throw error;
    }
}


async function loadPythonCryptoModule(pyodide) {
    /*
     * Charge crypto_complete.py dans un véritable module Python.
     *
     * Cela évite de reconstruire des appels Python complexes à chaque
     * opération.
     */

    const response = await fetch(PYTHON_SCRIPT, {
        cache: "no-cache"
    });

    if (!response.ok) {
        throw new Error(
            `Impossible de charger ${PYTHON_SCRIPT}.`
        );
    }

    const pythonCode = await response.text();

    if (!pythonCode.trim()) {
        throw new Error(
            `${PYTHON_SCRIPT} est vide.`
        );
    }

    pyodide.FS.writeFile(
        "/tmp/crypto_complete.py",
        pythonCode
    );

    await pyodide.runPythonAsync(`
import sys

if "/tmp" not in sys.path:
    sys.path.insert(0, "/tmp")

import importlib
import crypto_complete

importlib.reload(crypto_complete)
`);
}


// ============================================================================
// APPELS PYTHON
// ============================================================================

async function ensurePythonReady() {
    if (state.pythonReady && state.pyodide) {
        return state.pyodide;
    }

    return await loadPyodideRuntime();
}


async function pythonCall(functionName, args = {}) {
    const pyodide = await ensurePythonReady();

    /*
     * On transmet les arguments à Python via des variables PyProxy
     * plutôt que de générer :
     *
     *     function("... utilisateur ...")
     *
     * Cela évite les problèmes de quoting et d'injection dans le
     * code Python généré.
     */

    const pythonFunction = pyodide.globals
        .get("crypto_complete")[functionName];

    if (!pythonFunction) {
        throw new Error(
            `Fonction Python inconnue : ${functionName}`
        );
    }

    const pythonArgs = {};

    for (const [key, value] of Object.entries(args)) {
        pythonArgs[key] = value;
    }

    try {
        const result = pythonFunction(
            ...Object.values(pythonArgs)
        );

        /*
         * Les fonctions Python actuelles utilisent des arguments
         * positionnels. Cette fonction est conservée pour les appels
         * simples et est complétée par les helpers ci-dessous.
         */

        return result;
    } finally {
        /*
         * Les valeurs primitives JS ne nécessitent normalement pas
         * de destroy().
         */
    }
}


/*
 * Helpers explicites correspondant exactement à l'API Python.
 */

async function generateRSAKeys(keySize, password) {
    const pyodide = await ensurePythonReady();

    const result = await pyodide.runPythonAsync(`
import crypto_complete

crypto_complete.generate_rsa_keys(
    ${Number(keySize)},
    ${password === null ? "None" : JSON.stringify(password)}
)
`);

    return result;
}


async function encryptHybrid(publicKey, message) {
    const pyodide = await ensurePythonReady();

    /*
     * Passage des données via globals afin de ne jamais concaténer
     * directement le contenu utilisateur dans du code Python.
     */

    pyodide.globals.set(
        "_js_public_key",
        publicKey
    );

    pyodide.globals.set(
        "_js_message",
        message
    );

    try {
        const result = await pyodide.runPythonAsync(`
import crypto_complete

crypto_complete.encrypt_hybrid(
    _js_public_key,
    _js_message
)
`);

        return result;
    } finally {
        pyodide.globals.delete("_js_public_key");
        pyodide.globals.delete("_js_message");
    }
}


async function decryptHybrid(
    privateKey,
    ciphertext,
    password
) {
    const pyodide = await ensurePythonReady();

    pyodide.globals.set(
        "_js_private_key",
        privateKey
    );

    pyodide.globals.set(
        "_js_ciphertext",
        ciphertext
    );

    if (password === null || password === undefined) {
        pyodide.globals.set(
            "_js_password",
            null
        );
    } else {
        pyodide.globals.set(
            "_js_password",
            password
        );
    }

    try {
        const result = await pyodide.runPythonAsync(`
import crypto_complete

crypto_complete.decrypt_hybrid(
    _js_private_key,
    _js_ciphertext,
    _js_password
)
`);

        return result;
    } finally {
        pyodide.globals.delete("_js_private_key");
        pyodide.globals.delete("_js_ciphertext");
        pyodide.globals.delete("_js_password");
    }
}


async function validatePublicKey(publicKey) {
    const pyodide = await ensurePythonReady();

    pyodide.globals.set(
        "_js_public_key",
        publicKey
    );

    try {
        return Boolean(
            await pyodide.runPythonAsync(`
import crypto_complete

crypto_complete.validate_rsa_public_key_pem(
    _js_public_key
)
`)
        );
    } finally {
        pyodide.globals.delete("_js_public_key");
    }
}


async function validatePrivateKey(
    privateKey,
    password = null
) {
    const pyodide = await ensurePythonReady();

    pyodide.globals.set(
        "_js_private_key",
        privateKey
    );

    pyodide.globals.set(
        "_js_password",
        password
    );

    try {
        return Boolean(
            await pyodide.runPythonAsync(`
import crypto_complete

crypto_complete.validate_rsa_private_key_pem(
    _js_private_key,
    _js_password
)
`)
        );
    } finally {
        pyodide.globals.delete("_js_private_key");
        pyodide.globals.delete("_js_password");
    }
}


// ============================================================================
// GÉNÉRATION DES CLÉS
// ============================================================================

async function handleGenerateKeys() {
    const button = findElement([
        "generateKeys",
        "generate-keys",
        "generateRSAKeys",
        "generateButton"
    ]);

    if (button) {
        button.disabled = true;
    }

    try {
        const keySize = getRSAKeySize();

        const passwordEnabled = getPasswordProtectionEnabled();

        let password = null;

        if (passwordEnabled) {
            password = getValue("keyPassword");

            if (!password) {
                throw new Error(
                    "Veuillez saisir un mot de passe pour protéger la clé privée."
                );
            }

            if (password.length < 8) {
                throw new Error(
                    "Le mot de passe doit contenir au moins 8 caractères."
                );
            }

            const confirmation = getValue(
                "keyPasswordConfirmation"
            );

            if (confirmation && password !== confirmation) {
                throw new Error(
                    "Les mots de passe ne correspondent pas."
                );
            }
        }

        showStatus(
            `Génération d'une clé RSA ${keySize} bits…`,
            "info"
        );

        const start = performance.now();

        const json = await generateRSAKeys(
            keySize,
            password
        );

        const elapsed = Math.round(
            performance.now() - start
        );

        const keys = JSON.parse(json);

        if (
            !keys.public_key ||
            !keys.private_key
        ) {
            throw new Error(
                "La génération des clés a retourné un résultat invalide."
            );
        }

        state.publicKey = keys.public_key;
        state.privateKey = keys.private_key;

        state.privateKeyPassword = password;
        state.privateKeyEncrypted =
            Boolean(keys.encrypted_private_key);

        setPublicKeyOutput(state.publicKey);
        setPrivateKeyOutput(state.privateKey);

        showStatus(
            `Clés RSA ${keySize} bits générées en ${elapsed} ms.`,
            "success"
        );

        updateUI();

    } catch (error) {
        showError(error);
    } finally {
        if (button) {
            button.disabled = false;
        }
    }
}


function getRSAKeySize() {
    const element = findElement([
        "keySize",
        "rsaKeySize",
        "rsa-key-size"
    ]);

    if (!element || !element.value) {
        return DEFAULT_RSA_KEY_SIZE;
    }

    const keySize = Number(element.value);

    const allowedSizes = [
        2048,
        3072,
        4096
    ];

    if (!allowedSizes.includes(keySize)) {
        throw new Error(
            "Taille RSA invalide."
        );
    }

    return keySize;
}


function getPasswordProtectionEnabled() {
    const checkbox = findElement([
        "protectPrivateKey",
        "encryptPrivateKey",
        "passwordProtection"
    ]);

    if (!checkbox) {
        /*
         * Si l'ancien HTML ne possède pas encore de checkbox,
         * on considère que la protection est désactivée.
         */
        return false;
    }

    return checkbox.checked;
}


// ============================================================================
// CHIFFREMENT
// ============================================================================

async function handleEncrypt() {
    const button = findElement([
        "encrypt",
        "encryptButton",
        "encrypt-message"
    ]);

    if (button) {
        button.disabled = true;
    }

    try {
        const publicKey = getPublicKeyInput();
        const message = getPlaintextInput();

        if (!publicKey.trim()) {
            throw new Error(
                "Veuillez fournir une clé publique RSA."
            );
        }

        if (!message) {
            throw new Error(
                "Veuillez saisir un message."
            );
        }

        const messageSize = new TextEncoder()
            .encode(message)
            .byteLength;

        if (messageSize > MAX_MESSAGE_LENGTH) {
            throw new Error(
                "Le message est trop volumineux."
            );
        }

        showStatus(
            "Vérification de la clé publique…",
            "info"
        );

        const valid = await validatePublicKey(
            publicKey
        );

        if (!valid) {
            throw new Error(
                "La clé publique RSA est invalide."
            );
        }

        showStatus(
            "Chiffrement en cours…",
            "info"
        );

        const start = performance.now();

        const ciphertext = await encryptHybrid(
            publicKey,
            message
        );

        const elapsed = Math.round(
            performance.now() - start
        );

        if (
            typeof ciphertext !== "string" ||
            !ciphertext
        ) {
            throw new Error(
                "Le chiffrement a retourné un résultat invalide."
            );
        }

        state.lastCiphertext = ciphertext;

        setCiphertextOutput(ciphertext);

        showStatus(
            `Message chiffré en ${elapsed} ms.`,
            "success"
        );

        updateUI();

    } catch (error) {
        showError(error);
    } finally {
        if (button) {
            button.disabled = false;
        }
    }
}


// ============================================================================
// DÉCHIFFREMENT
// ============================================================================

async function handleDecrypt() {
    const button = findElement([
        "decrypt",
        "decryptButton",
        "decrypt-message"
    ]);

    if (button) {
        button.disabled = true;
    }

    try {
        const privateKey = getPrivateKeyInput();
        const ciphertext = getCiphertextInput();

        if (!privateKey.trim()) {
            throw new Error(
                "Veuillez fournir une clé privée RSA."
            );
        }

        if (!ciphertext.trim()) {
            throw new Error(
                "Veuillez fournir un message chiffré."
            );
        }

        /*
         * On demande le mot de passe seulement si nécessaire.
         *
         * On commence par tenter la validation sans mot de passe.
         * Si la clé est chiffrée, Python renverra False.
         */

        let password = null;

        const unprotectedKey = await validatePrivateKey(
            privateKey,
            null
        );

        if (!unprotectedKey) {
            password = await requestPrivateKeyPassword();

            const protectedKeyValid =
                await validatePrivateKey(
                    privateKey,
                    password
                );

            if (!protectedKeyValid) {
                throw new Error(
                    "Mot de passe incorrect ou clé privée invalide."
                );
            }
        }

        showStatus(
            "Déchiffrement en cours…",
            "info"
        );

        const start = performance.now();

        const plaintext = await decryptHybrid(
            privateKey,
            ciphertext.trim(),
            password
        );

        const elapsed = Math.round(
            performance.now() - start
        );

        setPlaintextOutput(plaintext);

        showStatus(
            `Message déchiffré en ${elapsed} ms.`,
            "success"
        );

        updateUI();

    } catch (error) {
        showError(error);
    } finally {
        if (button) {
            button.disabled = false;
        }
    }
}


async function requestPrivateKeyPassword() {
    /*
     * Si un champ permanent existe, on l'utilise.
     */

    const passwordInput = findElement([
        "privateKeyPassword",
        "decryptPassword",
        "keyPasswordDecrypt"
    ]);

    if (passwordInput) {
        const password = passwordInput.value;

        if (!password) {
            throw new Error(
                "La clé privée est protégée par un mot de passe."
            );
        }

        return password;
    }

    /*
     * Sinon, utilisation du prompt natif.
     *
     * Le mot de passe n'est jamais stocké dans localStorage.
     */

    const password = window.prompt(
        "Cette clé privée est protégée par un mot de passe.\n\n" +
        "Entrez le mot de passe :"
    );

    if (password === null) {
        throw new Error(
            "Déchiffrement annulé."
        );
    }

    if (!password) {
        throw new Error(
            "Mot de passe vide."
        );
    }

    return password;
}


// ============================================================================
// COPIE / TÉLÉCHARGEMENT
// ============================================================================

async function copyText(text, successMessage = "Copié.") {
    if (!text) {
        throw new Error(
            "Il n'y a rien à copier."
        );
    }

    try {
        await navigator.clipboard.writeText(text);

        showStatus(
            successMessage,
            "success"
        );
    } catch (error) {
        /*
         * Fallback pour les navigateurs qui ne permettent pas
         * navigator.clipboard.
         */

        const textarea = document.createElement("textarea");

        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.left = "-9999px";

        document.body.appendChild(textarea);

        textarea.focus();
        textarea.select();

        try {
            document.execCommand("copy");

            showStatus(
                successMessage,
                "success"
            );
        } finally {
            textarea.remove();
        }
    }
}


function downloadText(
    filename,
    content,
    mimeType = "text/plain;charset=utf-8"
) {
    if (!content) {
        throw new Error(
            "Il n'y a rien à télécharger."
        );
    }

    const blob = new Blob(
        [content],
        {
            type: mimeType
        }
    );

    const url = URL.createObjectURL(blob);

    const anchor = document.createElement("a");

    anchor.href = url;
    anchor.download = filename;

    document.body.appendChild(anchor);

    anchor.click();

    anchor.remove();

    /*
     * Libérer l'URL après le téléchargement.
     */
    setTimeout(() => {
        URL.revokeObjectURL(url);
    }, 1000);
}


function handleCopyPublicKey() {
    copyText(
        getPublicKeyInput(),
        "Clé publique copiée."
    ).catch(showError);
}


function handleCopyPrivateKey() {
    copyText(
        getPrivateKeyInput(),
        "Clé privée copiée."
    ).catch(showError);
}


function handleCopyCiphertext() {
    copyText(
        getCiphertextInput(),
        "Message chiffré copié."
    ).catch(showError);
}


function handleCopyPlaintext() {
    copyText(
        getPlaintextInput(),
        "Message déchiffré copié."
    ).catch(showError);
}


function handleDownloadPublicKey() {
    try {
        downloadText(
            "crypto-page-public-key.pem",
            getPublicKeyInput()
        );

        showStatus(
            "Clé publique téléchargée.",
            "success"
        );
    } catch (error) {
        showError(error);
    }
}


function handleDownloadPrivateKey() {
    try {
        const privateKey = getPrivateKeyInput();

        if (!privateKey) {
            throw new Error(
                "Aucune clé privée disponible."
            );
        }

        /*
         * Avertissement supplémentaire car la clé privée est
         * extrêmement sensible.
         */

        const confirmed = window.confirm(
            "Vous êtes sur le point de télécharger une clé privée.\n\n" +
            "Conservez-la dans un endroit sûr et ne la partagez jamais.\n\n" +
            "Continuer ?"
        );

        if (!confirmed) {
            return;
        }

        downloadText(
            "crypto-page-private-key.pem",
            privateKey
        );

        showStatus(
            "Clé privée téléchargée.",
            "success"
        );

    } catch (error) {
        showError(error);
    }
}


function handleDownloadCiphertext() {
    try {
        downloadText(
            "crypto-page-ciphertext.txt",
            getCiphertextInput()
        );

        showStatus(
            "Message chiffré téléchargé.",
            "success"
        );
    } catch (error) {
        showError(error);
    }
}


// ============================================================================
// RÉCUPÉRATION DES CHAMPS
// ============================================================================

function findElement(ids) {
    for (const id of ids) {
        const element = $(id);

        if (element) {
            return element;
        }
    }

    return null;
}


function getPublicKeyInput() {
    const element = findElement([
        "publicKey",
        "public-key",
        "publicKeyInput"
    ]);

    return element ? element.value : state.publicKey;
}


function getPrivateKeyInput() {
    const element = findElement([
        "privateKey",
        "private-key",
        "privateKeyInput"
    ]);

    return element ? element.value : state.privateKey;
}


function getPlaintextInput() {
    const element = findElement([
        "message",
        "plaintext",
        "plainText",
        "messageInput"
    ]);

    return element ? element.value : "";
}


function getCiphertextInput() {
    const element = findElement([
        "ciphertext",
        "encryptedMessage",
        "encryptedData",
        "ciphertextInput"
    ]);

    return element ? element.value : state.lastCiphertext;
}


function setPublicKeyOutput(value) {
    const element = findElement([
        "publicKey",
        "public-key",
        "publicKeyInput"
    ]);

    if (element) {
        element.value = value;
    }
}


function setPrivateKeyOutput(value) {
    const element = findElement([
        "privateKey",
        "private-key",
        "privateKeyInput"
    ]);

    if (element) {
        element.value = value;
    }
}


function setPlaintextOutput(value) {
    const element = findElement([
        "decryptedMessage",
        "plaintext",
        "plainText",
        "messageOutput"
    ]);

    if (element) {
        element.value = value;
    }
}


function setCiphertextOutput(value) {
    const element = findElement([
        "ciphertext",
        "encryptedMessage",
        "encryptedData",
        "ciphertextInput"
    ]);

    if (element) {
        element.value = value;
    }
}


// ============================================================================
// EFFACEMENT
// ============================================================================

function clearField(id) {
    const element = $(id);

    if (element) {
        element.value = "";
    }
}


function handleClearKeys() {
    state.publicKey = "";
    state.privateKey = "";

    state.privateKeyPassword = null;
    state.privateKeyEncrypted = false;

    clearField("publicKey");
    clearField("public-key");
    clearField("publicKeyInput");

    clearField("privateKey");
    clearField("private-key");
    clearField("privateKeyInput");

    clearField("keyPassword");
    clearField("keyPasswordConfirmation");

    showStatus(
        "Clés supprimées de l'interface.",
        "success"
    );

    updateUI();
}


function handleClearEncryption() {
    state.lastCiphertext = "";

    clearField("message");
    clearField("plaintext");
    clearField("plainText");
    clearField("messageInput");

    clearField("ciphertext");
    clearField("encryptedMessage");
    clearField("encryptedData");
    clearField("ciphertextInput");

    showStatus(
        "Données supprimées de l'interface.",
        "success"
    );

    updateUI();
}


// ============================================================================
// INTERFACE
// ============================================================================

function updateUI() {
    const ready = state.pythonReady;

    /*
     * Désactiver les opérations cryptographiques tant que Pyodide
     * n'est pas prêt.
     */

    const operationButtons = [
        "encrypt",
        "encryptButton",
        "decrypt",
        "decryptButton"
    ];

    for (const id of operationButtons) {
        const element = $(id);

        if (element) {
            element.disabled = !ready;
        }
    }

    /*
     * Afficher l'état du moteur.
     */

    const indicators = [
        "pythonStatus",
        "pyodideStatus",
        "cryptoStatus"
    ];

    for (const id of indicators) {
        const element = $(id);

        if (!element) {
            continue;
        }

        element.textContent = ready
            ? "Prêt"
            : "Chargement…";

        element.classList.toggle(
            "ready",
            ready
        );
    }
}


function updatePasswordUI() {
    const enabled = getPasswordProtectionEnabled();

    const passwordFields = [
        "keyPassword",
        "keyPasswordConfirmation"
    ];

    for (const id of passwordFields) {
        const element = $(id);

        if (!element) {
            continue;
        }

        element.disabled = !enabled;

        if (!enabled) {
            element.value = "";
        }
    }
}


// ============================================================================
// ÉVÉNEMENTS
// ============================================================================

function bindClick(ids, handler) {
    for (const id of ids) {
        const element = $(id);

        if (!element) {
            continue;
        }

        element.addEventListener(
            "click",
            handler
        );
    }
}


function bindEvents() {
    bindClick(
        [
            "generateKeys",
            "generate-keys",
            "generateRSAKeys",
            "generateButton"
        ],
        handleGenerateKeys
    );

    bindClick(
        [
            "encrypt",
            "encryptButton",
            "encrypt-message"
        ],
        handleEncrypt
    );

    bindClick(
        [
            "decrypt",
            "decryptButton",
            "decrypt-message"
        ],
        handleDecrypt
    );

    bindClick(
        [
            "copyPublicKey",
            "copy-public-key"
        ],
        handleCopyPublicKey
    );

    bindClick(
        [
            "copyPrivateKey",
            "copy-private-key"
        ],
        handleCopyPrivateKey
    );

    bindClick(
        [
            "copyCiphertext",
            "copy-ciphertext"
        ],
        handleCopyCiphertext
    );

    bindClick(
        [
            "copyPlaintext",
            "copy-plaintext"
        ],
        handleCopyPlaintext
    );

    bindClick(
        [
            "downloadPublicKey",
            "download-public-key"
        ],
        handleDownloadPublicKey
    );

    bindClick(
        [
            "downloadPrivateKey",
            "download-private-key"
        ],
        handleDownloadPrivateKey
    );

    bindClick(
        [
            "downloadCiphertext",
            "download-ciphertext"
        ],
        handleDownloadCiphertext
    );

    bindClick(
        [
            "clearKeys",
            "clear-keys"
        ],
        handleClearKeys
    );

    bindClick(
        [
            "clearEncryption",
            "clear-encryption"
        ],
        handleClearEncryption
    );

    const passwordProtection = findElement([
        "protectPrivateKey",
        "encryptPrivateKey",
        "passwordProtection"
    ]);

    if (passwordProtection) {
        passwordProtection.addEventListener(
            "change",
            updatePasswordUI
        );
    }
}


// ============================================================================
// INITIALISATION
// ============================================================================

async function initializeApplication() {
    try {
        bindEvents();

        updatePasswordUI();
        updateUI();

        /*
         * Le chargement commence après que le DOM est prêt.
         */
        await loadPyodideRuntime();

    } catch (error) {
        showError(error);
    }
}


// ============================================================================
// EXPOSITION GLOBALE
// ============================================================================

/*
 * Utile pour conserver la compatibilité avec un éventuel onclick=""
 * présent dans index.html.
 */

window.cryptoPage = {
    generateKeys: handleGenerateKeys,
    encrypt: handleEncrypt,
    decrypt: handleDecrypt,

    copyPublicKey: handleCopyPublicKey,
    copyPrivateKey: handleCopyPrivateKey,
    copyCiphertext: handleCopyCiphertext,
    copyPlaintext: handleCopyPlaintext,

    downloadPublicKey: handleDownloadPublicKey,
    downloadPrivateKey: handleDownloadPrivateKey,
    downloadCiphertext: handleDownloadCiphertext,

    clearKeys: handleClearKeys,
    clearEncryption: handleClearEncryption,

    loadPyodide: loadPyodideRuntime
};


// ============================================================================
// DÉMARRAGE
// ============================================================================

if (document.readyState === "loading") {
    document.addEventListener(
        "DOMContentLoaded",
        initializeApplication,
        {
            once: true
        }
    );
} else {
    initializeApplication();
}
