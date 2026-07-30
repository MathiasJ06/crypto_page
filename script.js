// Variables globales
let pyodide;
let isPyodideReady = false;
let pythonModuleLoaded = false;

// Stockage des clés symétriques (Fernet)
let symmetricKeyValue = "";

// Stockage des clés asymétriques (RSA)
let publicKeyValue = "";
let privateKeyValue = "";

// Initialiser Pyodide
async function initializePyodide() {
    const progressBar = document.getElementById('progress-bar');
    const loadingDiv = document.getElementById('loading');
    const contentDiv = document.getElementById('content');

    try {
        pyodide = await loadPyodide({
            indexURL: "https://cdn.jsdelivr.net/pyodide/v0.23.4/full/",
            onDownloadProgress: (loaded, total) => {
                const percent = (loaded / total) * 100;
                progressBar.value = percent;
            }
        });

        await pyodide.loadPackage("cryptography");
        isPyodideReady = true;

        // Charger le module Python
        await loadPythonModule();

        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';

        // Attacher les écouteurs d'événements APRÈS que tout soit chargé
        setupEventListeners();

    } catch (error) {
        console.error("Erreur lors du chargement de Pyodide :", error);
        loadingDiv.innerHTML = `
            <p style="color: #e74c3c;">Erreur lors du chargement de Pyodide.</p>
            <button onclick="location.reload()">Recharger</button>
        `;
    }
}

// Charger le module Python
async function loadPythonModule() {
    if (!isPyodideReady || pythonModuleLoaded) return;

    try {
        const response = await fetch('generate_fernet_key.py');
        const pythonCode = await response.text();
        await pyodide.runPythonAsync(pythonCode);
        pythonModuleLoaded = true;
    } catch (error) {
        console.error("Erreur lors du chargement du module Python :", error);
    }
}

// Echapper les caractères spéciaux pour Python
function escapeForPython(str) {
    return str.replace(/\\/g, '\\\\')
              .replace(/"/g, '\\"')
              .replace(/\n/g, '\\n')
              .replace(/\r/g, '\\r')
              .replace(/\t/g, '\\t');
}

// Executer une fonction Python
async function runPythonFunction(functionName, ...args) {
    if (!isPyodideReady || !pythonModuleLoaded) {
        console.log("Pyodide ou module non pret");
        return null;
    }

    try {
        const argsStr = args.map(arg => {
            if (typeof arg === 'string') {
                const escaped = escapeForPython(arg);
                return `"""${escaped}"""`;
            }
            return arg;
        }).join(', ');
        
        const result = await pyodide.runPythonAsync(`${functionName}(${argsStr})`);
        return result;
    } catch (error) {
        console.error(`Erreur dans ${functionName}:`, error);
        return null;
    }
}

// Masquer la clé dans l'UI
function maskKey(key) {
    if (!key || key.length === 0) return "";
    return "•".repeat(20);
}

// Mettre à jour l'affichage des clés masquées
function updateMaskedKeys() {
    document.getElementById('symmetric-key').value = maskKey(symmetricKeyValue);
    document.getElementById('public-key').value = maskKey(publicKeyValue);
    document.getElementById('private-key').value = maskKey(privateKeyValue);
}

// ====================
// FONCTIONS SYMÉTRIQUES
// ====================

// Générer une clé Fernet
async function generateSymmetricKey() {
    if (!isPyodideReady) {
        alert("Pyodide n'est pas encore pret. Veuillez patienter...");
        return;
    }

    const keyInput = document.getElementById('symmetric-key');
    keyInput.value = "Génération en cours...";

    try {
        const key = await runPythonFunction('generate_key');
        if (key) {
            symmetricKeyValue = key;
            updateMaskedKeys();
        } else {
            keyInput.value = "Erreur de génération";
        }
    } catch (error) {
        keyInput.value = "Erreur de génération";
    }
}

// Chiffrer avec clé symétrique
async function symmetricEncrypt() {
    const inputText = document.getElementById('symmetric-input');
    const outputText = document.getElementById('symmetric-output');

    const key = symmetricKeyValue.trim();
    const text = inputText.value;

    if (!key) {
        outputText.value = "Veuillez d'abord générer ou charger une clé";
        return;
    }

    if (!text) {
        outputText.value = "";
        return;
    }

    outputText.value = "Chiffrement en cours...";

    try {
        const encrypted = await runPythonFunction('encrypt_message', key, text);
        if (encrypted) {
            outputText.value = encrypted;
        } else {
            outputText.value = "Erreur de chiffrement";
        }
    } catch (error) {
        outputText.value = "Erreur de chiffrement";
    }
}

// Déchiffrer avec clé symétrique
async function symmetricDecrypt() {
    const inputText = document.getElementById('symmetric-input');
    const outputText = document.getElementById('symmetric-output');

    const key = symmetricKeyValue.trim();
    const text = inputText.value;

    if (!key) {
        outputText.value = "Veuillez d'abord générer ou charger une clé";
        return;
    }

    if (!text) {
        outputText.value = "";
        return;
    }

    outputText.value = "Déchiffrement en cours...";

    try {
        const decrypted = await runPythonFunction('decrypt_message', key, text);
        if (decrypted) {
            outputText.value = decrypted;
        } else {
            outputText.value = "Clé incorrecte ou message invalide";
        }
    } catch (error) {
        outputText.value = "Clé incorrecte ou message invalide";
    }
}

// ====================
// FONCTIONS ASYMÉTRIQUES (RSA)
// ====================

// Générer une paire de clés RSA
async function generateRSAKeys() {
    if (!isPyodideReady) {
        alert("Pyodide n'est pas encore pret. Veuillez patienter...");
        return;
    }

    const publicKeyName = document.getElementById('public-key-name').value.trim() || "public_key";
    const privateKeyName = document.getElementById('private-key-name').value.trim() || "private_key";
    
    const publicKeyInput = document.getElementById('public-key');
    const privateKeyInput = document.getElementById('private-key');
    publicKeyInput.value = "Génération en cours...";
    privateKeyInput.value = "Génération en cours...";

    try {
        // Générer une paire RSA 2048 bits
        const pythonCode = `
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Générer la paire de clés
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Sérialiser la clé publique en PEM
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# Sérialiser la clé privée en PEM (sans mot de passe)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

public_pem, private_pem
`;
        const result = await pyodide.runPythonAsync(pythonCode);
        if (result) {
            publicKeyValue = result[0];
            privateKeyValue = result[1];
            updateMaskedKeys();
        } else {
            publicKeyInput.value = "Erreur de génération";
            privateKeyInput.value = "Erreur de génération";
        }
    } catch (error) {
        console.error("Erreur lors de la génération RSA :", error);
        publicKeyInput.value = "Erreur de génération";
        privateKeyInput.value = "Erreur de génération";
    }
}

// Chiffrer avec clé publique RSA
async function asymmetricEncrypt() {
    const inputText = document.getElementById('asymmetric-input');
    const outputText = document.getElementById('asymmetric-output');

    const key = publicKeyValue.trim();
    const text = inputText.value;

    if (!key) {
        outputText.value = "Veuillez d'abord générer ou charger une clé publique";
        return;
    }

    if (!text) {
        outputText.value = "";
        return;
    }

    outputText.value = "Chiffrement en cours...";

    try {
        const escapedText = escapeForPython(text);
        const pythonCode = `
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

public_key_pem = """${key}"""
public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

message = """${escapedText}""".encode('utf-8')

# Chiffrer avec RSA-OAEP
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Retourner en base64 pour faciliter le stockage
import base64
base64.b64encode(ciphertext).decode('utf-8')
`;
        const encrypted = await pyodide.runPythonAsync(pythonCode);
        if (encrypted) {
            outputText.value = encrypted;
        } else {
            outputText.value = "Erreur de chiffrement";
        }
    } catch (error) {
        console.error("Erreur de chiffrement RSA :", error);
        outputText.value = "Erreur de chiffrement";
    }
}

// Déchiffrer avec clé privée RSA
async function asymmetricDecrypt() {
    const inputText = document.getElementById('asymmetric-input');
    const outputText = document.getElementById('asymmetric-output');

    const key = privateKeyValue.trim();
    const text = inputText.value;

    if (!key) {
        outputText.value = "Veuillez d'abord générer ou charger une clé privée";
        return;
    }

    if (!text) {
        outputText.value = "";
        return;
    }

    outputText.value = "Déchiffrement en cours...";

    try {
        const escapedText = escapeForPython(text);
        const pythonCode = `
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

private_key_pem = """${key}"""
private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)

# Décoder depuis base64
ciphertext = base64.b64decode("${escapedText}".encode('utf-8'))

# Déchiffrer avec RSA-OAEP
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

plaintext.decode('utf-8')
`;
        const decrypted = await pyodide.runPythonAsync(pythonCode);
        if (decrypted) {
            outputText.value = decrypted;
        } else {
            outputText.value = "Clé incorrecte ou message invalide";
        }
    } catch (error) {
        console.error("Erreur de déchiffrement RSA :", error);
        outputText.value = "Clé incorrecte ou message invalide";
    }
}

// ====================
// FONCTIONS UTILITAIRES
// ====================

// Télécharger une clé sous forme de fichier
function downloadKey(key, keyType, customName = null) {
    if (!key || key.length === 0) {
        alert("Aucune clé à télécharger.");
        return;
    }
    
    const name = customName || `fernet_key_${keyType}_${new Date().toISOString().slice(0, 10)}`;
    const blob = new Blob([key], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name}.key`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Charger une clé depuis un fichier
function loadKeyFromFile(keyType, fileInputId, targetVariable) {
    const fileInput = document.getElementById(fileInputId);
    fileInput.onchange = function(event) {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = function(e) {
            const key = e.target.result.trim();
            if (keyType === 'symmetric') {
                symmetricKeyValue = key;
            } else if (keyType === 'public') {
                publicKeyValue = key;
            } else if (keyType === 'private') {
                privateKeyValue = key;
            }
            updateMaskedKeys();
            
            // Réinitialiser l'input pour permettre de recharger le même fichier
            fileInput.value = "";
        };
        reader.readAsText(file);
    };
    fileInput.click();
}

// Effacer les clés
function clearSymmetricKey() {
    symmetricKeyValue = "";
    updateMaskedKeys();
    document.getElementById('symmetric-output').value = "";
}

function clearPublicKey() {
    publicKeyValue = "";
    updateMaskedKeys();
    document.getElementById('asymmetric-output').value = "";
}

function clearPrivateKey() {
    privateKeyValue = "";
    updateMaskedKeys();
    document.getElementById('asymmetric-output').value = "";
}

// ====================
// GESTION DES ONGLETS
// ====================

function setupTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.dataset.tab;

            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            button.classList.add('active');
            document.getElementById(`${tabId}-tab`).classList.add('active');
        });
    });
}

// ====================
// CONFIGURATION DES ÉCOUTEURS
// ====================

function setupEventListeners() {
    setupTabs();

    // Onglet Symétrique
    document.getElementById('generate-symmetric-key-btn').addEventListener('click', generateSymmetricKey);
    document.getElementById('clear-symmetric-key-btn').addEventListener('click', clearSymmetricKey);
    document.getElementById('download-symmetric-key-btn').addEventListener('click', () => downloadKey(symmetricKeyValue, 'symmetric'));
    document.getElementById('load-symmetric-key-btn').addEventListener('click', () => loadKeyFromFile('symmetric', 'file-input-symmetric', symmetricKeyValue));
    document.getElementById('symmetric-encrypt-btn').addEventListener('click', symmetricEncrypt);
    document.getElementById('symmetric-decrypt-btn').addEventListener('click', symmetricDecrypt);

    // Onglet Asymétrique
    document.getElementById('generate-rsa-keys-btn').addEventListener('click', generateRSAKeys);
    document.getElementById('download-public-key-btn').addEventListener('click', () => {
        const name = document.getElementById('public-key-name').value.trim() || "public_key";
        downloadKey(publicKeyValue, 'public', name);
    });
    document.getElementById('download-private-key-btn').addEventListener('click', () => {
        const name = document.getElementById('private-key-name').value.trim() || "private_key";
        downloadKey(privateKeyValue, 'private', name);
    });
    document.getElementById('load-public-key-btn').addEventListener('click', () => loadKeyFromFile('public', 'file-input-public', publicKeyValue));
    document.getElementById('load-private-key-btn').addEventListener('click', () => loadKeyFromFile('private', 'file-input-private', privateKeyValue));
    document.getElementById('clear-public-key-btn').addEventListener('click', clearPublicKey);
    document.getElementById('clear-private-key-btn').addEventListener('click', clearPrivateKey);
    document.getElementById('asymmetric-encrypt-btn').addEventListener('click', asymmetricEncrypt);
    document.getElementById('asymmetric-decrypt-btn').addEventListener('click', asymmetricDecrypt);
}

// Initialiser au chargement
initializePyodide();
