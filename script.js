// Variables globales
let pyodide;
let isPyodideReady = false;
let pythonModuleLoaded = false;
// Stockage des clés réelles (masquées dans l'UI)
let encryptKeyValue = "";
let decryptKeyValue = "";

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
    document.getElementById('encrypt-key').value = maskKey(encryptKeyValue);
    document.getElementById('decrypt-key').value = maskKey(decryptKeyValue);
}

// Générer une clé Fernet
async function generateKey() {
    if (!isPyodideReady) {
        alert("Pyodide n'est pas encore pret. Veuillez patienter...");
        return;
    }

    const keyInput = document.getElementById('encrypt-key');
    keyInput.value = "Génération en cours...";

    try {
        const key = await runPythonFunction('generate_key');
        if (key) {
            encryptKeyValue = key;
            decryptKeyValue = key;
            updateMaskedKeys();
        } else {
            keyInput.value = "Erreur de génération";
        }
    } catch (error) {
        keyInput.value = "Erreur de génération";
    }
}

// Chiffrer le texte en temps réel
async function encryptText() {
    const inputText = document.getElementById('encrypt-input');
    const outputText = document.getElementById('encrypt-output');

    const key = encryptKeyValue.trim();
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

// Déchiffrer le texte en temps réel
async function decryptText() {
    const inputText = document.getElementById('decrypt-input');
    const outputText = document.getElementById('decrypt-output');

    const key = decryptKeyValue.trim();
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

// Télécharger une clé sous forme de fichier
function downloadKey(key, keyType) {
    if (!key || key.length === 0) {
        alert("Aucune clé à télécharger.");
        return;
    }
    
    const blob = new Blob([key], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `fernet_key_${keyType}_${new Date().toISOString().slice(0, 10)}.key`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Charger une clé depuis un fichier
function loadKeyFromFile(keyType) {
    const fileInput = document.getElementById('file-input');
    fileInput.onchange = function(event) {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = function(e) {
            const key = e.target.result.trim();
            if (keyType === 'encrypt') {
                encryptKeyValue = key;
            } else {
                decryptKeyValue = key;
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
function clearKeys() {
    encryptKeyValue = "";
    decryptKeyValue = "";
    updateMaskedKeys();
    document.getElementById('encrypt-output').value = "";
    document.getElementById('decrypt-output').value = "";
}

// Effacer une clé spécifique
function clearKey(keyType) {
    if (keyType === 'encrypt') {
        encryptKeyValue = "";
    } else {
        decryptKeyValue = "";
    }
    updateMaskedKeys();
    
    if (keyType === 'encrypt') {
        document.getElementById('encrypt-output').value = "";
    } else {
        document.getElementById('decrypt-output').value = "";
    }
}

// Gestion des onglets
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

// Configurer tous les écouteurs d'événements
function setupEventListeners() {
    setupTabs();

    document.getElementById('generate-key-btn').addEventListener('click', generateKey);
    document.getElementById('clear-key-btn').addEventListener('click', clearKeys);
    document.getElementById('clear-decrypt-key-btn').addEventListener('click', () => clearKey('decrypt'));
    
    document.getElementById('download-encrypt-key-btn').addEventListener('click', () => downloadKey(encryptKeyValue, 'encrypt'));
    document.getElementById('download-decrypt-key-btn').addEventListener('click', () => downloadKey(decryptKeyValue, 'decrypt'));
    
    document.getElementById('load-encrypt-key-btn').addEventListener('click', () => loadKeyFromFile('encrypt'));
    document.getElementById('load-decrypt-key-btn').addEventListener('click', () => loadKeyFromFile('decrypt'));

    // Chiffrement en temps réel (avec debounce)
    let encryptTimeout;
    const encryptInput = document.getElementById('encrypt-input');
    
    encryptInput.addEventListener('input', () => {
        clearTimeout(encryptTimeout);
        encryptTimeout = setTimeout(encryptText, 500);
    });
    
    // Déchiffrement en temps réel (avec debounce)
    let decryptTimeout;
    const decryptInput = document.getElementById('decrypt-input');
    
    decryptInput.addEventListener('input', () => {
        clearTimeout(decryptTimeout);
        decryptTimeout = setTimeout(decryptText, 500);
    });
}

// Initialiser au chargement
initializePyodide();
