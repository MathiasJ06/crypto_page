// Variables globales
let pyodide;
let isPyodideReady = false;
let pythonModuleLoaded = false;

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

    } catch (error) {
        console.error("Erreur lors du chargement de Pyodide :", error);
        loadingDiv.innerHTML = `
            <p style="color: var(--error);">Erreur lors du chargement de Pyodide.</p>
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
        console.log("Module Python chargé");
    } catch (error) {
        console.error("Erreur lors du chargement du module Python :", error);
    }
}

// Exécuter une fonction Python
async function runPythonFunction(functionName, ...args) {
    if (!isPyodideReady || !pythonModuleLoaded) {
        console.log("Pyodide ou module non prêt");
        return null;
    }

    try {
        const argsStr = args.map(arg => {
            if (typeof arg === 'string') {
                // Échapper les guillemets et backslashes
                return `"${arg.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
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

// Générer une clé Fernet
async function generateKey() {
    if (!isPyodideReady) {
        alert("Pyodide n'est pas encore prêt. Veuillez patienter...");
        return;
    }

    const keyInput = document.getElementById('encrypt-key');
    keyInput.value = "Génération en cours...";

    try {
        const key = await runPythonFunction('generate_key');
        if (key) {
            keyInput.value = key;
            // Copier aussi dans l'onglet déchiffrage
            document.getElementById('decrypt-key').value = key;
        } else {
            keyInput.value = "Erreur de génération";
        }
    } catch (error) {
        keyInput.value = "Erreur de génération";
    }
}

// Chiffrer le texte en temps réel
async function encryptText() {
    const keyInput = document.getElementById('encrypt-key');
    const inputText = document.getElementById('encrypt-input');
    const outputText = document.getElementById('encrypt-output');

    const key = keyInput.value.trim();
    const text = inputText.value;

    if (!key) {
        outputText.value = "Veuillez d'abord fournir une clé";
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
    const keyInput = document.getElementById('decrypt-key');
    const inputText = document.getElementById('decrypt-input');
    const outputText = document.getElementById('decrypt-output');

    const key = keyInput.value.trim();
    const text = inputText.value;

    if (!key) {
        outputText.value = "Veuillez d'abord fournir une clé";
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

// Gestion des onglets
function setupTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.dataset.tab;

            // Retirer la classe active de tous
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            // Ajouter la classe active au cliqué
            button.classList.add('active');
            document.getElementById(`${tabId}-tab`).classList.add('active');
        });
    });
}

// Effacer un champ
function clearField(elementId) {
    document.getElementById(elementId).value = "";
    
    // Si on efface la clé de chiffrement, aussi effacer l'output
    if (elementId === 'encrypt-key') {
        document.getElementById('encrypt-output').value = "";
    }
    
    // Si on efface la clé de déchiffrement, aussi effacer l'output
    if (elementId === 'decrypt-key') {
        document.getElementById('decrypt-output').value = "";
    }
}

// Événements
document.addEventListener('DOMContentLoaded', () => {
    // Onglets
    setupTabs();

    // Génération de clé
    document.getElementById('generate-key-btn').addEventListener('click', generateKey);
    
    // Boutons effacer
    document.getElementById('clear-key-btn').addEventListener('click', () => {
        clearField('encrypt-key');
        clearField('decrypt-key');
    });
    
    document.getElementById('clear-decrypt-key-btn').addEventListener('click', () => {
        clearField('decrypt-key');
    });

    // Chiffrement en temps réel (avec debounce)
    let encryptTimeout;
    const encryptInput = document.getElementById('encrypt-input');
    const encryptKey = document.getElementById('encrypt-key');
    
    encryptInput.addEventListener('input', () => {
        clearTimeout(encryptTimeout);
        encryptTimeout = setTimeout(encryptText, 500);
    });
    
    encryptKey.addEventListener('input', () => {
        clearTimeout(encryptTimeout);
        encryptTimeout = setTimeout(encryptText, 500);
    });

    // Déchiffrement en temps réel (avec debounce)
    let decryptTimeout;
    const decryptInput = document.getElementById('decrypt-input');
    const decryptKey = document.getElementById('decrypt-key');
    
    decryptInput.addEventListener('input', () => {
        clearTimeout(decryptTimeout);
        decryptTimeout = setTimeout(decryptText, 500);
    });
    
    decryptKey.addEventListener('input', () => {
        clearTimeout(decryptTimeout);
        decryptTimeout = setTimeout(decryptText, 500);
    });
});

// Initialiser au chargement
initializePyodide();
