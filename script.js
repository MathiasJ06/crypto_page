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
        console.log("Module Python charge");
    } catch (error) {
        console.error("Erreur lors du chargement du module Python :", error);
    }
}

// Echapper les caractères spéciaux pour Python
function escapeForPython(str) {
    // Echapper les backslashes, guillemets doubles et newlines
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
                // Echapper correctement pour Python
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

// Generer une cle Fernet
async function generateKey() {
    if (!isPyodideReady) {
        alert("Pyodide n'est pas encore pret. Veuillez patienter...");
        return;
    }

    const keyInput = document.getElementById('encrypt-key');
    keyInput.value = "Generation en cours...";

    try {
        const key = await runPythonFunction('generate_key');
        if (key) {
            keyInput.value = key;
            // Copier aussi dans l'onglet déchiffrage
            document.getElementById('decrypt-key').value = key;
        } else {
            keyInput.value = "Erreur de generation";
        }
    } catch (error) {
        keyInput.value = "Erreur de generation";
    }
}

// Chiffrer le texte en temps reel
async function encryptText() {
    const keyInput = document.getElementById('encrypt-key');
    const inputText = document.getElementById('encrypt-input');
    const outputText = document.getElementById('encrypt-output');

    const key = keyInput.value.trim();
    const text = inputText.value;

    if (!key) {
        outputText.value = "Veuillez d'abord fournir une cle";
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

// Dechiffrer le texte en temps reel
async function decryptText() {
    const keyInput = document.getElementById('decrypt-key');
    const inputText = document.getElementById('decrypt-input');
    const outputText = document.getElementById('decrypt-output');

    const key = keyInput.value.trim();
    const text = inputText.value;

    if (!key) {
        outputText.value = "Veuillez d'abord fournir une cle";
        return;
    }

    if (!text) {
        outputText.value = "";
        return;
    }

    outputText.value = "Dechiffrement en cours...";

    try {
        const decrypted = await runPythonFunction('decrypt_message', key, text);
        if (decrypted) {
            outputText.value = decrypted;
        } else {
            outputText.value = "Cle incorrecte ou message invalide";
        }
    } catch (error) {
        outputText.value = "Cle incorrecte ou message invalide";
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

// Effacer un champ
function clearField(elementId) {
    document.getElementById(elementId).value = "";
    
    if (elementId === 'encrypt-key') {
        document.getElementById('encrypt-output').value = "";
    }
    
    if (elementId === 'decrypt-key') {
        document.getElementById('decrypt-output').value = "";
    }
}

// Evenements
document.addEventListener('DOMContentLoaded', () => {
    setupTabs();

    document.getElementById('generate-key-btn').addEventListener('click', generateKey);
    document.getElementById('clear-key-btn').addEventListener('click', () => {
        clearField('encrypt-key');
        clearField('decrypt-key');
    });
    
    document.getElementById('clear-decrypt-key-btn').addEventListener('click', () => {
        clearField('decrypt-key');
    });

    // Chiffrement en temps reel (avec debounce)
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

    // Dechiffrement en temps reel (avec debounce)
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
