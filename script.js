// Variables globales
let pyodide;
let isPyodideReady = false;
let currentKey = '';

// Initialiser Pyodide
async function initializePyodide() {
    const progressBar = document.getElementById('progress-bar');
    const loadingDiv = document.getElementById('loading');
    const contentDiv = document.getElementById('content');

    try {
        // Charger Pyodide
        pyodide = await loadPyodide({
            indexURL: "https://cdn.jsdelivr.net/pyodide/v0.23.4/full/",
            // Afficher la progression du chargement
            onDownloadProgress: (loaded, total) => {
                const percent = (loaded / total) * 100;
                progressBar.value = percent;
            }
        });

        // Charger la bibliothèque cryptography
        await pyodide.loadPackage("cryptography");
        isPyodideReady = true;

        // Masquer le chargement et afficher le contenu
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';

        console.log("Pyodide et cryptography sont prêts !");
    } catch (error) {
        console.error("Erreur lors du chargement de Pyodide :", error);
        loadingDiv.innerHTML = `
            <p style="color: red;">Erreur lors du chargement de Pyodide. Vérifiez votre connexion Internet et réessayez.</p>
            <button onclick="location.reload()">Recharger la page</button>
        `;
    }
}

// Charger le script Python depuis un fichier
async function loadPythonScript() {
    const response = await fetch('generate_fernet_key.py');
    return await response.text();
}

// Exécuter une fonction Python
async function runPythonFunction(functionName, ...args) {
    if (!isPyodideReady) {
        alert("Pyodide n'est pas encore prêt. Veuillez patienter...");
        return null;
    }

    try {
        // Charger le script Python
        const pythonCode = await loadPythonScript();
        
        // Exécuter le script pour définir les fonctions
        await pyodide.runPythonAsync(pythonCode);
        
        // Appeler la fonction spécifique avec les arguments
        const argsStr = args.map(arg => {
            if (typeof arg === 'string') {
                return `"${arg.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
            }
            return arg;
        }).join(', ');
        
        const result = await pyodide.runPythonAsync(`${functionName}(${argsStr})`);
        return result;
    } catch (error) {
        console.error(`Erreur lors de l'exécution de ${functionName}:`, error);
        return null;
    }
}

// Générer une clé Fernet
async function generateKey() {
    if (!isPyodideReady) {
        alert("Pyodide n'est pas encore prêt. Veuillez patienter...");
        return;
    }

    const keyOutput = document.getElementById('key-output');
    keyOutput.value = "Génération en cours...";

    try {
        const key = await runPythonFunction('generate_key');
        if (key) {
            currentKey = key;
            keyOutput.value = key;
            // Activer les boutons de chiffrement/déchiffrement
            document.getElementById('encrypt-btn').disabled = false;
            document.getElementById('decrypt-btn').disabled = false;
        } else {
            keyOutput.value = "Erreur lors de la génération de la clé.";
        }
    } catch (error) {
        console.error("Erreur lors de la génération de la clé :", error);
        keyOutput.value = "Erreur lors de la génération de la clé. Voir la console.";
    }
}

// Chiffrer un message
async function encryptMessage() {
    if (!currentKey) {
        alert("Veuillez d'abord générer une clé Fernet !");
        return;
    }

    const messageInput = document.getElementById('encrypt-message');
    const encryptedOutput = document.getElementById('encrypted-output');
    
    if (!messageInput.value.trim()) {
        alert("Veuillez saisir un message à chiffrer !");
        return;
    }

    encryptedOutput.value = "Chiffrement en cours...";

    try {
        const encrypted = await runPythonFunction('encrypt_message', currentKey, messageInput.value);
        if (encrypted) {
            encryptedOutput.value = encrypted;
        } else {
            encryptedOutput.value = "Erreur lors du chiffrement.";
        }
    } catch (error) {
        console.error("Erreur lors du chiffrement :", error);
        encryptedOutput.value = "Erreur lors du chiffrement. Voir la console.";
    }
}

// Déchiffrer un message
async function decryptMessage() {
    if (!currentKey) {
        alert("Veuillez d'abord générer une clé Fernet !");
        return;
    }

    const encryptedInput = document.getElementById('decrypt-message');
    const decryptedOutput = document.getElementById('decrypted-output');
    
    if (!encryptedInput.value.trim()) {
        alert("Veuillez saisir un message chiffré à déchiffrer !");
        return;
    }

    decryptedOutput.value = "Déchiffrement en cours...";

    try {
        const decrypted = await runPythonFunction('decrypt_message', currentKey, encryptedInput.value);
        if (decrypted) {
            decryptedOutput.value = decrypted;
        } else {
            decryptedOutput.value = "Erreur : clé incorrecte ou message invalide.";
        }
    } catch (error) {
        console.error("Erreur lors du déchiffrement :", error);
        decryptedOutput.value = "Erreur lors du déchiffrement. Voir la console.";
    }
}

// Copier dans le presse-papiers
function copyToClipboard(elementId, successMessage) {
    const element = document.getElementById(elementId);
    if (!element.value) {
        alert("Rien à copier !");
        return;
    }

    element.select();
    document.execCommand('copy');
    alert(successMessage);
}

// Effacer un champ
function clearField(elementId) {
    document.getElementById(elementId).value = "";
}

// Événements
document.getElementById('generate-key-btn').addEventListener('click', generateKey);
document.getElementById('copy-key-btn').addEventListener('click', () => copyToClipboard('key-output', 'Clé copiée dans le presse-papiers !'));
document.getElementById('clear-key-btn').addEventListener('click', () => clearField('key-output'));

document.getElementById('encrypt-btn').addEventListener('click', encryptMessage);
document.getElementById('copy-encrypted-btn').addEventListener('click', () => copyToClipboard('encrypted-output', 'Message chiffré copié dans le presse-papiers !'));
document.getElementById('clear-encrypted-btn').addEventListener('click', () => clearField('encrypted-output'));

document.getElementById('decrypt-btn').addEventListener('click', decryptMessage);
document.getElementById('copy-decrypted-btn').addEventListener('click', () => copyToClipboard('decrypted-output', 'Message déchiffré copié dans le presse-papiers !'));
document.getElementById('clear-decrypted-btn').addEventListener('click', () => clearField('decrypted-output'));

// Désactiver les boutons de chiffrement/déchiffrement au démarrage
document.getElementById('encrypt-btn').disabled = true;
document.getElementById('decrypt-btn').disabled = true;

// Initialiser Pyodide au chargement de la page
initializePyodide();
