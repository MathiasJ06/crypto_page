// Variables globales
let pyodide;
let isPyodideReady = false;
let pythonModuleLoaded = false;

// Stockage des clés
let myPublicKeyValue = "";
let myPrivateKeyValue = "";
let interlocutorPublicKeyValue = "";

// Stockage des noms de fichiers des clés pour les logs
let myPublicKeyName = "";
let myPrivateKeyName = "";
let interlocutorPublicKeyName = "";

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

        // Charger le package cryptography (contient tout ce dont on a besoin)
        console.log("Chargement du package cryptography...");
        await pyodide.loadPackage("cryptography");
        console.log("Package cryptography chargé avec succès");
        
        isPyodideReady = true;

        // Charger le module Python complet
        await loadPythonModules();

        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';

        // Attacher les écouteurs d'événements APRÈS que tout soit chargé
        setupEventListeners();

    } catch (error) {
        console.error("Erreur lors du chargement de Pyodide :", error);
        loadingDiv.innerHTML = `
            <p style="color: #e74c3c;">Erreur lors du chargement de Pyodide: ${error.message || error}</p>
            <p style="color: #666; font-size: 14px; margin-top: 10px;">
                Veuillez vérifier votre connexion internet et autoriser le chargement des scripts externes.<br>
                Pyodide nécessite une connexion internet pour se charger (environ 10-15 Mo).
            </p>
            <p style="color: #666; font-size: 12px; margin-top: 10px;">
                Si vous testez localement, utilisez un serveur HTTP: <code>python -m http.server 8000</code><br>
                Puis ouvrez <code>http://localhost:8000</code>
            </p>
            <button onclick="location.reload()" style="margin-top: 15px;">Recharger la page</button>
        `;
    }
}

// Charger le module Python complet
async function loadPythonModules() {
    if (!isPyodideReady || pythonModuleLoaded) return;

    try {
        // Charger le module complet (tout en un seul fichier, sans imports locaux)
        const completeResponse = await fetch('crypto_complete.py');
        const completeCode = await completeResponse.text();
        console.log("Chargement de crypto_complete.py...");
        await pyodide.runPythonAsync(completeCode);
        console.log("crypto_complete.py chargé avec succès");
        
        pythonModuleLoaded = true;
        console.log("Modules Python chargés");
    } catch (error) {
        console.error("Erreur lors du chargement des modules Python :", error);
        throw error;
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
    if (!isPyodideReady) {
        console.error("Pyodide n'est pas prêt");
        throw new Error("Pyodide n'est pas initialisé. Veuillez recharger la page.");
    }
    if (!pythonModuleLoaded) {
        console.error("Les modules Python ne sont pas chargés");
        throw new Error("Les modules Python ne sont pas chargés. Veuillez recharger la page.");
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
        throw error;
    }
}

// Extraire le nom du fichier à partir du contenu de la clé
function getKeyName(keyContent) {
    if (!keyContent) return "Non chargée";
    // Si la clé a été chargée depuis un fichier, on aurait le nom
    // Sinon, on extrait un identifiant à partir du contenu
    if (keyContent.includes("-----BEGIN PUBLIC KEY-----")) {
        const lines = keyContent.split('\n');
        const firstLine = lines.find(l => l.includes('-----BEGIN') || l.includes('-----END'));
        if (firstLine && firstLine.includes('(')) {
            return firstLine.match(/\(([^)]+)\)/)?.[1] || "Clé publique";
        }
        return "Clé publique";
    } else if (keyContent.includes("-----BEGIN PRIVATE KEY-----")) {
        return "Clé privée";
    }
    return "Clé";
}

// Mettre à jour l'affichage du statut des clés
function updateKeyStatus() {
    const publicKeyStatus = document.getElementById('public-key-status');
    const privateKeyStatus = document.getElementById('private-key-status');
    const interlocutorKeyStatus = document.getElementById('interlocutor-key-status');
    
    publicKeyStatus.textContent = myPublicKeyValue ? "✅ Chargée" : "❌ Non chargée";
    publicKeyStatus.className = myPublicKeyValue ? "ok" : "error";
    
    privateKeyStatus.textContent = myPrivateKeyValue ? "✅ Chargée" : "❌ Non chargée";
    privateKeyStatus.className = myPrivateKeyValue ? "ok" : "error";
    
    interlocutorKeyStatus.textContent = interlocutorPublicKeyValue ? "✅ Chargée" : "❌ Non chargée";
    interlocutorKeyStatus.className = interlocutorPublicKeyValue ? "ok" : "error";
}

// ====================
// FONCTIONS DE GESTION DES CLÉS
// ====================

// Générer une paire de clés RSA
async function generateRSAKeys() {
    if (!isPyodideReady) {
        alert("Pyodide n'est pas encore prêt. Veuillez patienter...");
        return;
    }

    const generateBtn = document.getElementById('generate-rsa-keys-btn');
    const originalText = generateBtn.textContent;
    generateBtn.disabled = true;
    generateBtn.textContent = "Génération en cours...";

    try {
        console.log("Génération des clés RSA...");
        const result = await runPythonFunction('generate_rsa_keys');
        
        console.log("Résultat brut:", result);
        
        if (!result) {
            throw new Error("Aucun résultat retourné");
        }
        
        // Parser le JSON retourné par Python
        let keys;
        try {
            keys = JSON.parse(result);
        } catch (e) {
            console.error("Erreur de parsing JSON:", e);
            throw new Error("Le résultat n'est pas un JSON valide: " + result);
        }
        
        if (!keys.public_key || !keys.private_key) {
            throw new Error("Clés manquantes dans la réponse");
        }
        
        if (!keys.public_key.startsWith("-----BEGIN PUBLIC KEY-----") || 
            !keys.private_key.startsWith("-----BEGIN PRIVATE KEY-----")) {
            throw new Error("Clés RSA mal formatées");
        }
        
        myPublicKeyValue = keys.public_key;
        myPrivateKeyValue = keys.private_key;
        
        // Mettre à jour les noms des clés
        const prefix = document.getElementById('key-prefix').value.trim() || "ma_cle";
        myPublicKeyName = `${prefix}_public`;
        myPrivateKeyName = `${prefix}_private`;
        
        updateKeyStatus();
        
        // Activer les boutons de téléchargement
        document.getElementById('download-rsa-public-key-btn').disabled = false;
        document.getElementById('download-rsa-private-key-btn').disabled = false;
        
        alert("Paire de clés RSA générée avec succès ! Vous pouvez maintenant les télécharger.");
        
    } catch (error) {
        console.error("Erreur lors de la génération RSA:", error);
        alert("Erreur lors de la génération des clés RSA: " + error.message);
    } finally {
        generateBtn.disabled = false;
        generateBtn.textContent = originalText;
    }
}

// ====================
// FONCTIONS DE GESTION DE LA CLÉ DE L'INTERLOCUTEUR
// ====================

// Charger la clé publique de l'interlocuteur depuis un fichier
function loadInterlocutorKeyFromFile() {
    const fileInput = document.getElementById('file-input-interlocutor');
    fileInput.onchange = function(event) {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = function(e) {
            const key = e.target.result.trim();
            if (!key.startsWith("-----BEGIN PUBLIC KEY-----")) {
                alert("Le fichier chargé n'est pas une clé publique RSA valide (format PEM attendu).");
                fileInput.value = "";
                return;
            }
            interlocutorPublicKeyValue = key;
            interlocutorPublicKeyName = file.name.replace('.key', '').replace('.txt', '');
            fileInput.value = "";
            updateKeyStatus();
            alert("Clé publique RSA de l'interlocuteur chargée avec succès.");
        };
        reader.readAsText(file);
    };
    fileInput.click();
}

// ====================
// FONCTIONS DE CHIFFREMENT/DÉCHIFFREMENT HYBRIDE
// ====================

// Chiffrer un message (hybride : Fernet + RSA)
async function encryptMessage() {
    const inputText = document.getElementById('encrypt-input');
    const outputText = document.getElementById('encrypt-output');
    const logText = document.getElementById('encrypt-log');
    const logSection = document.getElementById('encrypt-log-section');
    
    const text = inputText.value;
    
    if (!text) {
        outputText.value = "";
        return;
    }
    
    if (!interlocutorPublicKeyValue) {
        outputText.value = "Veuillez d'abord charger la clé publique de votre interlocuteur.";
        return;
    }
    
    const encryptBtn = document.getElementById('encrypt-btn');
    const originalText = encryptBtn.textContent;
    encryptBtn.disabled = true;
    encryptBtn.textContent = "Chiffrement en cours...";
    outputText.value = "Chiffrement en cours...";
    
    // Afficher les logs
    logText.textContent = "[INFO] Début du chiffrement...\n";
    logSection.style.display = 'block';
    
    try {
        logText.textContent += `[INFO] Longueur du message: ${text.length} caractères\n`;
        logText.textContent += `[INFO] Clé publique du destinataire: ${interlocutorPublicKeyName || 'Non nommée'}\n`;
        logText.textContent += `[INFO] Clé privée de l'envoyeur: ${myPrivateKeyName || 'Non chargée'}\n`;
        
        const startTime = Date.now();
        const result = await runPythonFunction('encrypt_hybrid', interlocutorPublicKeyValue, text);
        const endTime = Date.now();
        
        logText.textContent += `[INFO] Chiffrement terminé en ${endTime - startTime}ms\n`;
        
        if (!result) {
            throw new Error("Échec du chiffrement hybride");
        }
        
        logText.textContent += `[SUCCESS] Message chiffré avec succès!\n`;
        logText.textContent += `[INFO] Longueur du résultat: ${result.length} caractères\n`;
        
        // Le résultat est maintenant une chaîne Base64 directement, pas du JSON
        outputText.value = result;
        
    } catch (error) {
        console.error("Erreur lors du chiffrement hybride:", error);
        logText.textContent += `[ERROR] Erreur: ${error.message}\n`;
        outputText.value = "Erreur lors du chiffrement hybride: " + error.message;
    } finally {
        encryptBtn.disabled = false;
        encryptBtn.textContent = originalText;
    }
}

// Déchiffrer un message (hybride : RSA + Fernet)
async function decryptMessage() {
    const inputText = document.getElementById('decrypt-input');
    const outputText = document.getElementById('decrypt-output');
    const logText = document.getElementById('decrypt-log');
    const logSection = document.getElementById('decrypt-log-section');
    
    const text = inputText.value.trim();
    
    if (!text) {
        outputText.value = "";
        return;
    }
    
    if (!myPrivateKeyValue) {
        outputText.value = "Veuillez d'abord générer ou charger votre clé privée.";
        return;
    }
    
    const decryptBtn = document.getElementById('decrypt-btn');
    const originalText = decryptBtn.textContent;
    decryptBtn.disabled = true;
    decryptBtn.textContent = "Déchiffrement en cours...";
    outputText.value = "Déchiffrement en cours...";
    
    // Afficher les logs
    logText.textContent = "[INFO] Début du déchiffrement...\n";
    logSection.style.display = 'block';
    
    try {
        logText.textContent += `[INFO] Longueur des données chiffrées: ${text.length} caractères\n`;
        logText.textContent += `[INFO] Clé privée utilisée: ${myPrivateKeyName || 'Non nommée'}\n`;
        
        const startTime = Date.now();
        const result = await runPythonFunction('decrypt_hybrid', myPrivateKeyValue, text);
        const endTime = Date.now();
        
        logText.textContent += `[INFO] Déchiffrement terminé en ${endTime - startTime}ms\n`;
        
        if (result) {
            logText.textContent += `[SUCCESS] Message déchiffré avec succès!\n`;
            outputText.value = result;
        } else {
            throw new Error("Échec du déchiffrement hybride");
        }
    } catch (error) {
        console.error("Erreur lors du déchiffrement hybride:", error);
        logText.textContent += `[ERROR] Erreur: ${error.message}\n`;
        outputText.value = "Erreur lors du déchiffrement hybride: " + error.message;
    } finally {
        decryptBtn.disabled = false;
        decryptBtn.textContent = originalText;
    }
}

// ====================
// FONCTIONS UTILITAIRES
// ====================

// Télécharger une clé sous forme de fichier
function downloadKey(key, keyType) {
    if (!key || key.length === 0) {
        alert("Aucune clé à télécharger.");
        return;
    }
    
    if (keyType === 'public' && !key.startsWith("-----BEGIN PUBLIC KEY-----")) {
        alert("La clé publique n'est pas au format PEM valide.");
        return;
    }
    if (keyType === 'private' && !key.startsWith("-----BEGIN PRIVATE KEY-----")) {
        alert("La clé privée n'est pas au format PEM valide.");
        return;
    }
    
    const prefix = document.getElementById('key-prefix').value.trim() || "key";
    const name = `${prefix}_${keyType}_${new Date().toISOString().slice(0, 10)}`;
    
    // Mettre à jour le nom de la clé
    if (keyType === 'public') {
        myPublicKeyName = name;
    } else if (keyType === 'private') {
        myPrivateKeyName = name;
    }
    
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
function loadKeyFromFile(keyType, fileInputId) {
    const fileInput = document.getElementById(fileInputId);
    fileInput.onchange = function(event) {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = function(e) {
            const key = e.target.result.trim();
            
            if (keyType === 'public' && !key.startsWith("-----BEGIN PUBLIC KEY-----")) {
                alert("Le fichier chargé n'est pas une clé publique RSA valide (format PEM attendu).");
                fileInput.value = "";
                return;
            }
            if (keyType === 'private' && !key.startsWith("-----BEGIN PRIVATE KEY-----")) {
                alert("Le fichier chargé n'est pas une clé privée RSA valide (format PEM attendu).");
                fileInput.value = "";
                return;
            }
            
            if (keyType === 'public') {
                myPublicKeyValue = key;
                myPublicKeyName = file.name.replace('.key', '').replace('.txt', '');
            } else if (keyType === 'private') {
                myPrivateKeyValue = key;
                myPrivateKeyName = file.name.replace('.key', '').replace('.txt', '');
            }
            updateKeyStatus();
            
            // Activer les boutons de téléchargement
            document.getElementById('download-rsa-public-key-btn').disabled = !myPublicKeyValue;
            document.getElementById('download-rsa-private-key-btn').disabled = !myPrivateKeyValue;
            
            fileInput.value = "";
        };
        reader.readAsText(file);
    };
    fileInput.click();
}

// Effacer toutes les clés
function clearKeys() {
    if (confirm("Voulez-vous vraiment effacer toutes vos clés ?")) {
        myPublicKeyValue = "";
        myPrivateKeyValue = "";
        myPublicKeyName = "";
        myPrivateKeyName = "";
        interlocutorPublicKeyName = "";
        updateKeyStatus();
        document.getElementById('download-rsa-public-key-btn').disabled = true;
        document.getElementById('download-rsa-private-key-btn').disabled = true;
    }
}

// ====================
// GESTION DES ONGLETS PRINCIPAUX
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
// GESTION DES SOUS-ONGLETS (Gestion des clés)
// ====================

function setupSubTabs() {
    const subTabButtons = document.querySelectorAll('.sub-tab-button');
    const subTabContents = document.querySelectorAll('.sub-tab-content');

    subTabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const subTabId = button.dataset.subTab;

            subTabButtons.forEach(btn => btn.classList.remove('active'));
            subTabContents.forEach(content => content.classList.remove('active'));

            button.classList.add('active');
            document.getElementById(`${subTabId}-subtab`).classList.add('active');
        });
    });
}

// ====================
// FONCTIONS DE GESTION DES LOGS
// ====================

function setupLogToggles() {
    // Bouton pour afficher/masquer les logs de chiffrement
    const encryptToggleBtn = document.getElementById('encrypt-toggle-log-btn');
    const encryptLogSection = document.getElementById('encrypt-log-section');
    const encryptHideBtn = document.getElementById('encrypt-hide-log-btn');
    
    if (encryptToggleBtn && encryptLogSection) {
        encryptToggleBtn.addEventListener('click', () => {
            encryptLogSection.style.display = 'block';
            encryptToggleBtn.style.display = 'none';
        });
        
        if (encryptHideBtn) {
            encryptHideBtn.addEventListener('click', () => {
                encryptLogSection.style.display = 'none';
                encryptToggleBtn.style.display = 'inline-block';
            });
        }
    }
    
    // Bouton pour copier les logs de chiffrement
    const encryptCopyBtn = document.getElementById('encrypt-copy-log-btn');
    if (encryptCopyBtn) {
        encryptCopyBtn.addEventListener('click', () => {
            const logText = document.getElementById('encrypt-log');
            if (logText) {
                navigator.clipboard.writeText(logText.textContent)
                    .then(() => alert('Logs copiés dans le presse-papiers!'))
                    .catch(err => console.error('Erreur lors de la copie:', err));
            }
        });
    }
    
    // Bouton pour effacer les logs de chiffrement
    const encryptClearBtn = document.getElementById('encrypt-clear-log-btn');
    if (encryptClearBtn) {
        encryptClearBtn.addEventListener('click', () => {
            const logText = document.getElementById('encrypt-log');
            if (logText) {
                logText.textContent = '';
            }
        });
    }
    
    // Bouton pour afficher/masquer les logs de déchiffrement
    const decryptToggleBtn = document.getElementById('decrypt-toggle-log-btn');
    const decryptLogSection = document.getElementById('decrypt-log-section');
    const decryptHideBtn = document.getElementById('decrypt-hide-log-btn');
    
    if (decryptToggleBtn && decryptLogSection) {
        decryptToggleBtn.addEventListener('click', () => {
            decryptLogSection.style.display = 'block';
            decryptToggleBtn.style.display = 'none';
        });
        
        if (decryptHideBtn) {
            decryptHideBtn.addEventListener('click', () => {
                decryptLogSection.style.display = 'none';
                decryptToggleBtn.style.display = 'inline-block';
            });
        }
    }
    
    // Bouton pour copier les logs de déchiffrement
    const decryptCopyBtn = document.getElementById('decrypt-copy-log-btn');
    if (decryptCopyBtn) {
        decryptCopyBtn.addEventListener('click', () => {
            const logText = document.getElementById('decrypt-log');
            if (logText) {
                navigator.clipboard.writeText(logText.textContent)
                    .then(() => alert('Logs copiés dans le presse-papiers!'))
                    .catch(err => console.error('Erreur lors de la copie:', err));
            }
        });
    }
    
    // Bouton pour effacer les logs de déchiffrement
    const decryptClearBtn = document.getElementById('decrypt-clear-log-btn');
    if (decryptClearBtn) {
        decryptClearBtn.addEventListener('click', () => {
            const logText = document.getElementById('decrypt-log');
            if (logText) {
                logText.textContent = '';
            }
        });
    }
}

// ====================
// CONFIGURATION DES ÉCOUTEURS
// ====================

function setupEventListeners() {
    setupTabs();
    setupSubTabs();
    setupLogToggles();

    // Désactiver les boutons de téléchargement au chargement
    document.getElementById('download-rsa-public-key-btn').disabled = true;
    document.getElementById('download-rsa-private-key-btn').disabled = true;

    // Onglet Gestion des clés - Création de paire RSA
    document.getElementById('generate-rsa-keys-btn').addEventListener('click', generateRSAKeys);
    document.getElementById('download-rsa-public-key-btn').addEventListener('click', () => downloadKey(myPublicKeyValue, 'public'));
    document.getElementById('download-rsa-private-key-btn').addEventListener('click', () => downloadKey(myPrivateKeyValue, 'private'));

    // Onglet Gestion des clés - Chargement des clés
    document.getElementById('load-my-public-key-btn').addEventListener('click', () => loadKeyFromFile('public', 'file-input-my-public'));
    document.getElementById('load-my-private-key-btn').addEventListener('click', () => loadKeyFromFile('private', 'file-input-my-private'));
    document.getElementById('clear-keys-btn').addEventListener('click', clearKeys);
    document.getElementById('load-interlocutor-key-btn').addEventListener('click', loadInterlocutorKeyFromFile);

    // Onglet Chiffrement
    document.getElementById('encrypt-btn').addEventListener('click', encryptMessage);

    // Onglet Déchiffrement
    document.getElementById('decrypt-btn').addEventListener('click', decryptMessage);
}

// Initialiser au chargement
initializePyodide();
