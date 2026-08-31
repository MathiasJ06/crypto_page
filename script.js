// Variables globales
let pyodide;
let isPyodideReady = false;
let pythonModuleLoaded = false;

// Stockage des clés
let myPublicKeyValue = "";
let myPrivateKeyValue = "";
let interlocutorPublicKeyValue = "";

// Initialiser Pyodide
async function initializePyodide() {
    const progressBar = document.getElementById('progress-bar');
    const loadingDiv = document.getElementById('loading');
    const contentDiv = document.getElementById('content');

    try {
        pyodide = await loadPyodide({
            indexURL: "https://cdn.jsdelivr.net/pyodide/v0.25.0/full/",
            onDownloadProgress: (loaded, total) => {
                const percent = (loaded / total) * 100;
                progressBar.value = percent;
            }
        });

        // Charger le package cryptography EN PREMIER
        console.log("Chargement du package cryptography...");
        await pyodide.loadPackage("cryptography");
        console.log("Package cryptography chargé avec succès");
        
        // Charger le package json (nécessaire pour les fonctions Python)
        console.log("Chargement du package json...");
        await pyodide.loadPackage(["json", "base64"]);
        console.log("Packages json et base64 chargés avec succès");
        isPyodideReady = true;

        // Charger les modules Python (Fernet + RSA)
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
                Veuillez vérifier votre connexion internet et autoriser le chargement des scripts externes.
                Pyodide nécessite une connexion internet pour se charger (environ 10-15 Mo).
            </p>
            <button onclick="location.reload()" style="margin-top: 15px;">Recharger la page</button>
        `;
    }
}

// Charger les modules Python (Fernet + RSA)
async function loadPythonModules() {
    if (!isPyodideReady || pythonModuleLoaded) return;

    try {
        // Charger le module complet qui contient tout le code nécessaire
        const completeResponse = await fetch('crypto_complete.py');
        const completeCode = await completeResponse.text();
        console.log("Chargement de crypto_complete.py...");
        await pyodide.runPythonAsync(completeCode);
        console.log("crypto_complete.py chargé avec succès");
        
        pythonModuleLoaded = true;
        console.log("Modules Python (Fernet + RSA + Security) chargés");
        console.log("Vérification: generate_rsa_keys est-elle définie ?");
        try {
            const testResult = await pyodide.runPythonAsync("callable(generate_rsa_keys)");
            console.log("generate_rsa_keys est définie:", testResult);
        } catch (e) {
            console.error("Erreur lors de la vérification de generate_rsa_keys:", e);
        }
        
        // Vérification supplémentaire des fonctions disponibles
        try {
            const functions = await pyodide.runPythonAsync(
                "[name for name in dir() if callable(globals().get(name)) and not name.startswith('_')]"
            );
            console.log("Fonctions Python disponibles:", functions);
        } catch (e) {
            console.error("Erreur lors de la liste des fonctions:", e);
        }
    } catch (error) {
        console.error("Erreur lors du chargement des modules Python :", error);
        throw error; // Propager l'erreur pour bloquer le chargement
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
        console.log("isPyodideReady:", isPyodideReady, "pythonModuleLoaded:", pythonModuleLoaded);
        const result = await runPythonFunction('generate_rsa_keys');
        
        console.log("Résultat brut de generate_rsa_keys:", result);
        console.log("Type du résultat:", typeof result);
        
        if (!result) {
            throw new Error("Aucun résultat retourné (result est null/undefined)");
        }
        
        // Parser le JSON retourné par Python
        let keys;
        try {
            keys = JSON.parse(result);
        } catch (e) {
            console.error("Erreur de parsing JSON:", e);
            console.error("Résultat non parsable:", result);
            throw new Error("Le résultat n'est pas un JSON valide: " + result);
        }
        
        if (!keys.public_key || !keys.private_key) {
            throw new Error("Clés manquantes dans la réponse: " + JSON.stringify(keys));
        }
        
        if (!keys.public_key.startsWith("-----BEGIN PUBLIC KEY-----") || !keys.private_key.startsWith("-----BEGIN PRIVATE KEY-----")) {
            throw new Error("Clés RSA mal formatées (en-tête PEM manquant)");
        }
        
        console.log("Clés RSA valides générées !");
        myPublicKeyValue = keys.public_key;
        myPrivateKeyValue = keys.private_key;
        updateKeyStatus();
        
        // Activer les boutons de téléchargement des clés (dans le sous-onglet Création RSA)
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
    
    const text = inputText.value;
    
    if (!text) {
        outputText.value = "";
        return;
    }
    
    if (!interlocutorPublicKeyValue) {
        outputText.value = "Veuillez d'abord charger la clé publique de votre interlocuteur.";
        return;
    }
    
    if (!myPrivateKeyValue) {
        outputText.value = "Veuillez d'abord générer ou charger votre clé privée.";
        return;
    }
    
    const encryptBtn = document.getElementById('encrypt-btn');
    const originalText = encryptBtn.textContent;
    encryptBtn.disabled = true;
    encryptBtn.textContent = "Chiffrement en cours...";
    outputText.value = "Chiffrement en cours...";
    
    try {
        const result = await runPythonFunction('encrypt_hybrid', interlocutorPublicKeyValue, text);
        if (!result) {
            throw new Error("Échec du chiffrement hybride");
        }
        
        // Parser le JSON retourné par Python
        let encryptedData;
        try {
            encryptedData = JSON.parse(result);
        } catch (e) {
            throw new Error("Résultat du chiffrement invalide: " + result);
        }
        
        outputText.value = JSON.stringify(encryptedData, null, 2);
        
    } catch (error) {
        console.error("Erreur lors du chiffrement hybride:", error);
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
    
    try {
        const result = await runPythonFunction('decrypt_hybrid', myPrivateKeyValue, text);
        if (result) {
            outputText.value = result;
        } else {
            throw new Error("Échec du déchiffrement hybride (clé ou message invalide)");
        }
    } catch (error) {
        console.error("Erreur lors du déchiffrement hybride:", error);
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
            } else if (keyType === 'private') {
                myPrivateKeyValue = key;
            }
            updateKeyStatus();
            
            // Activer les boutons de téléchargement dans le sous-onglet Création RSA
            if (myPublicKeyValue || myPrivateKeyValue) {
                document.getElementById('download-rsa-public-key-btn').disabled = !myPublicKeyValue;
                document.getElementById('download-rsa-private-key-btn').disabled = !myPrivateKeyValue;
            }
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
        updateKeyStatus();
        // Désactiver les boutons de téléchargement des clés
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
// CONFIGURATION DES ÉCOUTEURS
// ====================

function setupEventListeners() {
    setupTabs();
    setupSubTabs();

    // Désactiver les boutons de téléchargement des clés au chargement
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
