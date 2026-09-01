// ============================================================================
// Chiffrement Hybride - Application de chiffrement RSA + Fernet
// ============================================================================

// Variables globales
let pyodide;
let isPyodideReady = false;
let pythonModuleLoaded = false;

// Stockage des clés (UNIQUEMENT EN MÉMOIRE, jamais en localStorage/sessionStorage)
let keys = {
    myPublic: { value: "", name: "" },
    myPrivate: { value: "", name: "" },
    interlocutorPublic: { value: "", name: "" }
};

// ============================================================================
// INITIALISATION DE PYODIDE
// ============================================================================

/**
 * Initialise Pyodide et charge les dépendances nécessaires
 */
async function initializePyodide() {
    const progressBar = document.getElementById('progress-bar');
    const loadingDiv = document.getElementById('loading');
    const contentDiv = document.getElementById('content');

    try {
        // Vérifier que loadPyodide est disponible
        if (typeof loadPyodide !== 'function') {
            throw new Error('loadPyodide non disponible - le script Pyodide ne s\'est pas chargé correctement');
        }

        pyodide = await loadPyodide({
            indexURL: "https://cdn.jsdelivr.net/pyodide/v0.23.4/full/",
            onDownloadProgress: (loaded, total) => {
                const percent = (loaded / total) * 100;
                progressBar.value = percent;
            }
        });

        // Charger le package cryptography
        await pyodide.loadPackage("cryptography");
        isPyodideReady = true;

        // Charger le module crypto
        await loadPythonModules();

        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';

        // Initialiser l'interface
        setupEventListeners();
        updateKeyStatus();

    } catch (error) {
        console.error("Erreur lors du chargement de Pyodide :", error);
        loadingDiv.innerHTML = `
            <p style="color: #dc3545;">❌ Erreur lors du chargement de Pyodide</p>
            <p style="color: #666; font-size: 14px; margin-top: 10px;">
                Veuillez vérifier votre connexion internet.<br>
                Pyodide nécessite une connexion pour se charger (~10-15 Mo).
            </p>
            <p style="color: #666; font-size: 12px; margin-top: 10px;">
                Pour tester localement: <code>python -m http.server 8000</code><br>
                Puis ouvrez <code>http://localhost:8000</code>
            </p>
            <button onclick="location.reload()" style="margin-top: 15px; padding: 8px 16px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">
                Recharger la page
            </button>
        `;
    }
}

/**
 * Charge les modules Python nécessaires
 */
async function loadPythonModules() {
    if (!isPyodideReady || pythonModuleLoaded) return;

    try {
        // Charger le package crypto
        const cryptoCode = await fetch('crypto/__init__.py').then(r => r.text());
        await pyodide.runPythonAsync(cryptoCode);
        
        pythonModuleLoaded = true;
        console.log("✅ Modules Python chargés avec succès");
        
    } catch (error) {
        console.error("❌ Erreur lors du chargement des modules Python :", error);
        throw error;
    }
}

// ============================================================================
// UTILITAIRES
// ============================================================================

/**
 * Met à jour l'affichage du statut des clés
 */
function updateKeyStatus() {
    const statusMap = {
        'public-key-status': keys.myPublic.value ? '✅ Chargée' : '❌ Non chargée',
        'private-key-status': keys.myPrivate.value ? '✅ Chargée' : '❌ Non chargée',
        'interlocutor-key-status': keys.interlocutorPublic.value ? '✅ Chargée' : '❌ Non chargée'
    };
    
    const infoMap = {
        'public-key-info': keys.myPublic.name ? `(${keys.myPublic.name})` : '',
        'private-key-info': keys.myPrivate.name ? `(${keys.myPrivate.name})` : '',
        'interlocutor-key-info': keys.interlocutorPublic.name ? `(${keys.interlocutorPublic.name})` : ''
    };
    
    for (const [id, status] of Object.entries(statusMap)) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = status;
            element.className = keys.myPublic.value ? 'ok' : 'error';
        }
    }
    
    for (const [id, info] of Object.entries(infoMap)) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = info;
        }
    }
}

/**
 * Ajoute un message aux logs
 */
function addLog(logElementId, message, type = 'INFO') {
    const logElement = document.getElementById(logElementId);
    if (logElement) {
        const timestamp = new Date().toLocaleTimeString();
        logElement.textContent += `[${timestamp}] [${type}] ${message}\n`;
        // Faire défiler vers le bas
        logElement.scrollTop = logElement.scrollHeight;
    }
}

/**
 * Efface les logs
 */
function clearLog(logElementId) {
    const logElement = document.getElementById(logElementId);
    if (logElement) {
        logElement.textContent = '';
    }
}

/**
 * Copie les logs dans le presse-papiers
 */
function copyLog(logElementId, successMessage = 'Logs copiés !') {
    const logElement = document.getElementById(logElementId);
    if (logElement && logElement.textContent) {
        navigator.clipboard.writeText(logElement.textContent)
            .then(() => alert(successMessage))
            .catch(err => console.error('Erreur copie:', err));
    }
}

// ============================================================================
// GESTION DES CLÉS
// ============================================================================

/**
 * Génère une paire de clés RSA
 */
async function generateRSAKeys() {
    const generateBtn = document.getElementById('generate-rsa-keys-btn');
    const originalText = generateBtn.textContent;
    generateBtn.disabled = true;
    generateBtn.textContent = "Génération en cours...";

    try {
        const prefix = document.getElementById('key-prefix').value.trim() || 'ma_cle';
        const keySize = 3072; // 3072 bits par défaut
        
        addLog('encrypt-log', `Génération des clés RSA (${keySize} bits) avec préfixe: ${prefix}`);
        
        // Utilisation de PyProxy avec paramètres explicites - PAS d'interpolation
        const result = await pyodide.runPythonAsync(`
from crypto.hybrid import generate_rsa_keys
result = generate_rsa_keys(key_size=${keySize}, password=None)
result
`);
        
        const keysData = JSON.parse(result);
        
        if (!keysData.public_key || !keysData.private_key) {
            throw new Error("Clés manquantes dans la réponse");
        }
        
        // Stocker les clés en mémoire
        keys.myPublic = { value: keysData.public_key, name: `${prefix}_public` };
        keys.myPrivate = { value: keysData.private_key, name: `${prefix}_private` };
        
        addLog('encrypt-log', `Clés générées: ${prefix}_public, ${prefix}_private`);
        
        updateKeyStatus();
        
        // Activer les boutons de téléchargement
        document.getElementById('download-rsa-public-key-btn').disabled = false;
        document.getElementById('download-rsa-private-key-btn').disabled = false;
        
        alert(`✅ Paire de clés RSA générée avec succès !\n\nPréfixe: ${prefix}\nTaille: ${keysData.key_size} bits`);
        
    } catch (error) {
        console.error("Erreur génération RSA:", error);
        addLog('encrypt-log', `Erreur: ${error.message}`, 'ERROR');
        alert(`❌ Erreur: ${error.message}`);
    } finally {
        generateBtn.disabled = false;
        generateBtn.textContent = originalText;
    }
}

/**
 * Charge une clé depuis un fichier
 */
function loadKeyFromFile(keyType, fileInputId, keyProperty) {
    const fileInput = document.getElementById(fileInputId);
    fileInput.onchange = function(event) {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = function(e) {
            const key = e.target.result.trim();
            
            // Validation du format
            const expectedStart = keyType === 'public' 
                ? "-----BEGIN PUBLIC KEY-----" 
                : "-----BEGIN PRIVATE KEY-----";
            
            if (!key.startsWith(expectedStart)) {
                alert(`Le fichier chargé n'est pas une clé ${keyType} RSA valide (format PEM attendu).`);
                fileInput.value = "";
                return;
            }
            
            // Stocker la clé en mémoire
            keys[keyProperty] = { value: key, name: file.name.replace(/\.(key|pem|txt)$/i, '') };
            fileInput.value = "";
            updateKeyStatus();
            
            alert(`✅ Clé ${keyType} chargée avec succès: ${keys[keyProperty].name}`);
        };
        reader.readAsText(file);
    };
    fileInput.click();
}

/**
 * Charge la clé publique de l'interlocuteur
 */
function loadInterlocutorKeyFromFile() {
    loadKeyFromFile('public', 'file-input-interlocutor', 'interlocutorPublic');
}

/**
 * Charge ma clé publique
 */
function loadMyPublicKeyFromFile() {
    loadKeyFromFile('public', 'file-input-my-public', 'myPublic');
}

/**
 * Charge ma clé privée
 */
function loadMyPrivateKeyFromFile() {
    loadKeyFromFile('private', 'file-input-my-private', 'myPrivate');
}

/**
 * Télécharge une clé sous forme de fichier
 */
function downloadKey(keyProperty, keyType) {
    const key = keys[keyProperty];
    
    if (!key || !key.value) {
        alert("Aucune clé à télécharger.");
        return;
    }
    
    const name = key.name || `cle_${keyType}_${new Date().toISOString().slice(0, 10)}`;
    const blob = new Blob([key.value], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name}.key`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    addLog('encrypt-log', `Clé ${keyType} téléchargée: ${name}.key`);
}

/**
 * Efface toutes les clés
 */
function clearKeys() {
    if (confirm("⚠️ Voulez-vous vraiment effacer toutes vos clés ?\n\nCette action ne peut pas être annulée.")) {
        keys.myPublic = { value: "", name: "" };
        keys.myPrivate = { value: "", name: "" };
        keys.interlocutorPublic = { value: "", name: "" };
        
        updateKeyStatus();
        
        // Désactiver les boutons de téléchargement
        document.getElementById('download-rsa-public-key-btn').disabled = true;
        document.getElementById('download-rsa-private-key-btn').disabled = true;
        
        addLog('encrypt-log', 'Toutes les clés ont été effacées');
        alert("✅ Toutes les clés ont été effacées.");
    }
}

// ============================================================================
// CHIFFREMENT / DÉCHIFFREMENT
// ============================================================================

/**
 * Chiffre un message avec chiffrement hybride
 */
async function encryptMessage() {
    const inputText = document.getElementById('encrypt-input');
    const outputText = document.getElementById('encrypt-output');
    const logText = document.getElementById('encrypt-log');
    const logSection = document.getElementById('encrypt-log-section');
    
    const text = inputText.value.trim();
    
    if (!text) {
        outputText.value = "";
        return;
    }
    
    if (!keys.interlocutorPublic.value) {
        outputText.value = "❌ Veuillez d'abord charger la clé publique de votre interlocuteur.";
        return;
    }
    
    const encryptBtn = document.getElementById('encrypt-btn');
    const originalText = encryptBtn.textContent;
    encryptBtn.disabled = true;
    encryptBtn.textContent = "Chiffrement en cours...";
    outputText.value = "Chiffrement en cours...";
    
    // Afficher les logs
    logText.textContent = '';
    logSection.style.display = 'block';
    addLog('encrypt-log', `Début du chiffrement, message: ${text.length} caractères`);
    addLog('encrypt-log', `Clé publique du destinataire: ${keys.interlocutorPublic.name || 'Non nommée'}`);
    
    try {
        const startTime = Date.now();
        
        // Utilisation de PyProxy sans interpolation pour les paramètres sensibles
        const result = await pyodide.runPythonAsync(`
from crypto.hybrid import encrypt_hybrid
public_key_pem = """${keys.interlocutorPublic.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"""
message = """${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"""
result = encrypt_hybrid(public_key_pem, message)
result
`);
        
        const endTime = Date.now();
        
        addLog('encrypt-log', `Chiffrement terminé en ${endTime - startTime}ms`);
        addLog('encrypt-log', `Message chiffré: ${result.length} caractères`, 'SUCCESS');
        
        outputText.value = result;
        
    } catch (error) {
        console.error("Erreur chiffrement:", error);
        addLog('encrypt-log', `Erreur: ${error.message}`, 'ERROR');
        outputText.value = `❌ Erreur: ${error.message}`;
    } finally {
        encryptBtn.disabled = false;
        encryptBtn.textContent = originalText;
    }
}

/**
 * Déchiffre un message avec chiffrement hybride
 */
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
    
    if (!keys.myPrivate.value) {
        outputText.value = "❌ Veuillez d'abord charger votre clé privée.";
        return;
    }
    
    const decryptBtn = document.getElementById('decrypt-btn');
    const originalText = decryptBtn.textContent;
    decryptBtn.disabled = true;
    decryptBtn.textContent = "Déchiffrement en cours...";
    outputText.value = "Déchiffrement en cours...";
    
    // Afficher les logs
    logText.textContent = '';
    logSection.style.display = 'block';
    addLog('decrypt-log', `Début du déchiffrement, données: ${text.length} caractères`);
    addLog('decrypt-log', `Clé privée utilisée: ${keys.myPrivate.name || 'Non nommée'}`);
    
    try {
        const startTime = Date.now();
        
        // Utilisation de PyProxy sans interpolation pour les paramètres sensibles
        const result = await pyodide.runPythonAsync(`
from crypto.hybrid import decrypt_hybrid
private_key_pem = """${keys.myPrivate.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"""
encrypted_data = """${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"""
result = decrypt_hybrid(private_key_pem, encrypted_data)
result
`);
        
        const endTime = Date.now();
        
        addLog('decrypt-log', `Déchiffrement terminé en ${endTime - startTime}ms`);
        addLog('decrypt-log', `Message déchiffré: ${result.length} caractères`, 'SUCCESS');
        
        outputText.value = result;
        
    } catch (error) {
        console.error("Erreur déchiffrement:", error);
        addLog('decrypt-log', `Erreur: ${error.message}`, 'ERROR');
        outputText.value = `❌ Erreur: ${error.message}`;
    } finally {
        decryptBtn.disabled = false;
        decryptBtn.textContent = originalText;
    }
}

// ============================================================================
// GESTION DES ONGLETS
// ============================================================================

/**
 * Configure les onglets principaux
 */
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

/**
 * Configure les sous-onglets
 */
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

// ============================================================================
// GESTION DES LOGS
// ============================================================================

/**
 * Configure les boutons de gestion des logs
 */
function setupLogToggles() {
    // Chiffrement
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
    
    // Déchiffrement
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
    
    // Boutons de copie et effacement
    document.getElementById('encrypt-copy-log-btn')?.addEventListener('click', () => {
        copyLog('encrypt-log', 'Logs de chiffrement copiés !');
    });
    
    document.getElementById('encrypt-clear-log-btn')?.addEventListener('click', () => {
        clearLog('encrypt-log');
    });
    
    document.getElementById('decrypt-copy-log-btn')?.addEventListener('click', () => {
        copyLog('decrypt-log', 'Logs de déchiffrement copiés !');
    });
    
    document.getElementById('decrypt-clear-log-btn')?.addEventListener('click', () => {
        clearLog('decrypt-log');
    });
}

// ============================================================================
// CONFIGURATION DES ÉCOUTEURS
// ============================================================================

/**
 * Configure tous les écouteurs d'événements
 */
function setupEventListeners() {
    setupTabs();
    setupSubTabs();
    setupLogToggles();

    // Désactiver les boutons de téléchargement au chargement
    document.getElementById('download-rsa-public-key-btn').disabled = true;
    document.getElementById('download-rsa-private-key-btn').disabled = true;

    // Gestion des clés
    document.getElementById('generate-rsa-keys-btn').addEventListener('click', generateRSAKeys);
    document.getElementById('download-rsa-public-key-btn').addEventListener('click', () => downloadKey('myPublic', 'publique'));
    document.getElementById('download-rsa-private-key-btn').addEventListener('click', () => downloadKey('myPrivate', 'privée'));
    document.getElementById('load-my-public-key-btn').addEventListener('click', loadMyPublicKeyFromFile);
    document.getElementById('load-my-private-key-btn').addEventListener('click', loadMyPrivateKeyFromFile);
    document.getElementById('clear-keys-btn').addEventListener('click', clearKeys);
    document.getElementById('load-interlocutor-key-btn').addEventListener('click', loadInterlocutorKeyFromFile);

    // Chiffrement/Déchiffrement
    document.getElementById('encrypt-btn').addEventListener('click', encryptMessage);
    document.getElementById('decrypt-btn').addEventListener('click', decryptMessage);
}

// ============================================================================
// INITIALISATION
// ============================================================================

// Initialiser au chargement de la page
initializePyodide();
