// Variables globales
let pyodide;
let isPyodideReady = false;
let pythonModuleLoaded = false;

// Stockage des clés
let myPublicKeyValue = "";
let myPrivateKeyValue = "";

// Liste des contacts (interlocuteurs) : { name: string, publicKey: string }
let contacts = [];

// Variable temporaire pour stocker la clé publique chargée avant d'ajouter un contact
let tempContactPublicKey = "";

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

        // Charger le package cryptography EN PREMIER
        await pyodide.loadPackage("cryptography");
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
            <p style="color: #e74c3c;">Erreur lors du chargement de Pyodide.</p>
            <button onclick="location.reload()">Recharger</button>
        `;
    }
}

// Charger les modules Python (Fernet + RSA)
async function loadPythonModules() {
    if (!isPyodideReady || pythonModuleLoaded) return;

    try {
        // Charger le module Fernet
        const fernetResponse = await fetch('generate_fernet_key.py');
        const fernetCode = await fernetResponse.text();
        await pyodide.runPythonAsync(fernetCode);
        
        // Charger le module RSA
        const rsaResponse = await fetch('rsa_functions.py');
        const rsaCode = await rsaResponse.text();
        await pyodide.runPythonAsync(rsaCode);
        
        pythonModuleLoaded = true;
        console.log("Modules Python (Fernet + RSA) chargés");
    } catch (error) {
        console.error("Erreur lors du chargement des modules Python :", error);
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
        console.log("Pyodide ou modules non prêts");
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
        throw error;
    }
}

// Mettre à jour l'affichage du statut des clés
function updateKeyStatus() {
    const publicKeyStatus = document.getElementById('public-key-status');
    const privateKeyStatus = document.getElementById('private-key-status');
    
    publicKeyStatus.textContent = myPublicKeyValue ? "✅ Chargée" : "❌ Non chargée";
    publicKeyStatus.className = myPublicKeyValue ? "ok" : "error";
    
    privateKeyStatus.textContent = myPrivateKeyValue ? "✅ Chargée" : "❌ Non chargée";
    privateKeyStatus.className = myPrivateKeyValue ? "ok" : "error";
}

// Mettre à jour la liste des contacts dans les selects
function updateContactsSelect() {
    const encryptSelect = document.getElementById('encrypt-contact-select');
    const decryptSelect = document.getElementById('decrypt-contact-select');
    
    let options = '<option value="">-- Sélectionner un interlocuteur --</option>';
    
    contacts.forEach((contact, index) => {
        options += `<option value="${index}">${contact.name}</option>`;
    });
    
    encryptSelect.innerHTML = options;
    decryptSelect.innerHTML = options;
}

// Mettre à jour l'affichage de la liste des contacts
function updateContactsList() {
    const contactsList = document.getElementById('contacts-list');
    contactsList.innerHTML = '';
    
    contacts.forEach((contact, index) => {
        const contactItem = document.createElement('div');
        contactItem.className = 'contact-item';
        
        const nameSpan = document.createElement('span');
        nameSpan.className = 'contact-name';
        nameSpan.textContent = contact.name;
        
        const statusSpan = document.createElement('span');
        statusSpan.className = 'contact-status';
        statusSpan.textContent = "✅";
        statusSpan.title = "Clé chargée";
        
        const removeBtn = document.createElement('button');
        removeBtn.className = 'remove-contact-btn';
        removeBtn.textContent = 'Supprimer';
        removeBtn.addEventListener('click', () => removeContact(index));
        
        contactItem.appendChild(nameSpan);
        contactItem.appendChild(statusSpan);
        contactItem.appendChild(removeBtn);
        contactsList.appendChild(contactItem);
    });
    
    updateContactsSelect();
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
        
        if (result && Array.isArray(result) && result.length === 2) {
            if (!result[0].startsWith("-----BEGIN PUBLIC KEY-----") || !result[1].startsWith("-----BEGIN PRIVATE KEY-----")) {
                throw new Error("Clés RSA mal formatées (en-tête PEM manquant)");
            }
            
            myPublicKeyValue = result[0];
            myPrivateKeyValue = result[1];
            updateKeyStatus();
            alert("Paire de clés RSA générée avec succès !");
        } else {
            throw new Error("Format de réponse invalide: " + JSON.stringify(result));
        }
    } catch (error) {
        console.error("Erreur lors de la génération RSA:", error);
        alert("Erreur lors de la génération des clés RSA: " + error.message);
    } finally {
        generateBtn.disabled = false;
        generateBtn.textContent = originalText;
    }
}

// ====================
// FONCTIONS DE GESTION DES CONTACTS
// ====================

// Ajouter un contact
function addContact() {
    const nameInput = document.getElementById('contact-name');
    const name = nameInput.value.trim();
    
    if (!name) {
        alert("Veuillez entrer un nom pour l'interlocuteur.");
        return;
    }
    
    if (!tempContactPublicKey) {
        alert("Veuillez d'abord charger une clé publique pour cet interlocuteur.");
        return;
    }
    
    if (!tempContactPublicKey.startsWith("-----BEGIN PUBLIC KEY-----")) {
        alert("La clé publique chargée n'est pas une clé RSA valide (format PEM attendu).");
        return;
    }
    
    // Vérifier si le contact existe déjà
    const existingContactIndex = contacts.findIndex(c => c.name === name);
    if (existingContactIndex !== -1) {
        if (confirm(`Un contact avec le nom "${name}" existe déjà. Voulez-vous le remplacer ?`)) {
            contacts[existingContactIndex].publicKey = tempContactPublicKey;
        }
    } else {
        contacts.push({ name, publicKey: tempContactPublicKey });
    }
    
    // Réinitialiser les champs
    nameInput.value = "";
    tempContactPublicKey = "";
    
    updateContactsList();
}

// Supprimer un contact
function removeContact(index) {
    if (confirm("Voulez-vous vraiment supprimer ce contact ?")) {
        contacts.splice(index, 1);
        updateContactsList();
    }
}

// Charger une clé de contact depuis un fichier
function loadContactKeyFromFile() {
    const fileInput = document.getElementById('file-input-contact');
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
            tempContactPublicKey = key;
            fileInput.value = "";
            alert("Clé publique RSA chargée. Cliquez sur 'Ajouter' pour enregistrer l'interlocuteur.");
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
    const contactSelect = document.getElementById('encrypt-contact-select');
    const inputText = document.getElementById('encrypt-input');
    const outputText = document.getElementById('encrypt-output');
    
    const selectedIndex = contactSelect.value;
    const text = inputText.value;
    
    if (!selectedIndex && selectedIndex !== "0") {
        outputText.value = "Veuillez sélectionner un interlocuteur.";
        return;
    }
    
    if (!text) {
        outputText.value = "";
        return;
    }
    
    const contact = contacts[parseInt(selectedIndex)];
    if (!contact || !contact.publicKey) {
        outputText.value = "Clé publique de l'interlocuteur introuvable.";
        return;
    }
    
    const encryptBtn = document.getElementById('encrypt-btn');
    const originalText = encryptBtn.textContent;
    encryptBtn.disabled = true;
    encryptBtn.textContent = "Chiffrement en cours...";
    outputText.value = "Chiffrement en cours...";
    
    try {
        const result = await runPythonFunction('encrypt_hybrid', contact.publicKey, text);
        if (!result) {
            throw new Error("Échec du chiffrement hybride");
        }
        
        // Ajouter le nom de l'interlocuteur au JSON
        const parsedResult = JSON.parse(result);
        parsedResult.from = contact.name;
        
        outputText.value = JSON.stringify(parsedResult, null, 2);
        
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
    const contactSelect = document.getElementById('decrypt-contact-select');
    const inputText = document.getElementById('decrypt-input');
    const outputText = document.getElementById('decrypt-output');
    
    const selectedIndex = contactSelect.value;
    const text = inputText.value.trim();
    
    if (!selectedIndex && selectedIndex !== "0") {
        outputText.value = "Veuillez sélectionner un interlocuteur.";
        return;
    }
    
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
    }
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

    // Onglet Gestion des clés
    document.getElementById('generate-rsa-keys-btn').addEventListener('click', generateRSAKeys);
    document.getElementById('download-my-public-key-btn').addEventListener('click', () => downloadKey(myPublicKeyValue, 'public'));
    document.getElementById('download-my-private-key-btn').addEventListener('click', () => downloadKey(myPrivateKeyValue, 'private'));
    document.getElementById('load-my-public-key-btn').addEventListener('click', () => loadKeyFromFile('public', 'file-input-my-public'));
    document.getElementById('load-my-private-key-btn').addEventListener('click', () => loadKeyFromFile('private', 'file-input-my-private'));
    document.getElementById('clear-keys-btn').addEventListener('click', clearKeys);

    // Gestion des contacts
    document.getElementById('add-contact-btn').addEventListener('click', addContact);
    document.getElementById('load-contact-key-btn').addEventListener('click', loadContactKeyFromFile);

    // Onglet Chiffrement
    document.getElementById('encrypt-btn').addEventListener('click', encryptMessage);

    // Onglet Déchiffrement
    document.getElementById('decrypt-btn').addEventListener('click', decryptMessage);
}

// Initialiser au chargement
initializePyodide();
