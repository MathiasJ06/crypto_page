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

        // Charger le module Python (Fernet)
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

// Charger le module Python (Fernet)
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

// Executer du code Python
async function runPythonCode(code) {
    if (!isPyodideReady) {
        console.log("Pyodide non pret");
        return null;
    }

    try {
        const result = await pyodide.runPythonAsync(code);
        return result;
    } catch (error) {
        console.error("Erreur dans l'exécution Python :", error);
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

// Générer une paire de clés RSA (version corrigée et isolée)
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
        console.log("=== Début génération RSA ===");
        
        // Code Python MINIMAL pour générer une paire RSA
        const pythonCode = `
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

backend = default_backend()
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=backend
)
public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

(public_pem, private_pem)
`;
        
        console.log("Exécution du code RSA...");
        const result = await runPythonCode(pythonCode);
        console.log("Résultat brut :", result);
        
        if (!result) {
            throw new Error("Aucun résultat retourné par Pyodide");
        }
        
        // Vérifier que le résultat est un tableau avec 2 éléments
        if (!Array.isArray(result) || result.length !== 2) {
            console.error("Format inattendu. Type:", typeof result, "Longueur:", result ? result.length : 'N/A');
            throw new Error(`Format de réponse invalide. Type: ${typeof result}, Valeur: ${JSON.stringify(result)}`);
        }
        
        // Vérifier que les clés ne sont pas vides
        if (!result[0] || !result[1]) {
            throw new Error("Une ou plusieurs clés sont vides");
        }
        
        // Vérifier que les clés commencent par les en-têtes PEM
        if (!result[0].startsWith("-----BEGIN PUBLIC KEY-----") || !result[1].startsWith("-----BEGIN PRIVATE KEY-----")) {
            console.error("Clés mal formatées. Public:", result[0].substring(0, 50));
            console.error("Clés mal formatées. Private:", result[1].substring(0, 50));
            throw new Error("Clés RSA mal formatées (en-tête PEM manquant)");
        }
        
        console.log("Clés RSA valides générées !");
        myPublicKeyValue = result[0];
        myPrivateKeyValue = result[1];
        updateKeyStatus();
        alert("Paire de clés RSA générée avec succès !");
        
    } catch (error) {
        console.error("=== ERREUR RSA ===", error);
        alert("Erreur lors de la génération des clés RSA.\n\nDétails: " + error.message + "\n\nVérifiez la console (F12) pour plus d'informations.");
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
    
    // Vérifier que la clé commence par l'en-tête PEM
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
        // Générer une clé Fernet aléatoire
        const fernetKeyResult = await runPythonCode('generate_key()');
        if (!fernetKeyResult) {
            throw new Error("Échec de la génération de la clé Fernet");
        }
        const fernetKey = fernetKeyResult;
        
        // Chiffrer le message avec la clé Fernet
        const escapedText = escapeForPython(text);
        const encryptedMessage = await runPythonCode(`encrypt_message("${fernetKey}", """${escapedText}""")`);
        if (!encryptedMessage) {
            throw new Error("Échec du chiffrement du message");
        }
        
        // Chiffrer la clé Fernet avec la clé publique RSA de l'interlocuteur
        const escapedFernetKey = escapeForPython(fernetKey);
        const escapedPublicKey = escapeForPython(contact.publicKey);
        
        const encryptedFernetKey = await runPythonCode(`
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

public_key_pem = """${escapedPublicKey}"""
public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

fernet_key = "${escapedFernetKey}".encode('utf-8')

ciphertext = public_key.encrypt(
    fernet_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

base64.b64encode(ciphertext).decode('utf-8')
`);
        
        if (!encryptedFernetKey) {
            throw new Error("Échec du chiffrement de la clé Fernet");
        }
        
        // Retourner un objet JSON
        const result = JSON.stringify({
            from: contact.name,
            encrypted_message: encryptedMessage,
            encrypted_fernet_key: encryptedFernetKey
        }, null, 2);
        
        outputText.value = result;
        
    } catch (error) {
        console.error("Erreur lors du chiffrement hybride :", error);
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
        // Parser le JSON
        let parsed;
        try {
            parsed = JSON.parse(text);
        } catch (e) {
            outputText.value = "Format de message invalide. Attendu un JSON avec 'encrypted_message' et 'encrypted_fernet_key'.";
            return;
        }
        
        const encryptedMessage = parsed.encrypted_message;
        const encryptedFernetKey = parsed.encrypted_fernet_key;
        
        if (!encryptedMessage || !encryptedFernetKey) {
            outputText.value = "Message invalide : 'encrypted_message' ou 'encrypted_fernet_key' manquant.";
            return;
        }
        
        // Déchiffrer la clé Fernet avec la clé privée RSA
        const escapedEncryptedFernetKey = escapeForPython(encryptedFernetKey);
        const escapedPrivateKey = escapeForPython(myPrivateKeyValue);
        
        const fernetKey = await runPythonCode(`
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

private_key_pem = """${escapedPrivateKey}"""
private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)

ciphertext = base64.b64decode("${escapedEncryptedFernetKey}".encode('utf-8'))

fernet_key = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

fernet_key.decode('utf-8')
`);
        
        if (!fernetKey) {
            throw new Error("Échec du déchiffrement de la clé Fernet");
        }
        
        // Déchiffrer le message avec la clé Fernet
        const escapedEncryptedMessage = escapeForPython(encryptedMessage);
        const decryptedMessage = await runPythonCode(`decrypt_message("${fernetKey}", """${escapedEncryptedMessage}""")`);
        
        if (decryptedMessage) {
            outputText.value = decryptedMessage;
        } else {
            throw new Error("Échec du déchiffrement du message");
        }
        
    } catch (error) {
        console.error("Erreur lors du déchiffrement hybride :", error);
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
    
    // Vérifier que la clé est au format PEM
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
            
            // Vérifier le format PEM
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
