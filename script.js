// Variables globales
let pyodide;
let isPyodideReady = false;

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

// Générer une clé Fernet
async function generateKey() {
    if (!isPyodideReady) {
        alert("Pyodide n'est pas encore prêt. Veuillez patienter...");
        return;
    }

    const keyOutput = document.getElementById('key-output');
    keyOutput.value = "Génération en cours..."; 

    try {
        // Exécuter du code Python pour générer une clé Fernet
        const pythonCode = `
from cryptography.fernet import Fernet
key = Fernet.generate_key()
key.decode('utf-8')  # Convertir en chaîne pour JavaScript
        `;

        const key = await pyodide.runPythonAsync(pythonCode);
        keyOutput.value = key;
    } catch (error) {
        console.error("Erreur lors de la génération de la clé :", error);
        keyOutput.value = "Erreur lors de la génération de la clé. Voir la console.";
    }
}

// Copier la clé dans le presse-papiers
function copyKey() {
    const keyOutput = document.getElementById('key-output');
    if (!keyOutput.value) {
        alert("Aucune clé à copier !");
        return;
    }

    keyOutput.select();
    document.execCommand('copy');
    alert("Clé copiée dans le presse-papiers !");
}

// Effacer la clé
function clearKey() {
    document.getElementById('key-output').value = "";
}

// Événements
document.getElementById('generate-key-btn').addEventListener('click', generateKey);
document.getElementById('copy-btn').addEventListener('click', copyKey);
document.getElementById('clear-btn').addEventListener('click', clearKey);

// Initialiser Pyodide au chargement de la page
initializePyodide();