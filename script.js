document.getElementById('generate-key-btn').addEventListener('click', generateKey);
document.getElementById('copy-btn').addEventListener('click', copyKey);

function generateKey() {
    // Génère une clé Fernet en JavaScript
    const key = Fernet.generateKey();
    document.getElementById('key-output').value = key;
}

function copyKey() {
    const keyOutput = document.getElementById('key-output');
    keyOutput.select();
    document.execCommand('copy');
    alert('Clé copiée dans le presse-papiers !');
}