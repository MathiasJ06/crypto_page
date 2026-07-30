from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import json

# Backend par défaut
backend = default_backend()


def generate_rsa_keys():
    """Génère une paire de clés RSA 2048 bits et retourne un JSON avec public_key et private_key"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=backend
    )
    public_key = private_key.public_key()
    
    # Sérialiser en PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Retourner sous forme de JSON pour une meilleure compatibilité avec Pyodide
    return json.dumps({"public_key": public_pem, "private_key": private_pem})


def encrypt_hybrid(public_key_pem, message):
    """
    Chiffre un message avec une clé publique RSA (chiffrement hybride Fernet + RSA).
    Args:
        public_key_pem: Clé publique RSA au format PEM (string)
        message: Message en clair (string)
    Returns:
        JSON string: {"encrypted_message": str, "encrypted_fernet_key": str}
    """
    # Générer une clé Fernet aléatoire
    fernet_key = Fernet.generate_key().decode('utf-8')
    
    # Chiffrer le message avec Fernet
    fernet = Fernet(fernet_key.encode('utf-8'))
    encrypted_message = fernet.encrypt(message.encode('utf-8')).decode('utf-8')
    
    # Charger la clé publique RSA
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    
    # Chiffrer la clé Fernet avec RSA-OAEP
    ciphertext = public_key.encrypt(
        fernet_key.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Retourner un JSON avec les données chiffrées
    result = {
        "encrypted_message": encrypted_message,
        "encrypted_fernet_key": base64.b64encode(ciphertext).decode('utf-8')
    }
    
    return json.dumps(result)


def decrypt_hybrid(private_key_pem, encrypted_data_json):
    """
    Déchiffre un message chiffré avec une clé privée RSA (chiffrement hybride).
    Args:
        private_key_pem: Clé privée RSA au format PEM (string)
        encrypted_data_json: JSON string avec "encrypted_message" et "encrypted_fernet_key"
    Returns:
        Message déchiffré (string) ou None en cas d'erreur
    """
    try:
        data = json.loads(encrypted_data_json)
        encrypted_message = data["encrypted_message"]
        encrypted_fernet_key_b64 = data["encrypted_fernet_key"]
        
        # Charger la clé privée RSA
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )
        
        # Déchiffrer la clé Fernet avec RSA-OAEP
        ciphertext = base64.b64decode(encrypted_fernet_key_b64.encode('utf-8'))
        fernet_key = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode('utf-8')
        
        # Déchiffrer le message avec Fernet
        fernet = Fernet(fernet_key.encode('utf-8'))
        decrypted_message = fernet.decrypt(encrypted_message.encode('utf-8')).decode('utf-8')
        
        return decrypted_message
        
    except Exception as e:
        print(f"Erreur lors du déchiffrement hybride: {e}")
        return None
