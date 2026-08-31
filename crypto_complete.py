"""
Module complet pour le chiffrement hybride (Fernet + RSA) pour Pyodide.

Ce module combine tout le code nécessaire sans imports entre fichiers locaux.
Toutes les dépendances externes (cryptography) sont chargées via Pyodide.

Fonctions exposées au niveau global pour JavaScript :
- generate_rsa_keys()
- encrypt_hybrid(public_key_pem, message)
- decrypt_hybrid(private_key_pem, encrypted_data_json)
"""

# ============================================================================
# IMPORTS EXTERNES (doivent être chargés via Pyodide.loadPackage)
# ============================================================================

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
import base64
import json
import os
import re
import time


# ============================================================================
# CONSTANTES
# ============================================================================

MIN_RSA_KEY_SIZE = 2048
RECOMMENDED_RSA_KEY_SIZE = 3072
FERNET_KEY_SIZE = 32
backend = default_backend()


# ============================================================================
# PARTIE 1: UTILITAIRES DE SÉCURITÉ (anciennement security_utils.py)
# ============================================================================

def validate_rsa_public_key_pem(public_key_pem: str) -> bool:
    """Valide qu'une clé publique RSA est au format PEM correct."""
    if not isinstance(public_key_pem, str):
        return False
    if not public_key_pem.strip().startswith("-----BEGIN PUBLIC KEY-----"):
        return False
    if not public_key_pem.strip().endswith("-----END PUBLIC KEY-----"):
        return False
    try:
        pem_content = re.sub(
            r'-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s+',
            '',
            public_key_pem.strip()
        )
        base64.b64decode(pem_content)
    except (ValueError, TypeError):
        return False
    return True


def validate_rsa_private_key_pem(private_key_pem: str) -> bool:
    """Valide qu'une clé privée RSA est au format PEM correct."""
    if not isinstance(private_key_pem, str):
        return False
    if not private_key_pem.strip().startswith("-----BEGIN PRIVATE KEY-----"):
        return False
    if not private_key_pem.strip().endswith("-----END PRIVATE KEY-----"):
        return False
    try:
        pem_content = re.sub(
            r'-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\\s+',
            '',
            private_key_pem.strip()
        )
        base64.b64decode(pem_content)
    except (ValueError, TypeError):
        return False
    return True


def validate_fernet_key(fernet_key):
    """Valide qu'une clé Fernet est au format correct."""
    if isinstance(fernet_key, str):
        fernet_key = fernet_key.encode('utf-8')
    if not isinstance(fernet_key, bytes):
        return False
    if len(fernet_key) != FERNET_KEY_SIZE:
        return False
    try:
        decoded = base64.urlsafe_b64decode(fernet_key)
        if len(decoded) != FERNET_KEY_SIZE:
            return False
    except (ValueError, TypeError):
        pass
    return True


def generate_nonce(size: int = 16) -> str:
    """Génère un nonce unique."""
    nonce = os.urandom(size)
    return base64.urlsafe_b64encode(nonce).decode('utf-8').rstrip('=')


def get_rsa_key_size_from_pem(private_key_pem: str) -> int:
    """Extrait la taille de la clé RSA à partir d'une clé privée PEM."""
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        return private_key.key_size
    except Exception:
        return -1


def is_rsa_key_size_secure(key_size: int) -> bool:
    """Vérifie si la taille d'une clé RSA est sécurisée."""
    return key_size >= MIN_RSA_KEY_SIZE


def derive_fernet_key_from_password(
    password: str,
    salt: bytes = None,
    iterations: int = 100_000
) -> str:
    """Dérive une clé Fernet à partir d'un mot de passe."""
    if not password or len(password) < 8:
        raise ValueError("Le mot de passe doit contenir au moins 8 caractères.")
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=FERNET_KEY_SIZE,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    derived_key = kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(derived_key).decode('utf-8')


# ============================================================================
# PARTIE 2: FONCTIONS FERNET (anciennement generate_fernet_key.py)
# ============================================================================

def generate_key() -> str:
    """Génère une nouvelle clé Fernet aléatoire."""
    key = Fernet.generate_key()
    return key.decode('utf-8')


def generate_key_from_password(
    password: str,
    salt: bytes = None,
    iterations: int = 100_000
) -> str:
    """Génère une clé Fernet à partir d'un mot de passe."""
    return derive_fernet_key_from_password(password, salt, iterations)


def encrypt_message(key_str: str, message: str) -> str:
    """Chiffre un message avec une clé Fernet."""
    if not key_str or not isinstance(key_str, str):
        raise ValueError("La clé Fernet est manquante ou invalide.")
    if not validate_fernet_key(key_str):
        raise ValueError("La clé Fernet n'est pas valide.")
    if not message or not isinstance(message, str):
        raise ValueError("Le message est manquant ou invalide.")
    key = key_str.encode('utf-8')
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode('utf-8'))
    return encrypted.decode('utf-8')


def decrypt_message(key_str: str, encrypted_message: str):
    """Déchiffre un message avec une clé Fernet."""
    try:
        if not key_str or not isinstance(key_str, str):
            return None
        if not validate_fernet_key(key_str):
            return None
        if not encrypted_message or not isinstance(encrypted_message, str):
            return None
        key = key_str.encode('utf-8')
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_message.encode('utf-8'))
        return decrypted.decode('utf-8')
    except (InvalidToken, ValueError, TypeError):
        return None


# ============================================================================
# PARTIE 3: FONCTIONS RSA HYBRIDES (anciennement rsa_functions.py)
# ============================================================================

def generate_rsa_keys(
    key_size: int = RECOMMENDED_RSA_KEY_SIZE,
    password: str = None
) -> str:
    """
    Génère une paire de clés RSA.
    Retourne un JSON avec public_key, private_key et key_size.
    """
    if key_size < MIN_RSA_KEY_SIZE:
        raise ValueError(
            f"La taille de la clé RSA doit être >= {MIN_RSA_KEY_SIZE} bits. "
            f"Recommandé: {RECOMMENDED_RSA_KEY_SIZE} bits."
        )
    if password and len(password) < 8:
        raise ValueError("Le mot de passe doit contenir au moins 8 caractères.")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=backend
    )
    public_key = private_key.public_key()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    encryption_algorithm = (
        BestAvailableEncryption(password.encode('utf-8'))
        if password
        else NoEncryption()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    ).decode('utf-8')
    
    return json.dumps({
        "public_key": public_pem,
        "private_key": private_pem,
        "key_size": key_size
    })


def encrypt_hybrid(
    public_key_pem: str,
    message: str,
    include_nonce: bool = True
) -> str:
    """
    Chiffre un message avec chiffrement hybride (Fernet + RSA).
    Retourne un JSON avec encrypted_message, encrypted_fernet_key, nonce, timestamp.
    """
    if not public_key_pem or not isinstance(public_key_pem, str):
        raise ValueError("La clé publique RSA est manquante ou invalide.")
    if not validate_rsa_public_key_pem(public_key_pem):
        raise ValueError("La clé publique RSA n'est pas au format PEM valide.")
    if not message or not isinstance(message, str):
        raise ValueError("Le message est manquant ou invalide.")
    
    # Générer une clé Fernet aléatoire
    fernet_key = Fernet.generate_key()
    
    # Chiffrer le message avec Fernet
    fernet = Fernet(fernet_key)
    encrypted_message = fernet.encrypt(message.encode('utf-8')).decode('utf-8')
    
    # Charger la clé publique RSA
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=backend
    )
    
    # Chiffrer la clé Fernet avec RSA-OAEP
    ciphertext = public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    result = {
        "encrypted_message": encrypted_message,
        "encrypted_fernet_key": base64.b64encode(ciphertext).decode('utf-8'),
    }
    
    if include_nonce:
        result["nonce"] = generate_nonce()
    
    result["timestamp"] = int(time.time())
    
    # Encoder tout le JSON en Base64 pour rendre le format illisible
    json_data = json.dumps(result)
    return base64.b64encode(json_data.encode('utf-8')).decode('utf-8')


def decrypt_hybrid(
    private_key_pem: str,
    encrypted_data_json: str,
    password: str = None,
    max_age_seconds: int = 3600
) -> str:
    """
    Déchiffre un message chiffré avec chiffrement hybride.
    """
    try:
        if not private_key_pem or not isinstance(private_key_pem, str):
            raise ValueError("La clé privée RSA est manquante ou invalide.")
        if not validate_rsa_private_key_pem(private_key_pem):
            raise ValueError("La clé privée RSA n'est pas au format PEM valide.")
        if not encrypted_data_json or not isinstance(encrypted_data_json, str):
            raise ValueError("Les données chiffrées sont manquantes ou invalides.")
        
        # Décoder le Base64 d'abord (le message est encodé en Base64)
        try:
            json_data = base64.b64decode(encrypted_data_json.encode('utf-8')).decode('utf-8')
            data = json.loads(json_data)
        except (ValueError, json.JSONDecodeError, TypeError) as e:
            raise ValueError("Les données chiffrées ne sont pas au format valide.")
        
        # Vérifier les champs obligatoires
        if "encrypted_message" not in data or "encrypted_fernet_key" not in data:
            raise ValueError(
                "Les données chiffrées doivent contenir 'encrypted_message' et 'encrypted_fernet_key'."
            )
        
        encrypted_message = data["encrypted_message"]
        encrypted_fernet_key_b64 = data["encrypted_fernet_key"]
        
        # Vérifier l'âge du message
        if max_age_seconds is not None and "timestamp" in data:
            current_time = int(time.time())
            message_time = data["timestamp"]
            if current_time - message_time > max_age_seconds:
                raise ValueError(
                    f"Le message est trop ancien (âge: {current_time - message_time} secondes). "
                    f"Seuls les messages de moins de {max_age_seconds} secondes sont acceptés."
                )
        
        # Charger la clé privée RSA
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=password.encode('utf-8') if password else None,
            backend=backend
        )
        
        # Vérifier la taille de la clé RSA
        key_size = private_key.key_size
        if not is_rsa_key_size_secure(key_size):
            raise ValueError(
                f"La taille de la clé RSA ({key_size} bits) est insuffisante. "
                f"Minimum requis: {MIN_RSA_KEY_SIZE} bits."
            )
        
        # Déchiffrer la clé Fernet
        ciphertext = base64.b64decode(encrypted_fernet_key_b64.encode('utf-8'))
        fernet_key = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Valider la clé Fernet
        if not validate_fernet_key(fernet_key):
            raise ValueError("La clé Fernet déchiffrée est invalide.")
        
        # Déchiffrer le message
        fernet = Fernet(fernet_key)
        decrypted_message = fernet.decrypt(encrypted_message.encode('utf-8')).decode('utf-8')
        
        return decrypted_message
        
    except InvalidToken as e:
        raise ValueError("Échec du déchiffrement: jeton Fernet invalide.") from e
    except Exception as e:
        raise ValueError("Échec du déchiffrement hybride.") from e


# ============================================================================
# EXPORT DES FONCTIONS POUR JAVASCRIPT
# ============================================================================

# Ces affectations sont nécessaires car Pyodide exécute le code dans un scope
# et nous devons rendre les fonctions accessibles au niveau global
generate_rsa_keys = generate_rsa_keys
encrypt_hybrid = encrypt_hybrid
decrypt_hybrid = decrypt_hybrid

print("crypto_complete.py chargé avec succès!")
print("Fonctions disponibles: generate_rsa_keys, encrypt_hybrid, decrypt_hybrid")
