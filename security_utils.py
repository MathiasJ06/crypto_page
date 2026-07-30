"""
Utilitaires de sécurité pour le chiffrement hybride (Fernet + RSA).

Ce module fournit des fonctions pour :
- Valider les clés RSA et Fernet.
- Générer des nonces uniques.
- Dériver des clés Fernet à partir de mots de passe (PBKDF2).
- Vérifier les formats PEM.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64
import re


# --- Constantes ---
MIN_RSA_KEY_SIZE = 2048  # Taille minimale acceptable pour RSA (bits)
RECOMMENDED_RSA_KEY_SIZE = 3072  # Taille recommandée pour RSA (bits)
FERNET_KEY_SIZE = 32  # Taille d'une clé Fernet (32 octets = 256 bits)


# --- Validation des clés ---

def validate_rsa_public_key_pem(public_key_pem: str) -> bool:
    """
    Valide qu'une clé publique RSA est au format PEM correct.
    
    Args:
        public_key_pem: Clé publique RSA au format PEM (string).
    
    Returns:
        bool: True si la clé est valide, False sinon.
    """
    if not isinstance(public_key_pem, str):
        return False
    
    # Vérifier le format PEM de base
    if not public_key_pem.strip().startswith("-----BEGIN PUBLIC KEY-----"):
        return False
    if not public_key_pem.strip().endswith("-----END PUBLIC KEY-----"):
        return False
    
    # Vérifier que la clé contient des données Base64 valides
    try:
        # Extraire la partie Base64 (entre les en-têtes)
        pem_content = re.sub(
            r'-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+',
            '',
            public_key_pem.strip()
        )
        base64.b64decode(pem_content)
    except (ValueError, TypeError):
        return False
    
    return True


def validate_rsa_private_key_pem(private_key_pem: str) -> bool:
    """
    Valide qu'une clé privée RSA est au format PEM correct.
    
    Args:
        private_key_pem: Clé privée RSA au format PEM (string).
    
    Returns:
        bool: True si la clé est valide, False sinon.
    """
    if not isinstance(private_key_pem, str):
        return False
    
    # Vérifier le format PEM de base
    if not private_key_pem.strip().startswith("-----BEGIN PRIVATE KEY-----"):
        return False
    if not private_key_pem.strip().endswith("-----END PRIVATE KEY-----"):
        return False
    
    # Vérifier que la clé contient des données Base64 valides
    try:
        pem_content = re.sub(
            r'-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s+',
            '',
            private_key_pem.strip()
        )
        base64.b64decode(pem_content)
    except (ValueError, TypeError):
        return False
    
    return True


def validate_fernet_key(fernet_key: str) -> bool:
    """
    Valide qu'une clé Fernet est au format correct (32 octets URL-safe Base64).
    
    Args:
        fernet_key: Clé Fernet (string ou bytes).
    
    Returns:
        bool: True si la clé est valide, False sinon.
    """
    if isinstance(fernet_key, str):
        fernet_key = fernet_key.encode('utf-8')
    
    if not isinstance(fernet_key, bytes):
        return False
    
    # Une clé Fernet doit faire exactement 32 octets
    if len(fernet_key) != FERNET_KEY_SIZE:
        return False
    
    # Vérifier que la clé est en Base64 URL-safe (optionnel, mais recommandé)
    try:
        # Si la clé est en Base64, elle doit être décodable
        decoded = base64.urlsafe_b64decode(fernet_key)
        if len(decoded) != FERNET_KEY_SIZE:
            return False
    except (ValueError, TypeError):
        # Si ce n'est pas du Base64, vérifier que c'est bien 32 octets bruts
        pass
    
    return True


# --- Génération de nonces ---

def generate_nonce(size: int = 16) -> str:
    """
    Génère un nonce unique (nombre utilisé une seule fois).
    
    Args:
        size: Taille du nonce en octets (par défaut 16).
    
    Returns:
        str: Nonce encodé en Base64 URL-safe.
    """
    nonce = os.urandom(size)
    return base64.urlsafe_b64encode(nonce).decode('utf-8').rstrip('=')


# --- Dérivation de clés Fernet ---

def derive_fernet_key_from_password(
    password: str,
    salt: bytes = None,
    iterations: int = 100_000
) -> str:
    """
    Dérive une clé Fernet (32 octets) à partir d'un mot de passe en utilisant PBKDF2.
    
    Args:
        password: Mot de passe (string). Doit être long et complexe.
        salt: Sel aléatoire (bytes). Si None, un sel est généré.
        iterations: Nombre d'itérations PBKDF2 (par défaut 100_000).
    
    Returns:
        str: Clé Fernet encodée en Base64 URL-safe.
    
    Raises:
        ValueError: Si le mot de passe est trop court (< 8 caractères).
    """
    if not password or len(password) < 8:
        raise ValueError("Le mot de passe doit contenir au moins 8 caractères.")
    
    if salt is None:
        salt = os.urandom(16)  # 16 octets de sel aléatoire
    
    # Dériver la clé avec PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=FERNET_KEY_SIZE,  # 32 octets pour Fernet
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    
    # Dériver la clé à partir du mot de passe
    derived_key = kdf.derive(password.encode('utf-8'))
    
    # Encoder en Base64 URL-safe (format attendu par Fernet)
    return base64.urlsafe_b64encode(derived_key).decode('utf-8')


def derive_fernet_key_from_password_with_salt(
    password: str,
    salt: str,
    iterations: int = 100_000
) -> str:
    """
    Dérive une clé Fernet à partir d'un mot de passe et d'un sel (encodé en Base64).
    
    Args:
        password: Mot de passe (string).
        salt: Sel encodé en Base64 (string).
        iterations: Nombre d'itérations PBKDF2.
    
    Returns:
        str: Clé Fernet encodée en Base64 URL-safe.
    """
    salt_bytes = base64.urlsafe_b64decode(salt.encode('utf-8') + b'==')
    return derive_fernet_key_from_password(password, salt_bytes, iterations)


# --- Vérification de la taille des clés RSA ---

def get_rsa_key_size_from_pem(private_key_pem: str) -> int:
    """
    Extrait la taille de la clé RSA (en bits) à partir d'une clé privée PEM.
    
    Args:
        private_key_pem: Clé privée RSA au format PEM (string).
    
    Returns:
        int: Taille de la clé en bits, ou -1 si impossible à déterminer.
    """
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        private_key = load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        return private_key.key_size
    except Exception:
        return -1


def is_rsa_key_size_secure(key_size: int) -> bool:
    """
    Vérifie si la taille d'une clé RSA est sécurisée.
    
    Args:
        key_size: Taille de la clé en bits.
    
    Returns:
        bool: True si la taille est ≥ 2048 bits (recommandé: ≥ 3072).
    """
    return key_size >= MIN_RSA_KEY_SIZE
