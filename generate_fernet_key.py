"""
Fonctions pour la génération et l'utilisation de clés Fernet.

Ce module fournit des fonctions pour :
- Générer des clés Fernet aléatoires (recommandé).
- Générer des clés Fernet à partir de mots de passe (PBKDF2).
- Chiffrer/déchiffrer des messages avec Fernet.

Améliorations de sécurité apportées :
- Support de la dérivation de clés avec PBKDF2 (pour éviter les mots de passe faibles).
- Validation des clés Fernet.
- Gestion des erreurs sans fuite d'informations.
"""

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

# Importer les utilitaires de sécurité
from security_utils import (
    validate_fernet_key,
    derive_fernet_key_from_password,
    FERNET_KEY_SIZE,
)


# --- Génération de clés Fernet ---

def generate_key() -> str:
    """
    Génère une nouvelle clé Fernet aléatoire.
    
    Returns:
        str: Clé Fernet encodée en Base64 URL-safe.
    """
    key = Fernet.generate_key()
    return key.decode('utf-8')


def generate_key_from_password(
    password: str,
    salt: bytes = None,
    iterations: int = 100_000
) -> str:
    """
    Génère une clé Fernet à partir d'un mot de passe en utilisant PBKDF2.
    
    Args:
        password: Mot de passe (string). Doit être long et complexe (>= 8 caractères).
        salt: Sel aléatoire (bytes). Si None, un sel est généré.
        iterations: Nombre d'itérations PBKDF2 (par défaut 100_000).
    
    Returns:
        str: Clé Fernet encodée en Base64 URL-safe.
    
    Raises:
        ValueError: Si le mot de passe est trop court (< 8 caractères).
    """
    return derive_fernet_key_from_password(password, salt, iterations)


def generate_key_with_salt(
    password: str,
    salt: str,
    iterations: int = 100_000
) -> str:
    """
    Génère une clé Fernet à partir d'un mot de passe et d'un sel (encodé en Base64).
    
    Args:
        password: Mot de passe (string).
        salt: Sel encodé en Base64 (string).
        iterations: Nombre d'itérations PBKDF2.
    
    Returns:
        str: Clé Fernet encodée en Base64 URL-safe.
    
    Raises:
        ValueError: Si le mot de passe est trop court ou si le sel est invalide.
    """
    try:
        salt_bytes = base64.urlsafe_b64decode(salt.encode('utf-8') + b'==')
    except (ValueError, TypeError) as e:
        raise ValueError("Le sel doit être une chaîne Base64 URL-safe valide.") from e
    
    return derive_fernet_key_from_password(password, salt_bytes, iterations)


# --- Chiffrement/Déchiffrement avec Fernet ---

def encrypt_message(key_str: str, message: str) -> str:
    """
    Chiffre un message avec une clé Fernet.
    
    Args:
        key_str: Clé Fernet (string, encodée en Base64 URL-safe).
        message: Message en clair (string).
    
    Returns:
        str: Message chiffré (string, encodé en Base64 URL-safe).
    
    Raises:
        ValueError: Si la clé ou le message est invalide.
    """
    # Valider les entrées
    if not key_str or not isinstance(key_str, str):
        raise ValueError("La clé Fernet est manquante ou invalide.")
    
    if not validate_fernet_key(key_str):
        raise ValueError("La clé Fernet n'est pas valide (doit faire 32 octets).")
    
    if not message or not isinstance(message, str):
        raise ValueError("Le message est manquant ou invalide.")
    
    # Chiffrer le message
    key = key_str.encode('utf-8')
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode('utf-8'))
    return encrypted.decode('utf-8')


def decrypt_message(key_str: str, encrypted_message: str) -> str:
    """
    Déchiffre un message avec une clé Fernet.
    
    Args:
        key_str: Clé Fernet (string, encodée en Base64 URL-safe).
        encrypted_message: Message chiffré (string, encodé en Base64 URL-safe).
    
    Returns:
        str: Message déchiffré (string), ou None en cas d'erreur.
    
    Note:
        Retourne None en cas d'erreur pour éviter de fuiter des informations.
        En production, il est préférable de lever une exception générique.
    """
    try:
        # Valider les entrées
        if not key_str or not isinstance(key_str, str):
            return None
        
        if not validate_fernet_key(key_str):
            return None
        
        if not encrypted_message or not isinstance(encrypted_message, str):
            return None
        
        # Déchiffrer le message
        key = key_str.encode('utf-8')
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_message.encode('utf-8'))
        return decrypted.decode('utf-8')
        
    except (InvalidToken, ValueError, TypeError):
        # Ne pas fuiter d'informations sur l'erreur (sécurité)
        return None
