"""
Module de chiffrement hybride (Fernet + RSA) pour Pyodide.

Schéma de chiffrement hybride sécurisé:
1. Le message est chiffré avec une clé symétrique Fernet (AES-128-CBC + HMAC-SHA256)
2. La clé Fernet est chiffrée avec une clé publique RSA (OAEP)
3. Le destinataire déchiffre la clé Fernet avec sa clé privée RSA, puis le message

Fonctions principales:
- generate_rsa_keys(key_size, password) -> JSON avec public_key, private_key
- encrypt_hybrid(public_key_pem, message) -> Base64_URL_SAFE
- decrypt_hybrid(private_key_pem, encrypted_data) -> message clair
"""

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
import base64
import json
import os
import re


# ============================================================================
# CONSTANTES
# ============================================================================

MIN_RSA_KEY_SIZE = 2048
RECOMMENDED_RSA_KEY_SIZE = 3072
FERNET_KEY_SIZE = 32
backend = default_backend()


# ============================================================================
# VALIDATION
# ============================================================================

def validate_rsa_public_key_pem(public_key_pem):
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


def validate_rsa_private_key_pem(private_key_pem):
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


# ============================================================================
# GÉNÉRATION DES CLÉS RSA
# ============================================================================

def generate_rsa_keys(key_size=None, password=None):
    """
    Génère une paire de clés RSA.
    
    Args:
        key_size: Taille de la clé RSA en bits (par défaut 3072)
        password: Mot de passe pour chiffrer la clé privée (optionnel)
    
    Returns:
        str: JSON avec {"public_key": str, "private_key": str, "key_size": int}
    """
    if key_size is None:
        key_size = RECOMMENDED_RSA_KEY_SIZE
    if password is None:
        password = ""
    
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


# ============================================================================
# CHIFFREMENT HYBRIDE
# ============================================================================

def encrypt_hybrid(public_key_pem, message):
    """
    Chiffre un message avec chiffrement hybride (Fernet + RSA).
    
    Format:
        Base64_URL_SAFE(length_4bytes + encrypted_message_base64 + encrypted_fernet_key_b64)
    """
    if not public_key_pem or not isinstance(public_key_pem, str):
        raise ValueError("La clé publique RSA est manquante ou invalide.")
    
    if not validate_rsa_public_key_pem(public_key_pem):
        raise ValueError("La clé publique RSA n'est pas au format PEM valide.")
    
    if not message or not isinstance(message, str):
        raise ValueError("Le message est manquant ou invalide.")
    
    print(f"DEBUG: Starting encryption, message length: {len(message)}")
    
    # Générer une clé Fernet aléatoire
    fernet_key = Fernet.generate_key()
    print(f"DEBUG: Fernet key generated, length: {len(fernet_key)}")
    
    # Chiffrer le message avec Fernet
    fernet = Fernet(fernet_key)
    encrypted_message = fernet.encrypt(message.encode('utf-8'))
    print(f"DEBUG: Message encrypted with Fernet, encrypted length: {len(encrypted_message)}")
    
    # Charger la clé publique RSA
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=backend
    )
    print("DEBUG: RSA public key loaded")
    
    # Chiffrer la clé Fernet avec RSA-OAEP
    ciphertext = public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"DEBUG: Fernet key encrypted with RSA, ciphertext length: {len(ciphertext)}")
    
    # Encoder la clé RSA chiffrée en Base64 URL-safe
    encrypted_fernet_key_b64 = base64.urlsafe_b64encode(ciphertext).decode('utf-8').rstrip('=')
    print(f"DEBUG: Encrypted Fernet key encoded, length: {len(encrypted_fernet_key_b64)}")
    
    # Créer le format binaire
    length_prefix = len(encrypted_message).to_bytes(4, 'big')
    encrypted_fernet_key_bytes = encrypted_fernet_key_b64.encode('utf-8')
    binary_data = length_prefix + encrypted_message + encrypted_fernet_key_bytes
    print(f"DEBUG: Binary data created, total length: {len(binary_data)}")
    
    # Encoder le tout en Base64 URL-safe
    result = base64.urlsafe_b64encode(binary_data).decode('utf-8').rstrip('=')
    print(f"DEBUG: Final result encoded, length: {len(result)}")
    
    return result


# ============================================================================
# DÉCHIFFREMENT HYBRIDE
# ============================================================================

def decrypt_hybrid(private_key_pem, encrypted_data):
    """
    Déchiffre un message chiffré avec chiffrement hybride.
    """
    if not private_key_pem or not isinstance(private_key_pem, str):
        raise ValueError("La clé privée RSA est manquante ou invalide.")
    
    if not validate_rsa_private_key_pem(private_key_pem):
        raise ValueError("La clé privée RSA n'est pas au format PEM valide.")
    
    if not encrypted_data or not isinstance(encrypted_data, str):
        raise ValueError("Les données chiffrées sont manquantes ou invalides.")
    
    print(f"DEBUG: Starting decryption, encrypted_data length: {len(encrypted_data)}")
    
    # Ajouter le padding Base64 URL-safe si nécessaire
    encrypted_data_padded = encrypted_data + '=' * ((4 - len(encrypted_data) % 4) % 4)
    print(f"DEBUG: Padded encrypted_data, length: {len(encrypted_data_padded)}")
    
    # Décoder le Base64 URL-safe
    binary_data = base64.urlsafe_b64decode(encrypted_data_padded.encode('utf-8'))
    print(f"DEBUG: Binary data decoded, length: {len(binary_data)}")
    
    # Extraire la longueur
    if len(binary_data) < 4:
        raise ValueError("Données chiffrées trop courtes.")
    
    message_length = int.from_bytes(binary_data[:4], 'big')
    print(f"DEBUG: Message length extracted: {message_length}")
    
    # Extraire le message chiffré et la clé chiffrée
    encrypted_message_bytes = binary_data[4:4+message_length]
    encrypted_fernet_key_b64 = binary_data[4+message_length:].decode('utf-8')
    print(f"DEBUG: Extracted encrypted_message length: {len(encrypted_message_bytes)}, encrypted_fernet_key_b64 length: {len(encrypted_fernet_key_b64)}")
    
    # Charger la clé privée RSA
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=backend
    )
    print(f"DEBUG: RSA private key loaded, key size: {private_key.key_size}")
    
    # Vérifier la taille de la clé RSA
    key_size = private_key.key_size
    if key_size < MIN_RSA_KEY_SIZE:
        raise ValueError(
            f"La taille de la clé RSA ({key_size} bits) est insuffisante. "
            f"Minimum requis: {MIN_RSA_KEY_SIZE} bits."
        )
    
    # Ajouter le padding Base64 à la clé Fernet si nécessaire
    encrypted_fernet_key_padded = encrypted_fernet_key_b64 + '=' * ((4 - len(encrypted_fernet_key_b64) % 4) % 4)
    print(f"DEBUG: Padded encrypted_fernet_key_b64, length: {len(encrypted_fernet_key_padded)}")
    
    # Décoder et déchiffrer la clé Fernet
    ciphertext = base64.urlsafe_b64decode(encrypted_fernet_key_padded.encode('utf-8'))
    print(f"DEBUG: Ciphertext decoded, length: {len(ciphertext)}")
    
    fernet_key = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"DEBUG: Fernet key decrypted, length: {len(fernet_key)}")
    
    if len(fernet_key) != FERNET_KEY_SIZE:
        raise ValueError(f"La clé Fernet déchiffrée est invalide. Taille: {len(fernet_key)} octets, attendu: {FERNET_KEY_SIZE}")
    
    # Déchiffrer le message avec Fernet
    fernet = Fernet(fernet_key)
    decrypted_message = fernet.decrypt(encrypted_message_bytes).decode('utf-8')
    print(f"DEBUG: Message decrypted, length: {len(decrypted_message)}")
    
    return decrypted_message
