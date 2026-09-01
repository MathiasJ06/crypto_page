"""
Module complet pour le chiffrement hybride (Fernet + RSA) pour Pyodide.

Ce module combine tout le code nécessaire sans imports entre fichiers locaux.
Toutes les dépendances externes (cryptography) sont chargées via Pyodide.

Fonctions exposées au niveau global pour JavaScript :
- generate_rsa_keys()
- encrypt_hybrid(public_key_pem, message)
- decrypt_hybrid(private_key_pem, encrypted_data)

Format de sortie :
Base64_URL_SAFE(length_4bytes + encrypted_message_bytes + encrypted_fernet_key_bytes)
Où tout est en binaire brut (pas de double encodage Base64)
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
import struct
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
    """Valide qu'une clé Fernet est au format correct (32 octets)."""
    if isinstance(fernet_key, str):
        fernet_key = fernet_key.encode('utf-8')
    if not isinstance(fernet_key, bytes):
        return False
    if len(fernet_key) != FERNET_KEY_SIZE:
        return False
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
    message: str
) -> str:
    """
    Chiffre un message avec chiffrement hybride (Fernet + RSA).
    
    Format de sortie :
    Base64_URL_SAFE(length_4bytes + encrypted_message_bytes + encrypted_fernet_key_bytes)
    
    Où :
    - length_4bytes = longueur de encrypted_message_bytes (4 octets, big-endian)
    - encrypted_message_bytes = message chiffré avec Fernet (déjà en Base64 standard)
    - encrypted_fernet_key_bytes = clé Fernet chiffrée avec RSA, encodée en Base64 URL-safe
    """
    print("=== DEBUT ENCRYPT_HYBRID ===")
    print(f"Longueur du message: {len(message)} caractères")
    
    if not public_key_pem or not isinstance(public_key_pem, str):
        print("ERREUR: Clé publique RSA manquante ou invalide")
        raise ValueError("La clé publique RSA est manquante ou invalide.")
    if not validate_rsa_public_key_pem(public_key_pem):
        print("ERREUR: Clé publique RSA n'est pas au format PEM valide")
        raise ValueError("La clé publique RSA n'est pas au format PEM valide.")
    if not message or not isinstance(message, str):
        print("ERREUR: Message manquant ou invalide")
        raise ValueError("Le message est manquant ou invalide.")
    
    # Générer une clé Fernet aléatoire (32 octets binaires)
    fernet_key = Fernet.generate_key()
    print(f"Clé Fernet générée: {len(fernet_key)} octets")
    print(f"Clé Fernet (hex): {fernet_key.hex()}")
    
    # Chiffrer le message avec Fernet (retourne des bytes Base64)
    fernet = Fernet(fernet_key)
    encrypted_message = fernet.encrypt(message.encode('utf-8'))
    print(f"Message chiffré Fernet: {len(encrypted_message)} octets")
    print(f"Type encrypted_message: {type(encrypted_message)}")
    
    # Charger la clé publique RSA
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=backend
    )
    print(f"Clé publique RSA chargée, taille: {public_key.key_size} bits")
    
    # Chiffrer la clé Fernet avec RSA-OAEP (retourne des bytes)
    ciphertext = public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Clé Fernet chiffrée RSA: {len(ciphertext)} octets")
    
    # Encoder la clé RSA chiffrée en Base64 URL-safe (sans padding)
    encrypted_fernet_key_b64 = base64.urlsafe_b64encode(ciphertext).decode('utf-8').rstrip('=')
    print(f"Clé Fernet chiffrée encodée: {len(encrypted_fernet_key_b64)} caractères")
    
    # Créer le format binaire : [length(4o)][encrypted_message_bytes][encrypted_fernet_key_bytes]
    # La longueur est celle de encrypted_message_bytes (qui est déjà du Base64)
    length_prefix = len(encrypted_message).to_bytes(4, 'big')
    print(f"Longueur du message chiffré: {len(encrypted_message)} octets")
    print(f"Prefix de longueur: {length_prefix.hex()}")
    
    # Tout en bytes pour la concaténation
    encrypted_fernet_key_bytes = encrypted_fernet_key_b64.encode('utf-8')
    print(f"Longueur encrypted_fernet_key_bytes: {len(encrypted_fernet_key_bytes)} octets")
    
    binary_data = length_prefix + encrypted_message + encrypted_fernet_key_bytes
    print(f"Données binaires totales: {len(binary_data)} octets")
    print(f"Structure: [{len(length_prefix)}o][{len(encrypted_message)}o][{len(encrypted_fernet_key_bytes)}o]")
    
    # Encoder le tout en Base64 URL-safe (sans padding)
    final_result = base64.urlsafe_b64encode(binary_data).decode('utf-8').rstrip('=')
    print(f"Résultat final: {len(final_result)} caractères")
    print("=== FIN ENCRYPT_HYBRID ===\n")
    
    return final_result


def decrypt_hybrid(
    private_key_pem: str,
    encrypted_data: str
) -> str:
    """
    Déchiffre un message chiffré avec chiffrement hybride.
    
    Format d'entrée :
    Base64_URL_SAFE(length_4bytes + encrypted_message_base64 + encrypted_fernet_key_b64)
    """
    print("=== DEBUT DECRYPT_HYBRID ===")
    print(f"Longueur des données d'entrée: {len(encrypted_data)} caractères")
    
    try:
        if not private_key_pem or not isinstance(private_key_pem, str):
            print("ERREUR: Clé privée RSA manquante ou invalide")
            raise ValueError("La clé privée RSA est manquante ou invalide.")
        if not validate_rsa_private_key_pem(private_key_pem):
            print("ERREUR: Clé privée RSA n'est pas au format PEM valide")
            raise ValueError("La clé privée RSA n'est pas au format PEM valide.")
        if not encrypted_data or not isinstance(encrypted_data, str):
            print("ERREUR: Données chiffrées manquantes ou invalides")
            raise ValueError("Les données chiffrées sont manquantes ou invalides.")
        
        # Ajouter le padding Base64 URL-safe si nécessaire
        encrypted_data_padded = encrypted_data + '=' * ((4 - len(encrypted_data) % 4) % 4)
        print(f"Données avec padding: {len(encrypted_data_padded)} caractères")
        
        # Décoder le Base64 URL-safe -> bytes
        try:
            binary_data = base64.urlsafe_b64decode(encrypted_data_padded.encode('utf-8'))
            print(f"Données binaires décodées: {len(binary_data)} octets")
        except (ValueError, TypeError) as e:
            print(f"ERREUR décodage Base64: {str(e)}")
            raise ValueError(f"Les données chiffrées ne sont pas au format valide: {str(e)}")
        
        # Extraire la longueur (4 premiers octets)
        if len(binary_data) < 4:
            print(f"ERREUR: Données trop courtes ({len(binary_data)} octets)")
            raise ValueError("Données chiffrées trop courtes.")
        
        message_length = int.from_bytes(binary_data[:4], 'big')
        print(f"Longueur du message chiffré: {message_length} octets")
        print(f"Prefix de longueur: {binary_data[:4].hex()}")
        
        # Extraire le message chiffré (déjà en Base64) et la clé chiffrée (Base64 URL-safe)
        encrypted_message_bytes = binary_data[4:4+message_length]
        encrypted_fernet_key_b64 = binary_data[4+message_length:].decode('utf-8')
        
        print(f"Message chiffré extrait: {len(encrypted_message_bytes)} octets")
        print(f"Message chiffré (premier 20 octets): {encrypted_message_bytes[:20]}")
        print(f"Clé Fernet chiffrée: {len(encrypted_fernet_key_b64)} caractères")
        
        # Charger la clé privée RSA
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=backend
        )
        print(f"Clé privée RSA chargée, taille: {private_key.key_size} bits")
        
        # Vérifier la taille de la clé RSA
        key_size = private_key.key_size
        if not is_rsa_key_size_secure(key_size):
            print(f"ERREUR: Taille de clé RSA insuffisante: {key_size} bits")
            raise ValueError(
                f"La taille de la clé RSA ({key_size} bits) est insuffisante. "
                f"Minimum requis: {MIN_RSA_KEY_SIZE} bits."
            )
        
        # Ajouter le padding Base64 à la clé Fernet si nécessaire
        encrypted_fernet_key_padded = encrypted_fernet_key_b64 + '=' * ((4 - len(encrypted_fernet_key_b64) % 4) % 4)
        print(f"Clé Fernet chiffrée avec padding: {len(encrypted_fernet_key_padded)} caractères")
        
        # Décoder la clé Fernet chiffrée
        ciphertext = base64.urlsafe_b64decode(encrypted_fernet_key_padded.encode('utf-8'))
        print(f"Ciphertext RSA décodé: {len(ciphertext)} octets")
        
        # Déchiffrer la clé Fernet avec RSA-OAEP
        fernet_key = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        print(f"Clé Fernet déchiffrée: {len(fernet_key)} octets")
        print(f"Clé Fernet déchiffrée (hex): {fernet_key.hex()}")
        print(f"Type: {type(fernet_key)}")
        
        # fernet_key doit être des bytes de 32 octets
        if not validate_fernet_key(fernet_key):
            print(f"ERREUR: Clé Fernet invalide! Taille: {len(fernet_key)}, attendu: {FERNET_KEY_SIZE}")
            raise ValueError(f"La clé Fernet déchiffrée est invalide. Taille: {len(fernet_key)} octets, attendu: {FERNET_KEY_SIZE}")
        
        print("Clé Fernet valide!")
        
        # Déchiffrer le message avec Fernet
        # encrypted_message_bytes est déjà en Base64, on doit le décoder pour Fernet
        fernet = Fernet(fernet_key)
        print(f"Création objet Fernet avec clé: {fernet_key[:16].hex()}...")
        
        # Essayer de déchiffrer
        try:
            decrypted_message = fernet.decrypt(encrypted_message_bytes).decode('utf-8')
            print(f"Message déchiffré: {len(decrypted_message)} caractères")
            print("=== FIN DECRYPT_HYBRID (SUCCESS) ===\n")
            return decrypted_message
        except InvalidToken as e:
            print(f"ERREUR InvalidToken: {str(e)}")
            print(f"Tentative avec encrypted_message_bytes type: {type(encrypted_message_bytes)}")
            print(f"Tentative avec encrypted_message_bytes: {encrypted_message_bytes[:50]}")
            print("=== FIN DECRYPT_HYBRID (ERROR) ===\n")
            raise ValueError(f"Échec du déchiffrement: jeton Fernet invalide: {str(e)}")
        
    except Exception as e:
        print(f"ERREUR générale: {str(e)}")
        print("=== FIN DECRYPT_HYBRID (ERROR) ===\n")
        raise ValueError(f"Échec du déchiffrement hybride: {str(e)}")


# ============================================================================
# EXPORT DES FONCTIONS POUR JAVASCRIPT
# ============================================================================

# Ces affectations sont nécessaires pour rendre les fonctions accessibles
generate_rsa_keys = generate_rsa_keys
encrypt_hybrid = encrypt_hybrid
decrypt_hybrid = decrypt_hybrid

print("crypto_complete.py chargé avec succès!")
print("Fonctions disponibles: generate_rsa_keys, encrypt_hybrid, decrypt_hybrid")
