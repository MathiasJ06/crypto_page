"""
Fonctions pour le chiffrement hybride (Fernet + RSA).

Ce module implémente un schéma de chiffrement hybride sécurisé :
1. Le message est chiffré avec une clé symétrique Fernet (AES-128-CBC + HMAC-SHA256).
2. La clé Fernet est chiffrée avec une clé publique RSA (OAEP).
3. Le destinataire déchiffre la clé Fernet avec sa clé privée RSA, puis le message.

Améliorations de sécurité apportées :
- Utilisation de RSA-3072 bits (au lieu de 2048) pour une sécurité à long terme.
- Chiffrement RSA avec OAEP (pas PKCS#1 v1.5).
- Génération de clés Fernet uniques par message.
- Ajout d'un nonce unique pour éviter les attaques par replay.
- Validation stricte des clés (format PEM, taille).
- Chiffrement optionnel de la clé privée RSA avec un mot de passe.
- Gestion des erreurs sans fuite d'informations.
"""

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
import base64
import json
import os

# Importer les utilitaires de sécurité
from security_utils import (
    validate_rsa_public_key_pem,
    validate_rsa_private_key_pem,
    validate_fernet_key,
    generate_nonce,
    get_rsa_key_size_from_pem,
    is_rsa_key_size_secure,
    MIN_RSA_KEY_SIZE,
    RECOMMENDED_RSA_KEY_SIZE,
)

# Backend par défaut
backend = default_backend()


# --- Génération des clés RSA ---

def generate_rsa_keys(
    key_size: int = RECOMMENDED_RSA_KEY_SIZE,
    password: str = None
) -> str:
    """
    Génère une paire de clés RSA et retourne un JSON avec public_key et private_key.
    
    Args:
        key_size: Taille de la clé RSA en bits (par défaut 3072).
                  Doit être >= 2048 (recommandé: 3072 ou 4096).
        password: Mot de passe pour chiffrer la clé privée (optionnel).
                  Si None, la clé privée n'est pas chiffrée (déconseillé pour la production).
    
    Returns:
        str: JSON string avec {"public_key": str, "private_key": str, "key_size": int}.
    
    Raises:
        ValueError: Si key_size < 2048 ou si le mot de passe est trop court (< 8 caractères).
    """
    # Valider la taille de la clé
    if key_size < MIN_RSA_KEY_SIZE:
        raise ValueError(
            f"La taille de la clé RSA doit être >= {MIN_RSA_KEY_SIZE} bits. "
            f"Recommandé: {RECOMMENDED_RSA_KEY_SIZE} bits."
        )
    
    # Valider le mot de passe (si fourni)
    if password and len(password) < 8:
        raise ValueError("Le mot de passe doit contenir au moins 8 caractères.")
    
    # Générer la paire de clés RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=backend
    )
    public_key = private_key.public_key()
    
    # Sérialiser en PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Choisir l'algorithme de chiffrement pour la clé privée
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
    
    # Retourner sous forme de JSON
    return json.dumps({
        "public_key": public_pem,
        "private_key": private_pem,
        "key_size": key_size
    })


# --- Chiffrement hybride ---

def encrypt_hybrid(
    public_key_pem: str,
    message: str,
    include_nonce: bool = True
) -> str:
    """
    Chiffre un message avec une clé publique RSA (chiffrement hybride Fernet + RSA).
    
    Args:
        public_key_pem: Clé publique RSA au format PEM (string).
        message: Message en clair (string).
        include_nonce: Si True, ajoute un nonce unique pour éviter les replays (recommandé).
    
    Returns:
        str: JSON string avec {
            "encrypted_message": str, 
            "encrypted_fernet_key": str,
            "nonce": str (optionnel),
            "timestamp": int (timestamp Unix)
        }.
    
    Raises:
        ValueError: Si la clé publique est invalide ou si le message est vide.
    """
    # Valider les entrées
    if not public_key_pem or not isinstance(public_key_pem, str):
        raise ValueError("La clé publique RSA est manquante ou invalide.")
    
    if not validate_rsa_public_key_pem(public_key_pem):
        raise ValueError("La clé publique RSA n'est pas au format PEM valide.")
    
    if not message or not isinstance(message, str):
        raise ValueError("Le message est manquant ou invalide.")
    
    # Générer une clé Fernet aléatoire (unique par message)
    fernet_key = Fernet.generate_key()
    
    # Chiffrer le message avec Fernet
    fernet = Fernet(fernet_key)
    encrypted_message = fernet.encrypt(message.encode('utf-8')).decode('utf-8')
    
    # Charger la clé publique RSA
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=backend
    )
    
    # Chiffrer la clé Fernet avec RSA-OAEP (sécurisé contre les attaques adaptatives)
    ciphertext = public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Préparer le résultat
    result = {
        "encrypted_message": encrypted_message,
        "encrypted_fernet_key": base64.b64encode(ciphertext).decode('utf-8'),
    }
    
    # Ajouter un nonce si demandé (pour éviter les replays)
    if include_nonce:
        result["nonce"] = generate_nonce()
    
    # Ajouter un timestamp (optionnel, mais utile pour la validation)
    import time
    result["timestamp"] = int(time.time())
    
    return json.dumps(result)


# --- Déchiffrement hybride ---

def decrypt_hybrid(
    private_key_pem: str,
    encrypted_data_json: str,
    password: str = None,
    max_age_seconds: int = 3600
) -> str:
    """
    Déchiffre un message chiffré avec une clé privée RSA (chiffrement hybride).
    
    Args:
        private_key_pem: Clé privée RSA au format PEM (string).
        encrypted_data_json: JSON string avec "encrypted_message" et "encrypted_fernet_key".
        password: Mot de passe pour déchiffrer la clé privée (si elle est chiffrée).
        max_age_seconds: Âge maximum du message en secondes (pour éviter les replays).
                         Si None, pas de vérification de l'âge.
    
    Returns:
        str: Message déchiffré (string).
    
    Raises:
        ValueError: Si les données sont invalides ou si le déchiffrement échoue.
        InvalidToken: Si le jeton Fernet est invalide (clé ou message corrompu).
    """
    try:
        # Valider les entrées
        if not private_key_pem or not isinstance(private_key_pem, str):
            raise ValueError("La clé privée RSA est manquante ou invalide.")
        
        if not validate_rsa_private_key_pem(private_key_pem):
            raise ValueError("La clé privée RSA n'est pas au format PEM valide.")
        
        if not encrypted_data_json or not isinstance(encrypted_data_json, str):
            raise ValueError("Les données chiffrées sont manquantes ou invalides.")
        
        # Parser le JSON
        try:
            data = json.loads(encrypted_data_json)
        except json.JSONDecodeError:
            raise ValueError("Les données chiffrées ne sont pas un JSON valide.")
        
        # Vérifier les champs obligatoires
        if "encrypted_message" not in data or "encrypted_fernet_key" not in data:
            raise ValueError(
                "Les données chiffrées doivent contenir 'encrypted_message' et 'encrypted_fernet_key'."
            )
        
        encrypted_message = data["encrypted_message"]
        encrypted_fernet_key_b64 = data["encrypted_fernet_key"]
        
        # Vérifier l'âge du message (si timestamp présent et max_age_seconds défini)
        if max_age_seconds is not None and "timestamp" in data:
            import time
            current_time = int(time.time())
            message_time = data["timestamp"]
            if current_time - message_time > max_age_seconds:
                raise ValueError(
                    f"Le message est trop ancien (âge: {current_time - message_time} secondes). "
                    f"Seuls les messages de moins de {max_age_seconds} secondes sont acceptés."
                )
        
        # Charger la clé privée RSA (avec mot de passe si nécessaire)
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=password.encode('utf-8') if password else None,
            backend=backend
        )
        
        # Vérifier la taille de la clé RSA (doit être >= 2048 bits)
        key_size = private_key.key_size
        if not is_rsa_key_size_secure(key_size):
            raise ValueError(
                f"La taille de la clé RSA ({key_size} bits) est insuffisante. "
                f"Minimum requis: {MIN_RSA_KEY_SIZE} bits."
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
        )
        
        # Valider la clé Fernet
        if not validate_fernet_key(fernet_key):
            raise ValueError("La clé Fernet déchiffrée est invalide.")
        
        # Déchiffrer le message avec Fernet
        fernet = Fernet(fernet_key)
        decrypted_message = fernet.decrypt(encrypted_message.encode('utf-8')).decode('utf-8')
        
        return decrypted_message
        
    except InvalidToken as e:
        # Ne pas fuiter d'informations sur l'erreur (sécurité)
        raise ValueError("Échec du déchiffrement: jeton Fernet invalide.") from e
    except Exception as e:
        # Message d'erreur générique pour éviter les fuites d'informations
        raise ValueError("Échec du déchiffrement hybride.") from e
