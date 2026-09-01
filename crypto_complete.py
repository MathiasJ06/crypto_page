"""
Chiffrement hybride RSA-OAEP + Fernet pour Pyodide.

Architecture :
    Message
       │
       ▼
    Fernet (clé symétrique aléatoire)
       │
       ├── ciphertext message
       │
       ▼
    RSA-OAEP-SHA256
       │
       └── clé Fernet chiffrée

Format du ciphertext :
    Base64 URL-safe sans padding du format binaire :

    [4 octets : longueur ciphertext Fernet]
    [ciphertext Fernet]
    [ciphertext RSA de la clé Fernet]

La version du format est actuellement implicite pour conserver
la compatibilité avec les ciphertexts existants.

API JavaScript :
    generate_rsa_keys(key_size=3072, password=None)
    encrypt_hybrid(public_key_pem, message)
    decrypt_hybrid(private_key_pem, encrypted_data, password=None)
"""

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
)

import base64
import binascii
import json


# ============================================================================
# CONSTANTES
# ============================================================================

MIN_RSA_KEY_SIZE = 2048
RECOMMENDED_RSA_KEY_SIZE = 3072

OAEP_HASH = hashes.SHA256()
FERNET_KEY_SIZE = 32

# Limites de sécurité / robustesse.
MAX_MESSAGE_LENGTH = 100 * 1024 * 1024  # 100 MiB
MAX_CIPHERTEXT_LENGTH = 150 * 1024 * 1024


# ============================================================================
# UTILITAIRES BASE64
# ============================================================================

def _b64url_encode(data: bytes) -> str:
    """Encode des bytes en Base64 URL-safe sans padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    """
    Décode strictement du Base64 URL-safe sans padding.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("Données Base64 manquantes.")

    # Le format doit uniquement contenir des caractères Base64 URL-safe.
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_="
    )

    if any(char not in allowed for char in value):
        raise ValueError("Données Base64 URL-safe invalides.")

    # Le padding '=' ne peut apparaître qu'à la fin.
    if "=" in value.rstrip("="):
        raise ValueError("Padding Base64 invalide.")

    padding_length = (-len(value)) % 4
    padded = value + ("=" * padding_length)

    try:
        return base64.b64decode(
            padded.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Données Base64 invalides.") from exc


# ============================================================================
# VALIDATION DES CLÉS
# ============================================================================

def _load_public_rsa_key(public_key_pem: str) -> rsa.RSAPublicKey:
    """Charge et valide une clé publique RSA PEM."""

    if not isinstance(public_key_pem, str) or not public_key_pem.strip():
        raise ValueError("La clé publique RSA est manquante.")

    try:
        key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("La clé publique RSA est invalide.") from exc

    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("La clé fournie n'est pas une clé RSA.")

    if key.key_size < MIN_RSA_KEY_SIZE:
        raise ValueError(
            f"La clé RSA est trop courte ({key.key_size} bits). "
            f"Minimum : {MIN_RSA_KEY_SIZE} bits."
        )

    return key


def _load_private_rsa_key(
    private_key_pem: str,
    password: str | None = None,
) -> rsa.RSAPrivateKey:
    """Charge et valide une clé privée RSA PEM."""

    if not isinstance(private_key_pem, str) or not private_key_pem.strip():
        raise ValueError("La clé privée RSA est manquante.")

    if password is not None and not isinstance(password, str):
        raise ValueError("Le mot de passe de la clé privée est invalide.")

    password_bytes = (
        password.encode("utf-8")
        if password is not None
        else None
    )

    try:
        key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=password_bytes,
        )
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError(
            "Impossible de charger la clé privée. "
            "Le mot de passe est peut-être incorrect."
        ) from exc

    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("La clé fournie n'est pas une clé RSA.")

    if key.key_size < MIN_RSA_KEY_SIZE:
        raise ValueError(
            f"La clé RSA est trop courte ({key.key_size} bits). "
            f"Minimum : {MIN_RSA_KEY_SIZE} bits."
        )

    return key


def validate_rsa_public_key_pem(public_key_pem: str) -> bool:
    """Retourne True si le PEM contient une clé publique RSA valide."""
    try:
        _load_public_rsa_key(public_key_pem)
        return True
    except ValueError:
        return False


def validate_rsa_private_key_pem(
    private_key_pem: str,
    password: str | None = None,
) -> bool:
    """Retourne True si le PEM contient une clé privée RSA valide."""
    try:
        _load_private_rsa_key(private_key_pem, password)
        return True
    except ValueError:
        return False


# ============================================================================
# UTILITAIRES FERNET
# ============================================================================

def validate_fernet_key(fernet_key) -> bool:
    """
    Vérifie qu'une clé Fernet est valide.

    Une clé Fernet est une représentation Base64 URL-safe
    de 32 octets, soit 44 caractères avec padding.
    """

    if isinstance(fernet_key, str):
        try:
            fernet_key = fernet_key.encode("ascii")
        except UnicodeEncodeError:
            return False

    if not isinstance(fernet_key, bytes):
        return False

    try:
        # Fernet effectue également ses propres validations.
        Fernet(fernet_key)
        return True
    except (ValueError, TypeError):
        return False


def generate_key() -> str:
    """Génère une nouvelle clé Fernet aléatoire."""
    return Fernet.generate_key().decode("ascii")


def encrypt_message(key_str: str, message: str) -> str:
    """Chiffre un message avec Fernet."""

    if not isinstance(message, str):
        raise ValueError("Le message doit être une chaîne de caractères.")

    if not message:
        raise ValueError("Le message ne peut pas être vide.")

    if not isinstance(key_str, str) or not validate_fernet_key(key_str):
        raise ValueError("La clé Fernet est invalide.")

    return Fernet(key_str.encode("ascii")).encrypt(
        message.encode("utf-8")
    ).decode("ascii")


def decrypt_message(key_str: str, encrypted_message: str) -> str:
    """Déchiffre un message Fernet."""

    if not isinstance(key_str, str) or not validate_fernet_key(key_str):
        raise ValueError("La clé Fernet est invalide.")

    if not isinstance(encrypted_message, str) or not encrypted_message:
        raise ValueError("Le message chiffré est invalide.")

    try:
        plaintext = Fernet(key_str.encode("ascii")).decrypt(
            encrypted_message.encode("ascii")
        )
        return plaintext.decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
        raise ValueError(
            "Impossible de déchiffrer le message."
        ) from exc


# ============================================================================
# GÉNÉRATION RSA
# ============================================================================

def generate_rsa_keys(
    key_size: int = RECOMMENDED_RSA_KEY_SIZE,
    password: str | None = None,
) -> str:
    """
    Génère une paire de clés RSA.

    Retourne un JSON contenant :
        public_key
        private_key
        key_size
        encrypted_private_key
    """

    if not isinstance(key_size, int):
        raise ValueError("La taille RSA doit être un entier.")

    if key_size < MIN_RSA_KEY_SIZE:
        raise ValueError(
            f"La taille RSA doit être >= {MIN_RSA_KEY_SIZE} bits."
        )

    if password is not None:
        if not isinstance(password, str):
            raise ValueError("Le mot de passe doit être une chaîne.")

        if len(password) < 8:
            raise ValueError(
                "Le mot de passe doit contenir au moins 8 caractères."
            )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    if password is not None:
        encryption_algorithm = BestAvailableEncryption(
            password.encode("utf-8")
        )
        encrypted_private_key = True
    else:
        encryption_algorithm = NoEncryption()
        encrypted_private_key = False

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    ).decode("utf-8")

    return json.dumps(
        {
            "public_key": public_pem,
            "private_key": private_pem,
            "key_size": key_size,
            "encrypted_private_key": encrypted_private_key,
        },
        ensure_ascii=False,
    )


# ============================================================================
# CHIFFREMENT HYBRIDE
# ============================================================================

def encrypt_hybrid(
    public_key_pem: str,
    message: str,
) -> str:
    """
    Chiffre un message avec :

        Fernet
        +
        RSA-OAEP-SHA256

    Le message peut être de taille importante car seul
    la clé Fernet est chiffrée avec RSA.
    """

    if not isinstance(message, str):
        raise ValueError("Le message doit être une chaîne de caractères.")

    if not message:
        raise ValueError("Le message ne peut pas être vide.")

    message_bytes = message.encode("utf-8")

    if len(message_bytes) > MAX_MESSAGE_LENGTH:
        raise ValueError(
            f"Le message est trop volumineux. "
            f"Maximum : {MAX_MESSAGE_LENGTH // (1024 * 1024)} MiB."
        )

    public_key = _load_public_rsa_key(public_key_pem)

    # ------------------------------------------------------------------
    # 1. Génération d'une clé Fernet aléatoire
    # ------------------------------------------------------------------

    fernet_key = Fernet.generate_key()

    # ------------------------------------------------------------------
    # 2. Chiffrement du message avec Fernet
    # ------------------------------------------------------------------

    encrypted_message = Fernet(fernet_key).encrypt(message_bytes)

    # ------------------------------------------------------------------
    # 3. Chiffrement de la clé Fernet avec RSA-OAEP
    # ------------------------------------------------------------------

    encrypted_fernet_key = public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=OAEP_HASH),
            algorithm=OAEP_HASH,
            label=None,
        ),
    )

    # ------------------------------------------------------------------
    # 4. Construction du format binaire
    # ------------------------------------------------------------------

    message_length = len(encrypted_message)

    if message_length > 0xFFFFFFFF:
        raise ValueError("Ciphertext trop volumineux.")

    binary_data = (
        message_length.to_bytes(4, "big")
        + encrypted_message
        + encrypted_fernet_key
    )

    if len(binary_data) > MAX_CIPHERTEXT_LENGTH:
        raise ValueError("Ciphertext trop volumineux.")

    # ------------------------------------------------------------------
    # 5. Encodage final
    # ------------------------------------------------------------------

    return _b64url_encode(binary_data)


# ============================================================================
# DÉCHIFFREMENT HYBRIDE
# ============================================================================

def decrypt_hybrid(
    private_key_pem: str,
    encrypted_data: str,
    password: str | None = None,
) -> str:
    """
    Déchiffre un message hybride.

    password :
        Mot de passe permettant de déverrouiller la clé privée PEM,
        si celle-ci a été générée avec un mot de passe.
    """

    if not isinstance(encrypted_data, str) or not encrypted_data:
        raise ValueError("Les données chiffrées sont manquantes.")

    if len(encrypted_data) > MAX_CIPHERTEXT_LENGTH * 2:
        raise ValueError("Les données chiffrées sont trop volumineuses.")

    private_key = _load_private_rsa_key(
        private_key_pem,
        password=password,
    )

    # ------------------------------------------------------------------
    # 1. Décodage Base64
    # ------------------------------------------------------------------

    try:
        binary_data = _b64url_decode(encrypted_data)
    except ValueError as exc:
        raise ValueError(
            "Les données chiffrées ne sont pas valides."
        ) from exc

    # ------------------------------------------------------------------
    # 2. Vérification de la structure minimale
    #
    #    4 octets longueur
    #    + ciphertext Fernet
    #    + ciphertext RSA
    # ------------------------------------------------------------------

    rsa_ciphertext_length = private_key.key_size // 8

    minimum_length = 4 + rsa_ciphertext_length

    if len(binary_data) < minimum_length:
        raise ValueError("Les données chiffrées sont trop courtes.")

    # ------------------------------------------------------------------
    # 3. Lecture de la longueur du ciphertext Fernet
    # ------------------------------------------------------------------

    message_length = int.from_bytes(
        binary_data[:4],
        "big",
    )

    if message_length <= 0:
        raise ValueError("La longueur du ciphertext est invalide.")

    if message_length > MAX_CIPHERTEXT_LENGTH:
        raise ValueError("Le ciphertext est trop volumineux.")

    message_start = 4
    message_end = message_start + message_length

    # Vérification stricte des bornes.
    if message_end > len(binary_data):
        raise ValueError("Format de ciphertext invalide.")

    encrypted_message = binary_data[
        message_start:message_end
    ]

    encrypted_fernet_key = binary_data[message_end:]

    # Pour RSA, le ciphertext doit avoir exactement la taille
    # du module RSA.
    if len(encrypted_fernet_key) != rsa_ciphertext_length:
        raise ValueError(
            "La taille du ciphertext RSA est invalide."
        )

    # ------------------------------------------------------------------
    # 4. Déchiffrement RSA-OAEP
    # ------------------------------------------------------------------

    try:
        fernet_key = private_key.decrypt(
            encrypted_fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=OAEP_HASH),
                algorithm=OAEP_HASH,
                label=None,
            ),
        )
    except ValueError as exc:
        # Ne pas révéler de détails cryptographiques inutiles.
        raise ValueError(
            "Impossible de déchiffrer la clé symétrique."
        ) from exc

    # ------------------------------------------------------------------
    # 5. Validation de la clé Fernet
    # ------------------------------------------------------------------

    if not validate_fernet_key(fernet_key):
        raise ValueError(
            "La clé symétrique déchiffrée est invalide."
        )

    # ------------------------------------------------------------------
    # 6. Déchiffrement Fernet
    # ------------------------------------------------------------------

    try:
        plaintext_bytes = Fernet(fernet_key).decrypt(
            encrypted_message
        )
    except InvalidToken as exc:
        raise ValueError(
            "Impossible de déchiffrer le message : "
            "le ciphertext est invalide ou a été modifié."
        ) from exc

    # ------------------------------------------------------------------
    # 7. Conversion UTF-8
    # ------------------------------------------------------------------

    try:
        return plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Le message déchiffré n'est pas du texte UTF-8 valide."
        ) from exc


# ============================================================================
# COMPATIBILITÉ / EXPORTS PYODIDE
# ============================================================================

__all__ = [
    "generate_rsa_keys",
    "encrypt_hybrid",
    "decrypt_hybrid",
    "generate_key",
    "encrypt_message",
    "decrypt_message",
    "validate_rsa_public_key_pem",
    "validate_rsa_private_key_pem",
    "validate_fernet_key",
]

