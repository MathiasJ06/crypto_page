"""
Package crypto pour l'application de chiffrement hybride.

Ce package contient les modules Python pour le chiffrement hybride RSA + Fernet.
Conçu pour être chargé dans Pyodide dans le navigateur.

Fonctions exposées:
- generate_rsa_keys(key_size, password) -> JSON avec public_key, private_key
- encrypt_hybrid(public_key_pem, message) -> Base64_URL_SAFE
- decrypt_hybrid(private_key_pem, encrypted_data) -> message clair
"""

from .hybrid import generate_rsa_keys, encrypt_hybrid, decrypt_hybrid

print("Package crypto chargé avec succès!")
