from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

def generate_key():
    """Generate a new Fernet key and return as string"""
    key = Fernet.generate_key()
    return key.decode('utf-8')

def encrypt_message(key_str, message):
    """Encrypt a message using Fernet key"""
    key = key_str.encode('utf-8')
    f = Fernet(key)
    encrypted = f.encrypt(message.encode('utf-8'))
    return encrypted.decode('utf-8')

def decrypt_message(key_str, encrypted_message):
    """Decrypt a message using Fernet key. Returns None on error"""
    try:
        key = key_str.encode('utf-8')
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_message.encode('utf-8'))
        return decrypted.decode('utf-8')
    except (InvalidToken, Exception):
        return None
