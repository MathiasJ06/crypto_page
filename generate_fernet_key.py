from cryptography.fernet import Fernet
key = Fernet.generate_key()
key.decode('utf-8')  # Convertir en chaîne pour JavaScript
