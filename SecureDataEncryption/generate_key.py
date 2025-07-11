from cryptography.fernet import Fernet 

KEY = Fernet.generate_key()
with open("secret.key", "wb") as file:
    file.write(KEY)
