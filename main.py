import json
import os
import base64
import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Session state ---
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "reauthorized" not in st.session_state:
    st.session_state.reauthorized = False

# --- Constants ---
DATA_FILE = "data.json"
MASTER_PASSWORD = "admin123"

# --- Encryption key ---
with open("secret.key", "rb") as file:
    KEY = file.read()
cipher = Fernet(KEY)

# --- Load & Save ---
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return {}  # Return empty if file is blank or invalid
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

stored_data = load_data()

# --- Hashing ---
def hash_passkey(passkey, salt=None):
    if not salt:
        salt = os.urandom(12)
    hashed = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return base64.b64encode(hashed).decode(), base64.b64encode(salt).decode()

def verify_passkey(input_passkey, stored_hash, stored_salt):
    salt_bytes = base64.b64decode(stored_salt.encode())
    input_hash, _ = hash_passkey(input_passkey, salt=salt_bytes)
    return input_hash == stored_hash

# --- Encrypt / Decrypt ---
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    if encrypted_text in stored_data:
        entry = stored_data[encrypted_text]
        if verify_passkey(passkey, entry["hashed_passkey"], entry["salt"]):
            st.session_state.failed_attempts = 0
            st.session_state.reauthorized = False  # reset after successful auth
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# --- UI ---
st.title("Secure Data Encryption System")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# --- Home ---
if choice == "Home":
    st.subheader("Welcome")
    st.write("Securely store and retrieve data using passkeys.")

# --- Store Data ---
elif choice == "Store Data":
    st.subheader("Store Data")
    user_data = st.text_area("Enter Data:", key="store_text")
    passkey = st.text_input("Enter Passkey:", type="password", key="store_pass")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey, salt = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "hashed_passkey": hashed_passkey,
                "salt": salt
            }
            save_data(stored_data)
            st.success("Data stored securely!")
            st.info("Copy the following encrypted text to retrieve it later:")
            st.code(encrypted_text, language="text")
        else:
            st.error("Both fields are required.")

# --- Retrieve Data ---
elif choice == "Retrieve Data":
    st.subheader("Retrieve Data")

    if st.session_state.failed_attempts >= 3 and not st.session_state.reauthorized:
        st.warning("Too many failed attempts. Please reauthorize first.")
        st.stop()

    encrypted_text = st.text_area("Enter Encrypted Data:", key="retrieve_text")
    passkey = st.text_input("Enter Passkey:", type="password", key="retrieve_pass")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success(f"Decrypted Data: {result}")
            else:
                remaining = max(0, 2 - st.session_state.failed_attempts)
                st.error(f"Incorrect passkey! Attempts left: {remaining + 1}")
        else:
            st.error("Both fields are required.")

# --- Login ---
elif choice == "Login":
    st.subheader("Reauthorization")
    login_pass = st.text_input("Enter Master Password:", type="password", key="admin_pass")

    if st.button("Login"):
        if login_pass == MASTER_PASSWORD:
            st.success("Reauthorized. You may now return to Retrieve Data.")
            st.session_state.failed_attempts = 0
            st.session_state.reauthorized = True
        else:
            st.error("Incorrect master password.")
