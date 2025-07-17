import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ---------- ENCRYPTION SETUP ----------

# Store key in session_state so it's persistent
if "KEY" not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()

cipher = Fernet(st.session_state.KEY)

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# ---------- SESSION STORAGE ----------
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

# ---------- STREAMLIT APP ----------
st.set_page_config(page_title="Secure Data Encryption System")
st.title("🔒 Secure Data Encryption System")

# Sidebar Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# ---------- HOME ----------
if choice == "Home":
    st.subheader("🏠 Welcome to Khansa's Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# ---------- STORE DATA ----------
elif choice == "Store Data":
    st.subheader("📝 Store Secret Data")

    user_data = st.text_area("Enter your secret data:")
    passkey = st.text_input("Enter a Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            # Process data
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)

            # Store in session_state
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }

            st.success("✅ Your data has been securely saved!")
            st.write("🔐 **Your Encrypted Text:**")
            st.code(encrypted_text, language="text")

        else:
            st.error("⚠️ Both fields are required!")

# ---------- RETRIEVE DATA ----------
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Secret Data")

    encrypted_text_input = st.text_area("Paste your encrypted text here:")
    passkey_input = st.text_input("Enter your Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text_input and passkey_input:
            hashed_passkey = hash_passkey(passkey_input)

            # Retrieve from stored data
            if encrypted_text_input in st.session_state.stored_data:
                stored_passkey = st.session_state.stored_data[encrypted_text_input]["passkey"]

                if hashed_passkey == stored_passkey:
                    try:
                        decrypted_text = decrypt_data(encrypted_text_input)
                        st.success("✅ Data decrypted successfully!")
                        st.write("🔓 **Decrypted Data:**")
                        st.code(decrypted_text, language="text")
                    except Exception:
                        st.error("❌ Decryption failed. Possibly wrong encryption key.")
                else:
                    st.error("❌ Incorrect passkey.")
            else:
                st.error("❌ Encrypted text not found in storage.")
        else:
            st.error("⚠️ Both fields are required!")

# ---------- LOGIN PAGE ----------
elif choice == "Login":
    st.subheader("🔑 Khansa - Reauthorization Required")
    st.info("This page is under development.")
