import streamlit as st 
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet  
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac


if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0



DATA_FILE = "secure_store.json"
SALT = b"super_secure_salt"
LOCKOUT_DURATION = 60  # in seconds


st.set_page_config(page_title="Secure-DATA", page_icon="🛡️", layout="centered")

st.markdown("""
    <style>
        body, .stApp {
            background-color: #111827;
            color: #e5e7eb;
        }

        .main-title {
            font-size: 2.5rem;
            text-align: center;
            color: #facc15;
            margin-bottom: 0.5rem;
        }

        .sub-title {
            text-align: center;
            color: #9ca3af;
            font-size: 1.1rem;
            margin-bottom: 2rem;
        }

        .stTextInput > div > div,
        .stTextArea > div > textarea {
            background-color: #1f2937 !important;
            color: white !important;
            border-radius: 8px;
            padding: 10px;
        }

        .footer {
            text-align: center;
            color: #6b7280;
            margin-top: 3rem;
            font-size: 0.9rem;
        }
    </style>
""", unsafe_allow_html=True)


# Utilities

def load_users():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def encrypt_text(text, passkey):
    key = generate_key(passkey)
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def decrypt_text(token, passkey):
    try:
        key = generate_key(passkey)
        f = Fernet(key)
        return f.decrypt(token.encode()).decode()
    except Exception:
        st.error("⚠️ Invalid decryption key.")
        return None


users = load_users()


st.markdown('<h1 class="main-title">Secure-DATA</h1>', unsafe_allow_html=True)
st.markdown('<p class="sub-title">Encrypt. Store. Retrieve. All with Confidence 🛡️</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-title"><b>Secure</b> Data Encryption System 🔐</p>', unsafe_allow_html=True)

menu = ["🏠 Home", "📝 Register", "🔐 Login", "📥 Store Data", "🔓 Decrypt"]
choice = st.sidebar.selectbox("Menu", menu)

# Home

if choice == "🏠 Home":
    st.markdown("### 🔒 About This App")
    st.write("""
    SecureVault allows you to:
    - Register & login securely
    - Encrypt sensitive data with a passkey
    - Decrypt and retrieve your data later
    """)
    st.success("Your data is stored encrypted using **Fernet symmetric encryption** and your passwords are **hashed** with PBKDF2.")


# Register and Login

elif choice == "📝 Register":
    st.subheader("Create Your Secure Account")
    new_user = st.text_input("Choose a username")
    pw = st.text_input("Create password", type='password')
    pw_confirm = st.text_input("Confirm password", type='password')
    if st.button("Register"):
        if not new_user or not pw:
            st.warning("Please fill in all fields.")
        elif pw != pw_confirm:
            st.error("Passwords do not match.")
        elif new_user in users:
            st.error("Username already exists.")
        else:
            users[new_user] = {"password": hash_password(pw), "data": ""}
            save_users(users)
            st.success("🎉 Registration successful! You can now log in.")

# Login

elif choice == "🔐 Login":
    st.subheader("User Login")
    user = st.text_input("Username")
    pw = st.text_input("Password", type='password')
    if st.button("Login"):
        if st.session_state.failed_attempts >= 3 and time.time() - st.session_state.lockout_time < LOCKOUT_DURATION:
            st.error("⏳ Too many failed attempts. Please wait a minute.")
        elif user in users and hash_password(pw) == users[user]["password"]:
            st.session_state.authenticated_user = user
            st.session_state.failed_attempts = 0
            st.success(f"Welcome back, {user}!")
        else:
            st.session_state.failed_attempts += 1
            st.session_state.lockout_time = time.time()
            st.error("Login failed. Check username and password.")



# Store Data

elif choice == "📥 Store Data":
    if st.session_state.authenticated_user:
        st.subheader("Encrypt & Save Data")
        secret = st.text_area("Enter data to encrypt")
        key = st.text_input("Set a passkey", type="password")
        if st.button("Encrypt and Save"):
            if secret and key:
                encrypted = encrypt_text(secret, key)
                users[st.session_state.authenticated_user]["data"] = encrypted
                save_users(users)
                st.success("✅ Your data was encrypted and saved.")
            else:
                st.error("Please fill in all fields.")
    else:
        st.warning("🔐 Please login to use this feature.")



elif choice == "🔓 Decrypt":
    if st.session_state.authenticated_user:
        st.subheader("Retrieve Your Data")
        key = st.text_input("Enter your passkey", type="password")
        if st.button("Decrypt"):
            encrypted = users[st.session_state.authenticated_user].get("data", "")
            if encrypted:
                decrypted = decrypt_text(encrypted, key)
                if decrypted:
                    st.success("🎉 Here's your decrypted data:")
                    st.code(decrypted)
            else:
                st.warning("No data stored for this account.")
    else:
        st.warning("🔐 Please login to access decryption.")


if st.session_state.authenticated_user:
    if st.button("Logout"):
        st.session_state.authenticated_user = None
        st.success("👋 You've been logged out.")




st.markdown("""
<hr>
<div class="footer">
    Made with ❤️ by <b>Fayaz ALI 😎</b>
            
</div>
""", unsafe_allow_html=True)
