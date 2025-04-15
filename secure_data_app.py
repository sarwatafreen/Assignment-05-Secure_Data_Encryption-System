import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64
import uuid

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state['failed_attempts'] = 0
if 'stored_data' not in st.session_state:
    st.session_state['stored_data'] = {}
if 'current_page' not in st.session_state:
    st.session_state['current_page'] = "Home"
if 'last_attempt_time' not in st.session_state:
    st.session_state['last_attempt_time'] = 0

# Utility functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

def encrypt_data(data, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]['passkey'] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_data.encode()).decode()
            st.session_state['failed_attempts'] = 0
            return decrypted
        else:
            st.session_state['failed_attempts'] += 1
            st.session_state['last_attempt_time'] = time.time()
    except Exception as e:
        st.session_state['failed_attempts'] += 1
        st.session_state['last_attempt_time'] = time.time()
    return None

def generate_data_id():
    return str(uuid.uuid4())

def reset_failed_attempts():
    st.session_state['failed_attempts'] = 0

def change_page(page):
    st.session_state['current_page'] = page

# App UI
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state['current_page']))
st.session_state['current_page'] = choice

if st.session_state['failed_attempts'] >= 3:
    st.session_state['current_page'] = "Login"
    st.warning("🔓 Too many failed attempts! Reauthorization required.")

# Home Page
if st.session_state['current_page'] == "Home":
    st.subheader("🏡 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store New Data", use_container_width=True):
            change_page("Store Data")
    with col2:
        if st.button("Retrieve Data", use_container_width=True):
            change_page("Retrieve Data")

    st.info(f"Currently storing {len(st.session_state['stored_data'])} encrypted data entries.")

# Store Data Page
elif st.session_state['current_page'] == "Store Data":
    st.subheader("📁 Store Data Securely")
    user_data = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")

    if st.button("Encrypt and Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("☢ Passkeys do not match!")
            else:
                data_id = generate_data_id()
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                st.session_state['stored_data'][data_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                st.success("✅ Data stored securely!")
                st.code(data_id, language="text")
                st.info("⚠ Save this Data ID! You’ll need it to retrieve your data.")
        else:
            st.error("⚠ All fields are required!")

# Retrieve Data Page
elif st.session_state['current_page'] == "Retrieve Data":
    st.subheader("🔎 Retrieve Your Data")
    attempts_remaining = 3 - st.session_state['failed_attempts']
    st.info(f"Attempts remaining: {attempts_remaining}")
    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt and Retrieve"):
        if data_id and passkey:
            if data_id in st.session_state['stored_data']:
                encrypted_text = st.session_state['stored_data'][data_id]["encrypted_text"]
                decrypted_text = decrypt_data(encrypted_text, passkey, data_id)
                if decrypted_text:
                    st.success("✅ Decryption successful!")
                    st.markdown("### Your Decrypted Data:")
                    st.code(decrypted_text, language="text")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state['failed_attempts']}")
            else:
                st.error("⚠ Data ID not found!")
        else:
            st.error("☣ Both fields are required!")

    if st.session_state['failed_attempts'] >= 3:
        st.warning("🔏 Too many failed attempts! Redirecting to Login Page.")
        st.session_state['current_page'] = "Login"
        st.rerun()

# Login Page
elif st.session_state['current_page'] == "Login":
    st.subheader("🔑 Reauthorization Required")
    wait_time = 10
    time_elapsed = time.time() - st.session_state['last_attempt_time']

    if st.session_state['failed_attempts'] >= 3 and time_elapsed < wait_time:
        remaining_time = int(wait_time - time_elapsed)
        st.warning(f"⏰ Please wait {remaining_time} seconds before trying again.")
    else:
        login_passkey = st.text_input("Enter Master Password:", type="password")
        if st.button("Login"):
            if login_passkey == "admin12345678":
                reset_failed_attempts()
                st.success("✅ Reauthorized Successfully!")
                st.session_state['current_page'] = "Home"
                st.rerun()
            else:
                st.error("❌ Incorrect password!")

# Footer
st.markdown("---")
st.markdown("🔐 Secure Data Encryption System | Educational Project")










# import streamlit as st
# import hashlib
# import json
# import time
# import cryptography.fernet import Fernet
# import base64

# if 'Failed_attempts' not in st.session_state:
#     st.session_state['Failed_attempts'] = 0
#     if  'stored_data' not in st.session_state:
#         st.session_state.stored_data = {}
#     if 'current_page' not in st.session_state:
#         st.session_state.current_page = "Home" 
#     if 'last_attempt_time' not in st.session_state:
#             st.session_state.last_attempt_time = 0
#             def hash_passkey(passkey):
#                  return hashlib.sha256(passkey.encode()).hexdigest()
#                  def generate_key_from_passkey(password):
#                   hashed = hashlib.sha256(passkey.encode()).digest()
#                   return base64.urlsafe_b64encode(hashed[:32])
#                  def encrypt_data(data,passkey):
#                    key = generate_key_from_passkey(passkey)
#                     cipher = Fernet(key)
#                    return cipher.encrypt(data.encode()).decode()
#                  def decrypt_data(encrypted_data,passkey,data_id):
#          try:
#           hashed_passkey = hash_passkey(passkey)
#           if data_id in st.session_state.stored_data and st.session_state.storded_data[data_id]['hash'] == hashed_passkey:
#                key = generate_key_from_passkey(passkey)
#                cipher = Fernet(key)
#                decrypt = cipher.decrypt(encrypted_text.encode()).decode()
#                st.session_state.state.failed_attempts = 0
#              return decrypted
#              else:
#           st.session_state.failed_attempts += 1
#           st.session_state.last_attempt_time = time.time()
#          except Exception as e:
#          st.session_state.failed_attempts += 1
#          st.session_state.last_attempt_time = time time.time()
#       return None
#  def generate_data_id():
#      import uuid
#      return str(uuid.uuid4())
#  def reset_failed_attempts():
#       st.session_state.failed_attempts = 0
#        def change_page(page):
#           st.session_state.current_page = page
#           st.title("🔒 secure Data Encryption System")

#           menu =["Home", "Encrypt Data", "Decrypt Data", "View Stored Data","Delete Data","login"]
#           choice = st.sidebar.selectbox("Navigation",menu,index=menu.index(st.session_state.current_page))
#           st.session_state.current_page = choice
#            if st.session_state.failed_attempts >= 3:
#               st.session_state.current_page ="login"
#               st.warning("🔓 ...Too many failed attemts! Reauthorization required.")

#               if st.session_state.current_page == "Home":
#                   st.subheader("🏡 Wellcome to the Secure Data System")
#                   st. write(" Use this app to ** secuely store and rettrieve data** using  unique passkeys.")
#                   col1,col2 = st.columns(2)
#                      with col1:
#                       if st.button("Store New Data", use_container_width=True):
#                        change_page("Store Data")
#                       with col2:
#                           if st.button("Retrieve Data", use_container_width=True):
#                               change_page("Retrieve Data")
#                               st.info(f"Current storing {len(st.session_state.stored_data)}  encrypted data entries.")
#                             elif st.session_state.current_page == "Store Data":
#                               st.subheader("📁 Store Data  Securely")
#                               user_data = st.text_area ("Enter the data you want to store:")
#                               passkey =st.text_input("enter passkey:",type="password")
#                                confirm_passkey = st.text_input("confirm Passkey:", type="Password")  
#                               if st.button("Encrypt and Save"):
#                                  if user_data and passkey and confirm_passkey:
#                                     if passkey != confirm_passkey:
#                                        st.error("☢ Passkeys do not matach!")   
#                                     else:
#                                        data_id = generate_data_id()    
#                                        hashed_passkey = hash_passkey(passkey)   
#                                        encrypted_text = encrypted_data(user_data, passkey)  
#                                        st.session_state.stored_data[data_id]  ={
#                                           "encrypted_text": encrypted_text,
#                                           "passkey": hashed_passkey
#                                        }  
#                                        st.success("✅ Data stored securely!")  
#                                        st.code(data_id,language="text") 
#                                        st.info("⚠ Save this Data ID! You 'll need it to retrieve your data.")
#                                     else:
#                                    st.error("⚠ All fields  are required!")
#                               elif st.session_state.current_page =="Retrieve Data":
#                                   st.subheader("🔎 Retrieve Your Data")
#                                   attempts_remaining = 3 - st.session_state.failed_attempts
#                                   st.info(f"Attempts remaining: {attempts_remaining}")
#                                   data_id = st.text_input("Enter Data ID:")
#                                   passkey = st.text_input("Enter Passkey:", type="password")
#                                    if st.button("Decrypt and Retrieve"):
#                                      if data_id and passkey:
#                                         if data_id in st.session_state.state.stored_data:
#                                            encrypted_text =st . session_state.stored_data[data_id]["encrypted_text"]
#                                            decrypted_text = decrypt_data (encrypted_text,passkey, data_id)
#                                            if decrypted_text:
#                                               st.success("✅ Decryption successful!")
#                                                st.markdown("### Your Decrypted Data:")
#                                               st.code( decrypted_text,language="text")
#                                            else:
#                                               st.error(f"❌ Incorrect passkey! Attempts remaining:{3 - st.session_state.failed_attempts}")
#                                            else:
#                                              st.error("⚠ Data ID not found!")
#                                            if st.session_state.failed_attempts >= 3:
#                                               st.warning(🔏 Too many failed attemts! Redirecting to Login Redirecting to Login Page.)
#                                                st.session_state.current_page = "Login"
#                                                st.rerun()
#                                            else: st.error("☣  Both fields are required!")
#                                           elif st.session_state.current_page == "Login":
#                                            st.subheader("🔑Reauthorization Required")
#                                             if time.time() -st.session_state.last_attempt_time < 10 and st. session_state.failed_attempts >= 3:
#                                               remaining_time = int(10 - ( time.time( - st.session_state.last_attempt_time))
#                                                                    st.warning9(f"⏰Please wait {remaining_time} seconds before trying again.")
#                                                                    else:
#                                                                    login_passkey = st.text_input("Entre Paster Password:" type="password")
#                                                                    if st.button("Login"):
#                                                                    if login_passkey == "admin12345678":
#                                                                    reset_failed_attempts()
#                                                                    st.success("✅Reauthorized Successfully!")
#                                                                    st. session_state.current_page = "Home"
#                                                                   st.rerun()
#                                                                   else:
#                                                                   st.error("❌Incorrect password!")
#                                                                   st.markdown ("----")
#                                                                   st.markdown("🔐Secure Data Encryption System | Eductional Project")



                          