import backend
import handling_totp_secretkey
from twofa import verify_totp, generate_totp_qr
import sendEmail
import streamlit as st
import re
from dotenv import load_dotenv
import os

password = os.getenv('ENV', 'local')
dotenv = f'.env.{password}'
load_dotenv(dotenv_path=dotenv)

def reset_session_variables():
    st.session_state['email'] = ''
    st.session_state['password'] = ''
    st.session_state['password_confirm'] = ''
    st.session_state['user_otp'] = ''

def main():
    st.set_page_config(page_title="Welcome", page_icon=":key:")
    st.title("Welcome! Select Your Option")
    choice = st.radio("What would you like to do?", ['Create an Account', 'Login'])   
    if choice == 'Create an Account':
        with st.form("signup_form"):
            st.markdown("### Sign Up\nPlease enter your details below to create an account.")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            password_confirm = st.text_input("Confirm Password", type="password")

            st.session_state['email'] = email
            st.session_state['password'] = password
            st.session_state['password_confirm'] = password_confirm
            submitted = st.form_submit_button("Sign Up")

            if submitted:
                email = st.session_state.get('email')
                password = st.session_state.get('password')
                password_confirm = st.session_state.get('password_confirm')
                st.write(email, password, password_confirm)
                # validate_signup(email, password, password_confirm)
        if password == password_confirm and validate_signup(email, password, password_confirm) == True:
            st.write('Stup 2 step')
            if handle_signup(email, password) == True:
                generratingQR = generate_totp_qr(email, backend.retieval_data(email)[-1])
                st.session_state['generatingQR'] = generratingQR
                st.image(f"{email}.png", caption="Scan the QR code with your TOTP app to finish setup")
                # finished = st.form_submit_button("Finished Setup!")
                # if finished:
                #     handle_signup(email, password)
                reset_session_variables()
                st.success("Your account has been created! You can try to log in to your account.")
        else:
            st.warning("Something is wrong! Check your Email and Password")

    elif choice == 'Login':
        with st.form("login_form"):
            st.markdown("### Log In")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Log In"):
                st.success("Setup your 2 step")
        if handle_login(email, password) == True:
            reset_session_variables()
            st.success("Logged in successfully!")



                        
def validate_signup(email, password, password_confirm):
    common_PW = {"Password123@", "Password123", "AdminPassword1234", "LetMeInNow123"}
    if not email or not password or not password_confirm:
        st.error("Please fill in all fields.")
        reset_session_variables()
        return False
    if password != password_confirm:
        st.error("Passwords do not match.")
        return False
    if password in common_PW:
        st.error("Password is common. Try again...")
        reset_session_variables
        return False
    if not all([len(password) >= 8, re.search(r"[A-Z]", password), re.search(r"[a-z]", password), re.search(r"[0-9]", password), re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)]):
        st.error("Password must be 8 characters long with mixed case letters, digits, and special characters.")
        reset_session_variables()
        return False
    return True



def handle_signup(email, password):
     # Generate a new OTP and store it in session state for each verification attempt
    if 'verify_attempt' not in st.session_state or st.session_state['verify_attempt']:
        randomdgt = sendEmail.randomDigit()
        sendEmail.send_emails(email, randomdgt)  # Placeholder for actual email sending logic
        st.session_state['randomdgt'] = randomdgt
        st.session_state['verify_attempt'] = False  # Reset flag after OTP generation

    # Display the OTP for debugging (remove or secure in production)
    st.write("DEBUG: OTP sent is", st.session_state['randomdgt'])

    with st.form("verify"):
        otp_code = st.text_input("Enter the OTP sent to your email", key='otp_input')
        verify = st.form_submit_button("Verify OTP")

    if verify:
        # Check if the entered OTP matches the stored OTP
        if otp_code == st.session_state['randomdgt']:
            st.success("OTP verified! Proceeding to account creation...")
            finish_account_setup(email, password)
            # Place to add further processing like calling finish_account_setup
            st.session_state['verify_attempt'] = True  # Allow for new OTP generation on next call
            st.session_state['randomdgt'] = None  # Clear the OTP after successful verification
            return True
        else:
            st.error("Invalid OTP. Please try again.")
            st.session_state['verify_attempt'] = True  # Ensure new OTP is generated if the user retries




def finish_account_setup(email, password):
    secretkey = handling_totp_secretkey.generate_and_endcrypt_secret_key(password)
    if backend.createAccount(email, password, secretkey) == True:
        st.success("Your account has been created! Setup 2FA")
    else:
        st.write("Your Account already exists. Please sign in.")



def handle_login(email, password):
    data_retrieval_from_db = backend.retieval_data(email)
    if data_retrieval_from_db and backend.checkAccount(email, password) == True:
        decrypted_secret_key = handling_totp_secretkey.decrypt_secret_key(data_retrieval_from_db[0], password, data_retrieval_from_db[1], data_retrieval_from_db[2])
        with st.form("Verify MFA "):
            otp_code = st.text_input("Enter your OTP Code")
            if st.form_submit_button("Log In"):
                if verify_totp(decrypted_secret_key, otp_code) == True:
                    return True
                else:
                    st.error("Invalid login or OTP. Please try again.")
    else:
        st.error("Invalid Password or email address.")
    

if __name__ == "__main__":
    main()
