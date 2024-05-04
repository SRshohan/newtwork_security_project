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

def main():
    """Main function to select the user action: Sign Up or Log In."""
    st.set_page_config(page_title="Welcome", page_icon=":key:")
    st.title("Welcome! Select Your Option")
    choice = st.radio("What would you like to do?", ['Create an Account', 'Login'])

    if choice == 'Create an Account':
        common_PW = {"Password123@", "Password123", "AdminPassword1234", "LetMeInNow123"}
        
        """ User sign-up process."""
        with st.form("signup_form"):
            st.markdown("### Sign Up\nPlease enter your details below to create an account.")
            col1, col2, col3 = st.columns([1, 6, 1])
            with col2:
                st.markdown("""
                    <style>
                    .big-font {
                        font-size:30px !important;
                        font-weight: bold;
                        color: #4CAF50; /* Green */
                        background-color: #f2f2f2;
                        padding: 10px;
                        text-align: center;
                        border-radius: 10px;
                    }
                    </style>
                    <p class="big-font">Create Your Account</p>
                    """, unsafe_allow_html=True)
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            password_confirm = st.text_input("Confirm Password", type="password")
            submitted = st.form_submit_button("Sign Up")
            
            if 'secretkey' not in st.session_state:
                if password:
                    st.session_state['secretkey'] = handling_totp_secretkey.generate_and_endcrypt_secret_key(password)
            secretkey = st.session_state.get('secretkey', None)
            st.write(secretkey)

            if submitted:
                if not email or not password or not password_confirm:
                    st.error("Please fill in all fields.")
                elif password != password_confirm:
                    st.error("Passwords do not match.")
                else:
                    if (len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
                        st.error("Please make sure if you use special characters combination")
                    elif password in common_PW:
                        st.error("Password is common. Try again...")
                    else:
                        randomdgt = sendEmail.randomDigit()
                        sendEmail.send_emails(email, randomdgt)
                        if 'randomgt' not in st.session_state:  
                            st.session_state['randomdgt'] = randomdgt 
                        randomdgt = st.session_state.get('randomgt', None)
                        user_otp = st.text_input("Enter the OTP sent to your email", key="otp_verification")
                        if 'user_otp' not in st.session_state:
                            st.session_state['user_otp'] = user_otp
                        user_otp = st.session_state.get('user_otp', None)
                        # verify_button = st.form_submit_button("Verify OTP")
             # Add the verification button outside of the form block
            verify_button = st.form_submit_button("Verify OTP")

            if verify_button:
                if len(secretkey) > 3:
                    st.write("Submitted")
                    if user_otp == randomdgt:
                        st.session_state['Verified'] = True
                        st.success("Email successfully verified!!! Please proceed to 2FA verification.")
                        generratingQR = generate_totp_qr(email, password)
                        st.session_state['generatingQR'] = generratingQR
                        st.image(f"{email}.png", caption="Scan the QR code with your TOTP app to finish setup")
                        finished = st.form_submit_button("Finished Setup!")
                        if finished:
                            backend.createAccount(email, password, secretkey)
                            st.success("Your account has been created! You can try to log in to your account.")

    elif choice == 'Login':
        """ User login process. """
        with st.form("login_form"):
            st.markdown("### Log In")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Log In")
            if not email or not password:
                st.error("Please fill in all fields.")
            else:
                data_retrieval_from_db = backend.retrieve_data(email)
                if data_retrieval_from_db is not None:
                    checking_from_db = backend.checkAccount(email, password)
                    if checking_from_db:
                        status ='Login successful!'
                        st.success(status)
                        otp_code = st.text_input("OTP Code")
                        decrypted_secret_key = handling_totp_secretkey.decrypt_secret_key(data_retrieval_from_db[0], password, data_retrieval_from_db[1], data_retrieval_from_db[2])
                        if submitted:
                            if verify_totp(decrypted_secret_key, otp_code):
                                st.success("Logged in successfully!")
                            else:
                                st.error("Invalid login or OTP. Please try again.")
                    else:
                        status = "Invalid Password or email address"
                        st.error(status)
                else:
                    st.error("Email not found. Please check your email or sign up.")

if __name__=="__main__":
    main()






