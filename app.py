import backend
import handling_totp_secretkey
from twofa import verify_totp, generate_totp_qr
import pyotp
import sendEmail
import streamlit as st
from dotenv import load_dotenv
import os
import re



password = os.getenv('ENV', 'local')
dotenv = f'.env.{password}'
# Define email sender and receiver
load_dotenv(dotenv_path=dotenv)




def main():
    """Main function to select the user action: Sign Up or Log In."""
    st.set_page_config(page_title="Welcome", page_icon=":key:")
    st.title("Welcome! Select Your Option")
    choice = st.radio("What would you like to do?", ['Create an Account', 'Login'])

    if choice == 'Create an Account':
        common_PW = {
                    "Password123@",
                    "Password123",
                    "AdminPassword1234",
                    "LetMeInNow123"
                    }
        """ User sign-up process."""
        with st.form("signup_form"):
            st.markdown("### Sign Up\nPlease enter your details below to create an account.")
            # Adding a colorful background to the title using Streamlit's columns
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
            

            encrypted = handling_totp_secretkey.generate_and_endcrypt_secret_key(password)
            secretkey = encrypted[3]


            if submitted:
                if not email or not password or not password_confirm:
                    st.error("Please fill in all fields.")
                elif password != password_confirm:
                    st.error("Passwords do not match.")
                else:
                    if (len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
                        st.error("Please make sure if you you special characters combination")
                    # otp = pyotp.random_base32()
                    elif password in common_PW:
                        st.error("Password is common. Try again...")
    #             print("Password is common. Try again...")
                    else:
                        sendEmail.send_emails(email, sendEmail.randomDigit())
                        user_otp = st.text_input("Enter the OTP sent to your email", key="otp_verification")
                        verify_button = st.form_submit_button("Verify OTP")
                        if verify_button:
                            st.session_state['Verified'] = True
                            st.success("Email successfully verified!!! Please proced to 2FA verification.")
                            generratingQR = generate_totp_qr(email, secretkey)
                            st.session_state['generatingQR'] = generratingQR
                            st.image(f"{email}.png", caption="Scan the QR code with your TOTP app to finish setup")
                            finished = st.form_submit_button("Finished Setup!")
                            if finished:
                                backend.createTable()
                                backend.createAccount(email, password, encrypted)
                                st.success("Your account has been created!!you can try to login to your account")
                        else:
                            st.error("Invalid OTP. Please try again.")


    elif choice == 'Login':
        
        """ User login process. """
        with st.form("login_form"):
            st.markdown("### Log In")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            data_retrival_from_db = backend.retieval_data(email)
            if not email or not password:
                st.error("Please fill in all fields.")
            else:
                checking_from_db = backend.checkAccount(email, password)
                if checking_from_db == True:
                    status ='Login successful!'
                    st.success(status)
                    otp_code = st.text_input("OTP Code")
                    decrected_secret_key = handling_totp_secretkey.decrypt_secret_key(data_retrival_from_db[0], data_retrival_from_db[1], data_retrival_from_db[2], data_retrival_from_db[3])
                    submitted = st.form_submit_button("Log In")
                    if submitted:
                        # Here you'd use the actual key associated with the username
                        if verify_totp(decrected_secret_key, otp_code) == True:
                            st.success("Logged in successfully!")
                        else:
                            st.error("Invalid login or OTP. Please try again.")
                else:
                    status = "Invalid Password :( or email address"
                    st.error(status)
        

        




if __name__=="__main__":
    main()






