import streamlit as st
import pyotp
import sendgrid
from time import sleep
import qrcode

def otpGoogleAuthenticator(key):
    otp = pyotp.totp.TOTP(key).provisioning_uri(name="username", issuer_name="Authenticator App")
    qrc = qrcode.make(otp).save("totp.png")

    return otp

def verification(key):
    # res = []
    totp = pyotp.TOTP(key)
    while True:
        print(totp.verify(input("Enter OTP: ")))


key = "GrasoAndFlacoApp"
# print(otpGoogleAuthenticator(key))
# verification(key)

# st.image('totp.png', caption="Scan the QR code to setup Google authentication: ")


def sign_up():
    with st.form("signup_form"):
        st.write("### Sign Up")
        st.write("Please enter your details below to create an account.")
        
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

        # Input fields
        username = st.text_input("Username", placeholder="Your username")
        email = st.text_input("Email", placeholder="Your email address")
        password = st.text_input("Password", type="password", placeholder="Create a password")
        password_confirm = st.text_input("Confirm Password", type="password", placeholder="Confirm your password")
        
        # Submit button
        submitted = st.form_submit_button("Sign Up")
        if submitted:
            if not username or not email or not password or not password_confirm:
                st.error("Please fill in all fields.")
            elif password != password_confirm:
                st.error("Passwords do not match. Please try again.")
            else:
                st.success("Sign Up Successful!")
                st.session_state['is_signed_up'] = True

def setup_totp():
    if 'is_signed_up' in st.session_state and st.session_state['is_signed_up']:
        st.image('totp.png', caption="Scan the QR code to setup Google authentication.")
        if st.button("I have set up my TOTP"):
            st.session_state['totp_set'] = True

def login_page():
    if 'totp_set' in st.session_state and st.session_state['totp_set']:
        with st.form("login_form"):
            st.write("### Log In")
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            otp_code = st.text_input("OTP Code", placeholder="Enter your OTP code")
            submitted = st.form_submit_button("Log In")
            if submitted:
                # Place authentication logic here
                st.success("Logged in successfully!")  # Update with actual validation logic

if __name__ == "__main__":
    st.set_page_config(page_title="Sign Up", page_icon=":pencil:")
    if 'is_signed_up' not in st.session_state:
        st.session_state['is_signed_up'] = False
    if 'totp_set' not in st.session_state:
        st.session_state['totp_set'] = False

    sign_up()
    setup_totp()
    login_page()
