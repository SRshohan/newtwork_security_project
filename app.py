import streamlit as st
import pyotp
import qrcode


key = pyotp.random_base32()  # Generate a random TOTP key
def generate_totp_qr(username):
    """Generates and saves a QR code for TOTP authentication."""
    # key = pyotp.random_base32()  # Generate a random TOTP key
    totp = pyotp.TOTP(key)
    uri = totp.provisioning_uri(name=username, issuer_name="Authenticator App")
    qr = qrcode.make(uri)
    qr.save(f"{username}.png")

def verify_totp(key, otp_code):
    """Verifies the OTP code entered by the user."""
    totp = pyotp.TOTP(key)
    return totp.verify(otp_code)

def sign_up():
    """User sign-up process."""
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
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        password_confirm = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Sign Up")
        
        if submitted:
            if not username or not email or not password or not password_confirm:
                st.error("Please fill in all fields.")
            elif password != password_confirm:
                st.error("Passwords do not match.")
            else:
                totp_key = generate_totp_qr(username)
                st.session_state['totp_key'] = totp_key  # Store key in session for use in login
                st.image("totp.png", caption="Scan the QR code with your TOTP app to finish setup.")
                st.success("Sign Up Successful! Please save your TOTP key securely.")
        generate_totp_qr(username)

def login_page():
    """User login process."""
    with st.form("login_form"):
        st.markdown("### Log In")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        otp_code = st.text_input("OTP Code")
        submitted = st.form_submit_button("Log In")
        
        if submitted:
            # Here you'd use the actual key associated with the username
            if 'totp_key' in st.session_state and verify_totp(st.session_state['totp_key'], otp_code):
                st.success("Logged in successfully!")
            else:
                st.error("Invalid login or OTP. Please try again.")
    if verify_totp(key, otp_code) == True:
        st.write("Login Successful")
    else:
        st.write("Not Correct!")

def main():
    """Main function to select the user action: Sign Up or Log In."""
    st.title("Welcome! Select Your Option")
    choice = st.radio("What would you like to do?", ['Create an Account', 'Login'])
    
    if choice == 'Create an Account':
        sign_up()
    elif choice == 'Login':
        login_page()



if __name__ == "__main__":
    st.set_page_config(page_title="Welcome", page_icon=":key:")
    main()
