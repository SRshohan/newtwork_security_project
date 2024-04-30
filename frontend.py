import streamlit as st
from twofa import generate_totp_qr, verify_totp



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
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        password_confirm = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Sign Up")
        
        if submitted:
            if not email or not password or not password_confirm:
                st.error("Please fill in all fields.")
            elif password != password_confirm:
                st.error("Passwords do not match.")
            else:
                totp_key = generate_totp_qr(email)
                st.session_state['totp_key'] = totp_key  # Store key in session for use in login
                st.image(f"{email}.png", caption="Scan the QR code with your TOTP app to finish setup.")
                st.success("Sign Up Successful! Please save your TOTP key securely.")
        generate_totp_qr(email)

def login_page():
    """User login process."""
    with st.form("login_form"):
        st.markdown("### Log In")
        email = st.text_input("Email")
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