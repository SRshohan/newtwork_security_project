import streamlit as st
import pyotp
import qrcode


# Generate a random TOTP key
def generate_totp_qr(email, key): # key = pyotp.random_base32()  # Generate a random TOTP key
    """Generates and saves a QR code for TOTP authentication."""
    totp = pyotp.TOTP(key)
    uri = totp.provisioning_uri(name=email, issuer_name="Authenticator App")
    qr = qrcode.make(uri)
    qr.save(f"{email}.png")
    return qr

def verify_totp(key, otp_code):
    """Verifies the OTP code entered by the user."""
    totp = pyotp.TOTP(key)
    return totp.verify(otp_code)
    #     status = "Logged in successfully!"
    #     return status
    # else:
    #     status = " Try agin "
    #     return status




    
