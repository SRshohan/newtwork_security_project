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
print(otpGoogleAuthenticator(key))
verification(key)







