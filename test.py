import sqlite3
import json
import handling_totp_secretkey
import bcrypt
import qrcode
import pyotp

def createAccount(email_input, userpassword, encrypted_data):
    conn = sqlite3.connect("Verification.db")
    cur = conn.cursor()
    createTable()
    json_data = json.dumps({
        'encrypted':encrypted_data[0].decode('utf-8'),
        'iv': encrypted_data[1].decode('utf-8'),
        'salt': encrypted_data[2].decode('utf-8'),
        'secret_key': encrypted_data[3]
    })
    # email_input = validEmail()
    # password_input = validPassword()
    bytes = userpassword.encode('utf-8')
    salt = bcrypt.gensalt()
    encoded_password = bcrypt.hashpw(bytes, salt) #add the thing from sql lab
    cur.execute('''INSERT INTO User_Info (Email, Password, Combined_data) VALUES (?, ?, ?)''', (email_input, encoded_password, json_data, ))
    conn.commit() 
    
def createTable():
    conn = sqlite3.connect("Verification.db")
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS User_Info(
        Email TEXT NOT NULL,
        Password TEXT NOT NULL,
        Combined_data TEXT NOT NULL,
        PRIMARY KEY (Email),
        CONSTRAINT unique_val UNIQUE (Email))''') 
    conn.commit()
    
def retieval_data(email):
    """Retrieve encrypted data from the database for a given email."""
    conn = sqlite3.connect("Verification.db")
    cur = conn.cursor()
    
    # Attempt to fetch the user's encrypted data using their email
    cur.execute('''SELECT Combined_data FROM User_Info WHERE Email = ?''', (email,))
    result = cur.fetchone()

    # Parse the JSON data stored in the database
    json_data = json.loads(result[0])
    
    # Decode the data that was encoded before storing
    encrypted_secret_key = json_data['encrypted'].encode()
    iv = json_data['iv'].encode()
    salt = json_data['salt'].encode()
    secret_key = json_data['secret_key']  # Only if you are storing the plaintext secret key

    return (encrypted_secret_key, iv, salt, secret_key)

def generate_totp_qr(email, key): # key = pyotp.random_base32()  # Generate a random TOTP key
    """Generates and saves a QR code for TOTP authentication."""
    totp = pyotp.TOTP(key)
    uri = totp.provisioning_uri(name=email, issuer_name="Authenticator App")
    qr = qrcode.make(uri)
    qr.save(f"{email}.png")
    
if __name__ == '__main__':
    email = "srahman06@manhattan.edu"
    userpassword = "password"
    createTable()
    encrypted = handling_totp_secretkey.generate_and_endcrypt_secret_key(userpassword)
    # createAccount(email, userpassword, encrypted)
    en = retieval_data(email)
    # print(en)
    # print(encrypted)
    # print(handling_totp_secretkey.decrypt_secret_key(en[0], userpassword, en[1], en[2]))
    # print(retieval_data(email)[3])
    generate_totp_qr(email, en[3])
