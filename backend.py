import sqlite3
import bcrypt
import re
import json
#small dict -> to check if its frequent password -> 

def createTable():
    conn = sqlite3.connect("Verification.db")
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS User_Info(
        Email TEXT NOT NULL,
        Password TEXT NOT NULL,
        Combined_data TEXT NOT NULL,
        PRIMARY KEY (Email),
        CONSTRAINT unique_val UNIQUE (Email))''')  
    
def dropTables():
    conn = sqlite3.connect("Verification.db")
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS User_Info")


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
    cur.commit() 


# def validEmail():
#     while True:
#         email_input = input('Email: ')
#         if not re.match(r"[^@]+@[^@]+\.[^@]+", email_input):
#                 print("Invalid email format")
#         else:
#             return email_input
        
# def validPassword():
#     common_PW = {
#                 "Password123@",
#                 "Password123",
#                 "AdminPassword1234",
#                 "LetMeInNow123"
#                 }
    
#     # password_input = input('Password: ')
#     if (len(password_input) < 8 or not re.search(r"[A-Z]", password_input) or not re.search(r"[a-z]", password_input) or not re.search(r"[0-9]", password_input) or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password_input)):
#         print("Try again...")
#         continue
#     else:
#         if password_input.lower() in common_PW:
#             print("Password is common. Try again...")
#             continue
#         else:
#             return password_input


def checkAccount(email, password):
    conn = sqlite3.connect("Verification.db")
    cur = conn.cursor()
    # email_input = input('Email: ')
    # password_input = input('Password: ')
    cur.execute('''SELECT Password FROM User_Info WHERE Email = ?''', (email,))
    stored_password = cur.fetchone()
    if stored_password:
        user_bytes = password.encode('utf-8')
        if bcrypt.checkpw(user_bytes, stored_password[0]):
            return True
        else:
            return False
    else:
        return False
    
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
    encrypted_secret_key = json_data['encrypted']
    iv = json_data['iv']
    salt = json_data['salt']
    secret_key = json_data['secret_key']  # Only if you are storing the plaintext secret key

    return (encrypted_secret_key, iv, salt, secret_key)


def adminInfo():
    conn = sqlite3.connect("Verification.db")
    cur = conn.cursor()
    cur.execute('''SELECT * FROM User_Info''')
    results = cur.fetchall()
    if results:
        for row in results:
            print(row)
    else:
        print("No records found.")


if __name__ == '__main__':
    None