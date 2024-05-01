import sqlite3
import bcrypt
import re
#small dict -> to check if its frequent password -> 

def createDB():
    conn = sqlite3.connect("Verification.db")
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS User_Info(
         Email TEXT NOT NULL,
        Password BLOB NOT NULL,
        PRIMARY KEY (Email),
        CONSTRAINT unique_val UNIQUE (Email))''')  
    
def dropTables():
    conn = sqlite3.connect("Verification.db")
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS User_Info")

def createAccount():
    conn = sqlite3.connect("Verification.db")
    cur = conn.cursor()
    email_input = validEmail()
    password_input = validPassword()
    bytes = password_input.encode('utf-8')
    salt = bcrypt.gensalt()
    encoded_password = bcrypt.hashpw(bytes, salt) #add the thing from sql lab
    cur.execute('''INSERT INTO User_Info (Email, Password) VALUES (?, ?)''',
                (email_input, encoded_password))
    conn.commit() 

def validEmail():
    while True:
        email_input = input('Email: ')
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email_input):
                print("Invalid email format")
        else:
            return email_input
def validPassword():
    common_PW = {
                "Password123@",
                "Password123",
                "AdminPassword1234",
                "LetMeInNow123"
                }
    while True:
        password_input = input('Password: ')
        if (len(password_input) < 8 or not re.search(r"[A-Z]", password_input) or not re.search(r"[a-z]", password_input) or not re.search(r"[0-9]", password_input) or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password_input)):
            print("Try again...")
            continue
        else:
            if password_input.lower() in common_PW:
                print("Password is common. Try again...")
                continue
            else:
                return password_input

def checkAccount():
    conn = sqlite3.connect("Verification.db")
    cur = conn.cursor()
    email_input = input('Email: ')
    password_input = input('Password: ')
    cur.execute('''SELECT Password FROM User_Info WHERE Email = ?''', (email_input,))
    stored_password = cur.fetchone()
    if stored_password:
        user_bytes = password_input.encode('utf-8')
        if bcrypt.checkpw(user_bytes, stored_password[0]):
            print('Login successful!')
        else:
            print('Incorrect password.')
    else:
        print('Email not found.')

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

def main(): 
    dropTables()
    createDB()
    createAccount()
    checkAccount()
    adminInfo()
main()
