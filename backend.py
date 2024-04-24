import sqlite3
import bcrypt

def main():
    conn = sqlite3.connect("Verification.db")
    cur = conn.cursor()
    #cur.execute("DROP TABLE IF EXISTS User_Info") only to clear database
    cur.execute('''CREATE TABLE IF NOT EXISTS User_Info(
        Username TEXT NOT NULL,
        Password BLOB NOT NULL,
        Email TEXT NOT NULL,
        PRIMARY KEY (Username),
        CONSTRAINT unique_val UNIQUE (Username, Email))''')  
    while True:
        Input = int(input('Enter 1 - 4 for different options: '))
        if Input == 1:
            createAccount(cur)
            conn.commit()  
        elif Input == 2:
            checkAccount(cur)
        elif Input == 3:
            cur.execute('''SELECT * FROM User_Info''')
            results = cur.fetchall()  # Fetches all the results # Check if results exist and print them
            if results:
                for row in results:
                    print(row)
            else:
                print("No records found.")
        elif Input == 4:
            break
    conn.close()  

def createAccount(cur):
    username_input = input('Username: ')
    password_input = input('Password: ')
    email_input = input('Email: ')
    bytes = password_input.encode('utf-8')
    salt = bcrypt.gensalt()
    encoded_password = bcrypt.hashpw(bytes, salt)
    print(encoded_password)
    cur.execute('''INSERT INTO User_Info (Username, Password, Email) VALUES (?, ?, ?)''',
                (username_input, encoded_password, email_input))

def checkAccount(cur):
    username_input = input('Username: ')
    password_input = input('Password: ')
    cur.execute('''SELECT Password FROM User_Info WHERE Username = ?''', (username_input,))
    stored_password = cur.fetchone()
    if stored_password:
        user_bytes = password_input.encode('utf-8')
        if bcrypt.checkpw(user_bytes, stored_password[0]):
            print('Login successful!')
        else:
            print('Incorrect password.')
    else:
        print('Username not found.')

main()
