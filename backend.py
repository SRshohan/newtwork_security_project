import sqlite3
conn = sqlite3.connect("Verification.db")
cur = conn.cursor()
cur.execute('''CREATE TABLE IF NOT EXISTS User_Info(Username TEXT NOT NULL, Password TEXT NOT NULL, Email TEXT NOT NULL,PRIMARY KEY (Username), CONSTRAINT unique_val UNIQUE(Username, Password))''')
cur.execute('''INSERT INTO User_Info (Username, Password, Email)
                   VALUES ("SRshohan", "Sohanur Rahman", "srahman06@manhattan.edu")''')
username_input = input('Username:')
password_input = input('Password:')
cur.execute('''SELECT * from User_Info where Username = ? and Password = ?
''', (username_input, password_input,))
result = cur.fetchone()
if result:
    print('works')
else:
    print('no')