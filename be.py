import sqlite3
from sqlite3 import Error
import bcrypt

def database_connection():
    """ Create a database if doesn't exist """
    conn = None

    try:
        conn = sqlite3.connect('Verification.db')
        print('Connection established!! ')
    except Error as e:
        print(f" Connection coneect to db failed: {e}")
    return conn
    


def create_table(conn, tables_name):
    """ Create a table in the database """
    try:
        c = conn.cursor() # Cursor objects to move through the database
        c.execute(f''' CREATE TABLE IF NOT EXISTS {tables_name} (
                  id INTEGER PRIMARY KEY,
                  email TEXT NOT NULL,
                  password TEXT NOT NULL)'''
                ) # """ SQL statement to create a table """
        conn.commit()
        print("Table created!!")
    except Error as e:
        print(Error)






def add_user(connection, email, password):
    """ Add a new user in the table"""
    password_hash = bcrypt.hashpw(password.encode('UTF-8'), bcrypt.gensalt())
    c = connection.cursor()
    c.execute('''INSERT INTO users (email, username, password) VALUES (?, ?)''', (email, password_hash))

    connection.commit() # Submit changes
    print(f"{username}, {email}, and {password_hash} has been added to the database")



def update_user(connection, email, password):
    ''' Update user information'''
    connection = connection.cursor()
    connection.exexute('''UPDATE user SET username = ?, Email = ?, WHERE id = ?''', (email, password))

    connection.commit()
    connection.close()



def login(connection, email, password):
    """ Checking if the user exist """
    try:
        connection = connection.cursor()
        query = 'SELECT password FROM users WHERE username=?'
        connection.execute(query, (email,))
        """ Fetch the first row """
        result = connection.fetchone()
        if result:
            print(bcrypt.checkpw(password.encode('utf-8'), result[0]))
        else:
            return False
    except Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        connection.close()

def drop_table(conn, name_table):
    try:
        c = conn.cursor()
        c.execute(f'DROP TABLE IF EXISTS {name_table}')
        conn.commit()
        print("table dropped successfully!! ")
    except Error as e:
        print(e)
    


if __name__== '__main__':
    connection=database_connection()
    email = 'srshohan182@gmail.com'
    username = "sohanur"
    password = "Shohan@2020"
    
    
    


        




