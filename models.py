import pysqlcipher3.dbapi2 as sqlite
from werkzeug.security import generate_password_hash

def init_db(database_file, key):
    conn = sqlite.connect(database_file)
    conn.execute(f"PRAGMA key='{key}'")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS user (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                    )''')
    conn.commit()
    conn.close()

def add_user(database_file, key, email, password):
    hashed_password = generate_password_hash(password)
    conn = sqlite.connect(database_file)
    conn.execute(f"PRAGMA key='{key}'")
    cursor = conn.cursor()
    cursor.execute('INSERT INTO user (email, password) VALUES (?, ?)', (email, hashed_password))
    conn.commit()
    conn.close()
