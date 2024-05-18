import pysqlcipher3.dbapi2 as sqlite
from dotenv import load_dotenv
import os
from logger import logger

load_dotenv()


class Database:
    def __init__(self, database_file, key) -> None:
        self.__database_file = database_file
        self.__key = key

    def __open(self):
        x = sqlite.connect(self.__database_file)
        x.execute(f"PRAGMA key='{self.__key}'")
        return x

    def init_db(self):
        database = self.__open()
        cursor = database.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        reset_token TEXT NOT NULL
                    )"""
        )
        database.commit()
        database.close()

    def add_user(self, username, email, password, token):
        logger.info(f"Adding to database: {username}")
        database = self.__open()
        cursor = database.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password, reset_token) VALUES (?, ?, ?, ?)",
            (username, email, password, token),
        )
        database.commit()
        database.close()

    def update_user_password(self, password, id):
        database = self.__open()
        cursor = database.cursor()
        cursor.execute(
            "UPDATE users SET password = ? WHERE id = ?;",
            (password, id),
        )
        database.commit()
        database.close()

    def find_by_username(self, username):
        database = self.__open()
        cursor = database.cursor()
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        row = cursor.fetchone()
        database.close()
        if row:
            return row
        else:
            return None

    def find_by_email(self, email):
        database = self.__open()
        cursor = database.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        row = cursor.fetchone()
        database.close()
        if row:
            return row
        else:
            return None

    def find_by_id(self, user_id):
        database = self.__open()
        cursor = database.cursor()
        cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
        row = cursor.fetchone()
        database.close()
        if row:
            return row
        else:
            return None


db = Database("./security/db.sqlite", os.getenv("RtYbfYZecfEzoLHzjA71qDXaiofjjRH7n"))
if not os.path.exists("./security/db.sqlite"):
    db.init_db()
