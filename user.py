import sys
import os
from flask_login import UserMixin
import bcrypt
import secrets
import string


ROOT_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(ROOT_DIR) # NO
from db import db
from login_manager import login_manager
from logger import logger


class User(UserMixin):
    def __init__(self, username, password, email, exists=False, id=None, token=None) -> None:
        self.exists = exists
        self.username = username
        self.password = password
        self.email = email
        self.id = id
        self.reset_token = token

    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password):
        if self.exists:
            self.__password = password
            return
        salt = bcrypt.gensalt(rounds=12)
        self.__password = bcrypt.hashpw(password.encode(), salt)

    def verify_password(self, password):
        res = bcrypt.checkpw(password.encode(), self.__password)
        logger.info(f"Password matching: {res}")
        return res

    def add_to_db(self):
        self.reset_token = secrets.token_urlsafe(32)
        db.add_user(self.username, self.email, self.__password, self.reset_token)

    def update_password(self, password):
        self.exists = False
        self.password = password
        db.update_user_password(self.__password, self.id)

    @staticmethod
    def random_password():
        lower = string.ascii_lowercase
        upper = string.ascii_uppercase
        digits = string.digits
        special = string.punctuation
        password = [
            secrets.choice(lower),
            secrets.choice(upper),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        all_characters = lower + upper + digits + special
        password += [secrets.choice(all_characters) for _ in range(20 - 4)]
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)

    @staticmethod
    def find_by_username(username):
        answer = db.find_by_username(username)
        if answer:
            id = answer[0]
            name = answer[1]
            email = answer[2]
            password = answer[3]
            token = answer[4]
            return User(name, password, email, exists=True, id=id, token=token)
        else:
            logger.info(f"No user with username: {username}")
            return None

    @staticmethod
    def find_by_email(email):
        answer = db.find_by_email(email)
        if answer:
            id = answer[0]
            name = answer[1]
            email = answer[2]
            password = answer[3]
            token = answer[4]
            return User(name, password, email, exists=True, id=id, token=token)
        else:
            logger.info(f"No user with email: {email}")
            return None

    @staticmethod
    def find_by_id(user_id):
        answer = db.find_by_id(user_id)
        if answer:
            id = answer[0]
            name = answer[1]
            email = answer[2]
            password = answer[3]
            token = answer[4]
            return User(name, password, email, exists=True, id=id, token=token)
        else:
            logger.info(f"No user with id: {user_id}")
            return None


@login_manager.user_loader
def load_user(user_id):
    return User.find_by_id(user_id)
