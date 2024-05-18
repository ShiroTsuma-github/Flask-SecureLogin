import sys
import os
from flask_wtf import Form
from wtforms import BooleanField, PasswordField, SubmitField, StringField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp
from wtforms_validators import NotEqualTo

ROOT_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(ROOT_DIR)

from flask_login import current_user
from user import User
from logger import logger


class LoginForm(Form):
    email = StringField("Email", validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Log In")

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)

    def validate(self):
        initial_validation = super(LoginForm, self).validate()
        if not initial_validation:
            return False
        user = User.find_by_email(self.email.data)
        if not user:
            self.email.errors.append("Unknown email")
            logger.info(f"Email not found: {self.email.data}")
            return False
        if not user.verify_password(self.password.data):
            self.password.errors.append("Invalid password")
            logger.info(f"Incorrect password: {self.password.data}")
            return False
        return True


class RegisterForm(Form):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=3, max=32)]
    )
    email = StringField(
        "Email", validators=[DataRequired(), Email(), Length(min=6, max=40)]
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=12, max=64),
            Regexp(
                "(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).+",
                message="Must contain at least one number, one uppercase and one lowercase letter.",
            ),
        ],
    )
    confirm = PasswordField(
        "Verify password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match"),
        ],
    )

    def __init__(self, *args, **kwargs):
        super(RegisterForm, self).__init__(*args, **kwargs)

    def validate(self):
        initial_validation = super(RegisterForm, self).validate()
        if not initial_validation:
            return False
        user = User.find_by_username(username=self.username.data)
        if user:
            self.username.errors.append("Username already registered")
            return False
        user = User.find_by_email(email=self.email.data)
        if user:
            self.email.errors.append("Email already registered")
            return False
        return True


class ChangeForm(Form):
    password = PasswordField("Password", validators=[DataRequired()])
    new_password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            NotEqualTo("password", message="Password must be different"),
            Length(min=12, max=64),
            Regexp(
                "(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).+",
                message="Must contain at least one number, one uppercase and one lowercase letter.",
            ),
        ],
    )
    confirm = PasswordField(
        "Verify password",
        validators=[
            DataRequired(),
            EqualTo("new_password", message="Passwords must match"),
        ],
    )

    def __init__(self, *args, **kwargs):
        super(ChangeForm, self).__init__(*args, **kwargs)

    def validate(self):
        initial_validation = super(ChangeForm, self).validate()
        if not initial_validation:
            return False
        user = current_user
        if not user.verify_password(self.password.data):
            return False
        return True
