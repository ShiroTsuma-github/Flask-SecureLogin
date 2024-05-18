import sys
import os
from flask import Flask, render_template, redirect, url_for, flash, g, request, Response
from werkzeug.middleware.proxy_fix import ProxyFix
from forms import RegisterForm, LoginForm, ChangeForm
from flask_login import current_user, login_user, login_required, logout_user
from dotenv import load_dotenv

ROOT_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(ROOT_DIR)
from logger import logger
from login_manager import login_manager
from user import User

load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config["SECRET_KEY"] = os.getenv("1171zxVHcVzQKWfLKQQc2gQrY9Jhwl2rF")
app.config["DATABASE_FILE"] = "./security/db.sqlite"
login_manager.init_app(app)


@app.before_request
def before_request():
    g.user = current_user


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/home")
@login_required
def home():
    return render_template("home.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if form.validate():
        user = User.find_by_email(form.email.data)
        if user is not None and user.verify_password(form.password.data):
            login_user(user)
            logger.info("logged in")
            redirect_url = request.args.get("next") or url_for("home")
            return redirect(redirect_url)
        logger.info("Did not pass check in app")
    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form, csrf_enabled=False)
    if form.validate():
        new_user = User(
            email=form.email.data,
            username=form.username.data,
            password=form.password.data,
        )
        new_user.add_to_db()
        flash("SAVE THIS RESET TOKEN. IT'S GENERATED ONCE AND NEVER ACCESSIBLE AGAIN!\n", 'warning')
        flash(f"{new_user.reset_token}", 'warning')
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/change_pass", methods=["GET", "POST"])
@login_required
def change_pass():
    form = ChangeForm(request.form)
    if form.validate():
        user = current_user
        if user.verify_password(form.password.data):
            user.update_password(form.new_password.data)
            logger.info("changed password")
            redirect_url = request.args.get("next") or url_for("home")
            return redirect(redirect_url)
        logger.info("Did not change password")
    return render_template("change_pass.html", form=form)


@app.route("/reset_token", methods=["GET", "POST"])
def use_token():
    if request.method == "POST":
        email = request.form.get('email')
        token = request.form.get('token')
        if email and token:
            user = User.find_by_email(email)
            if user and user.reset_token == token:
                new_pass = User.random_password()
                user.update_password(new_pass)
                return f'Temporary Password: {new_pass}\n<h1>Remember to change it instantly</h1><a href="/login">Login now</a>'
        else:
            return 'Missing email or token', 400


if __name__ == "__main__":
    app.run(debug=False, port=8201)

if __name__ == "app":
    app.run(port=8202)
