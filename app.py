#! ./venv/bin/python
# -*- coding: utf-8 -*-

from flask import Flask, render_template
from flask.ext.principal import Principal, Permission, RoleNeed, Identity, AnonymousIdentity, identity_changed
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField
from flask_login import LoginManager, UserMixin, login_user, logout_user


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['DEBUG'] = True
app.config['SERVER_NAME'] = '127.0.0.1:5006'

Principal(app)
admin_permission = Permission(RoleNeed('admin'))

login_manager = LoginManager(app)
users = {'admin': {'pw': 'password'}}

class User(UserMixin):
    pass


@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    # Validate form input
    if form.validate_on_submit():
        # Retrieve the user from the hypothetical datastore
        user = load_user(form.email.data)

        # Compare passwords (use password hashing production)
        if form.password.data == user.password:
            # Keep the user info in the session using Flask-Login
            login_user(user)

            # Tell Flask-Principal the identity changed
            identity_changed.send(current_app._get_current_object(),
                                  identity=Identity(user.id))

            return redirect(request.args.get('next') or '/')

    return render_template('login.html', form=form)

@login_manager.user_loader
def load_user(userid):
    user = User()
    user.id = userid
    return user

class LoginForm(Form):
    email = StringField()
    password = PasswordField()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/srv_or_anon/')
def srv_or_anon_page():
    return render_template('srv_or_anon.html')

@app.route('/srv_or_auth/')
@admin_permission.require()
def srv_or_auth_page():
    return render_template('srv_or_auth.html')


app.run()