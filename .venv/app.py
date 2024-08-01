from flask import Flask, render_template, request, redirect, flash, session, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(16).hex()
app.config['JWT_SECRET_KEY'] = os.urandom(16).hex()
jwt = JWTManager(app)

# Connect to the SQLite database
def get_db_connection():
    conn = sqlite3.connect("db.sqlite3", check_same_thread=False)
    return conn

# Create users table if it doesn't exist
def create_users_table():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirmation = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=:email", {"email": email})
        if c.fetchone():
            flash('User already registered')
        else:
            passhash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
            c.execute('INSERT INTO users (email, password) VALUES (:email, :passhash)', {"email": email, "passhash": passhash})
            conn.commit()
            flash('Registered successfully')
            return redirect('/home')
        conn.close()

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=:email", {"email": email})
        user = c.fetchone()

        if user is None:
            flash('User not found')
        else:
            passhash = user[2]
            if not check_password_hash(passhash, password):
                flash('Wrong password')
            else:
                access_token = create_access_token(identity=user[0])
                return jsonify(access_token=access_token)
        conn.close()

    return render_template('login.html', form=form)

@app.route('/protected', methods=['GET'])
@jwt_required(refresh=True)
def protected():
    current_user = get_jwt_identity()
    return render_template('protected.html', user=current_user)

@app.route('/logout')
def logout():
    return redirect('/login')

@app.route('/home')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    create_users_table()
    app.run(debug=True)