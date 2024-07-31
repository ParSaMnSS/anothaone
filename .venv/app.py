from flask import Flask, render_template, request, redirect, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  #gotta change it
jwt = JWTManager(app)

# SQLite setup
conn = sqlite3.connect("db.sqlite3", check_same_thread=False)
c = conn.cursor()

# Define WTForms
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
        confirmation = form.confirmation.data

        if c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchall():
            flash('User already registered')
        else:
            passhash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
            c.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, passhash))
            conn.commit()
            flash('Registered successfully')
            return redirect('/login')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

        if user is None:
            flash('User not found')
        else:
            passhash = user[2]
            if not check_password_hash(passhash, password):
                flash('Wrong password')
            else:
                access_token = create_access_token(identity=user[0])
                return jsonify(access_token=access_token)

    return render_template('login.html', form=form)

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route('/logout')
def logout():
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
