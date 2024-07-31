from flask import Flask, render_template, request, redirect, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from werkzeug.security import check_password_hash, generate_password_hash #hashes a password and verifies if a password matches the hash 
from flask_jwt_extended import JWTManager #manages jwt for auth
from flask_jwt_extended import create_access_token # creates jwt for user authentication 
from flask_jwt_extended import jwt_required # ensures that the request has a valid jwt 
from flask_jwt_extended import get_jwt_identity #identifies the current user from the jwt   
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
import os



app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(16).hex()
app.config['JWT_SECRET_KEY'] = 'super-secret-key'

jwt = JWTManager(app)

# Create a connection pool with PostgreSQL
DATABASE_URL = 'postgresql://parsa:parsa123@localhost/mydb.db'
engine = create_engine(DATABASE_URL)
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

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

        # create a session from the session maker
        session = db_session()

        try:
            user = session.execute("SELECT * FROM users WHERE email=:email", {"email": email}).fetchone()  
            if user:  
                flash('User already registered')
            else:
                passhash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8) 
                session.execute('INSERT INTO users (email, password) VALUES (:email, :password)', {"email": email, "password": passhash}) 
                session.commit()
                flash('Registered successfully')
                return redirect('/login')
        finally:
            session.close() 

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        session = db_session()

        try:
            user = session.execute("SELECT * FROM users WHERE email=:email", {"email": email}).fetchone()

            if user is None:
                flash('User not found')
            else:
                passhash = user[2]
                if not check_password_hash(passhash, password):
                    flash('Wrong password')
                else:
                    access_token = create_access_token(identity=user[0])
                    return redirect('/protected')
        finally:
            session.close()  

    return render_template('login.html', form=form)

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return render_template('protected.html', user=current_user)

@app.route('/logout')
def logout():
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)