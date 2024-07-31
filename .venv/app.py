from flask import Flask, url_for, render_template, request, redirect, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3


conn = sqlite3.connect("db.sqlite3", check_same_thread=False)
c = conn.cursor()


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods = ['POST', 'GET'])
def register():
    if request.method == 'POST':
        if not request.form.get('email') or not request.form.get('password') or not request.form.get('confirmation'):
            flash('Please fill out the fields')
        if request.form.get('password') != request.form.get('confirmation'):
            flash('Password confirmation doesnt match the original password')
        #to check the email

        exist = c.execute('SELECT * FROM users WHERE email=:email', {'email': request.form.get('email')}).fetchall()
        exist = c.execute("SELECT * FROM users WHERE email=:email", {"email": request.form.get("email")}).fetchall()


        if len(exist) != 0:
            flash('User already registered')
        
        passhash = generate_password_hash(request.form.get("password"), method="pbkdf2:sha256", salt_length=8)

        c.execute('INSERT INFO users (email, password) VALUES (:email, :password)', {'email: ': request.form.get('email'), 'password: ': passhash})
        conn.commit()

        flash('registered successfully')
        return render_template('home.html')
    else: 
        return render_template('register.html')


@app.route('/login', methods = ['POST', 'GET'])
def login():

    if request.method == 'POST':
        if not request.form.get('email') or not request.form.get('password'):
            flash('Please fill the required fields')
            # use from wtforms.validators import DataRequired instead

        user = c.execute("SELECT * FROM users WHERE email=:email", {"email": request.form.get("email")}).fetchall()

        if len(user) != 1:
            flash('You didnt register')
        
        passhash = user[0][2]
        if check_password_hash(passhash, request.form.get('password')) == False:
            flash('Wrong password')
        
        session['user_id'] = user[0][0]

        return redirect('/dashboard')
    else:
        return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)