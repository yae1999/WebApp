# app.py
from flask import Flask, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

#Umgebungsvariablen holen
CLOUDSQL_CONNECTION_NAME = os.environ.get('CLOUDSQL_CONNECTION_NAME')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
DB_NAME = os.environ.get('DB_NAME')

# App Config erstellen
app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@/{DB_NAME}?unix_socket=/cloudsql/{CLOUDSQL_CONNECTION_NAME}'

# Kommunikation zwischen App und DB
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#Klasse Benutzer deklarieren - Angelehnt von MicroBlog
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

#Klasse Eintraege deklarieren - Angelehnt von MicroBlog
class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Registrierung eines neuen Benutzers - Angelehnt von MicroBlog
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = generate_password_hash(request.form.get('password'), method='sha256')

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for('index'))

    return render_template('register.html')

#Anmelden eines neuen Benutzers - Angelehnt von MicroBlog
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))

        flash('Falscher Benutzername oder Passwort')

    return render_template('login.html')

#Logout Vorgang eines Benutzers - Angelehnt von MicroBlog
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#Root Seite der App - Angelehnt von MicroBlog
@app.route('/')
@login_required
def index():
    entries = Entry.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', entries=entries)

#neuen Tagebuch Eintrag erstellen - Angelehnt von MicroBlog
@app.route('/add', methods=['POST'])
@login_required
def add():
    content = request.form.get('content')
    if content:
        new_entry = Entry(content=content, user_id=current_user.id)
        db.session.add(new_entry)
        db.session.commit()

    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
