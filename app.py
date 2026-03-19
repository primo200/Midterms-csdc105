from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from datetime import datetime
from config import Config
import hashlib
import base64
import os

db = SQLAlchemy()
csrf = CSRFProtect()

def verify_django_password(raw_password, encoded):
    """Verify password against Django's PBKDF2 format"""
    try:
        algorithm, iterations, salt, hash_value = encoded.split('$', 3)
        iterations = int(iterations)
        
        if algorithm == 'pbkdf2_sha256':
            new_hash = hashlib.pbkdf2_hmac(
                'sha256',
                raw_password.encode('utf-8'),
                salt.encode('utf-8'),
                iterations
            )
            new_hash = base64.b64encode(new_hash).decode('ascii').strip()
            return new_hash == hash_value
    except Exception as e:
        print(f"Password verification error: {e}")
        return False
    return False

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)
    csrf.init_app(app)
    
    #define models
    with app.app_context():
        #user model 
        class User(db.Model):
            __tablename__ = 'auth_user'
        
        #define columns based on your database schema (only the ones that exist)
            id = db.Column(db.Integer, primary_key=True)
            username = db.Column(db.String(150), nullable=False, unique=True)
            email = db.Column(db.String(254), nullable=False)
            password = db.Column(db.String(128), nullable=False)
            date_joined = db.Column(db.DateTime(timezone=True), nullable=False)
     
        
            def verify_password(self, raw_password):
                return verify_django_password(raw_password, self.password)
        
            def __repr__(self):
                return f"<User {self.username}>"
    
    #routes/views/urls
    @app.route('/')
    def index():
        return redirect(url_for('login'))
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            #find user by username
            user = User.query.filter_by(username=username).first()
            
            if user:
                if user.verify_password(password):
                    session['user_id'] = user.id
                    session['username'] = user.username
                    flash(f'Welcome back, {user.username}!', 'success')
                    return redirect(url_for('users_list'))
                else:
                    flash('Invalid password', 'error')
            else:
                flash('Username not found', 'error')
        
        return render_template('login.html', title='Login')
    
    @app.route('/register', methods=['POST'])
    def register():
        if request.method == 'POST':
            username = request.form.get('reg_username')
            email = request.form.get('email')
            password = request.form.get('reg_password')
            confirm_password = request.form.get('confirm_password')
            
            #validation
            if not username or not email or not password or not confirm_password:
                flash('All fields are required', 'error')
                return redirect(url_for('login'))
            
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return redirect(url_for('login'))
            
            #check if username already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already taken', 'error')
                return redirect(url_for('login'))
            
            #check if email already exists
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash('Email already registered', 'error')
                return redirect(url_for('login'))
            
            #password hashing using Django's PBKDF2 format
            salt = base64.b64encode(os.urandom(18)).decode('utf-8').replace('+', '.').replace('/', '.')[:22]
            iterations = 1000000
            hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations)
            hash_b64 = base64.b64encode(hash_bytes).decode('ascii').strip()
            django_password = f"pbkdf2_sha256${iterations}${salt}${hash_b64}"
            
            #create new users with all required fields based from database schema
            new_user = User(
                username=username,
                email=email,
                password=django_password,
                date_joined=datetime.utcnow()
            )
            
            try:
                db.session.add(new_user)
                db.session.commit()
                flash('Registration successful! Please login.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error creating user: {str(e)}', 'error')
            
            return redirect(url_for('login'))
    
    @app.route('/users')
    def users_list():
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        
        #Get all users from supabase database
        users = User.query.all()
        
        return render_template('users.html',
                             users=users,
                             title='User List')
    
    @app.route('/logout')
    def logout():
        session.clear()
        flash('You have been logged out', 'info')
        return redirect(url_for('login'))
    
    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)