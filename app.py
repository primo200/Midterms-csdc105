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
    
    with app.app_context():
        # ---------- USER MODEL ----------
        class User(db.Model):
            __tablename__ = 'auth_user'
            id = db.Column(db.Integer, primary_key=True)
            username = db.Column(db.String(150), nullable=False, unique=True)
            email = db.Column(db.String(254), nullable=False)
            password = db.Column(db.String(128), nullable=False)
            date_joined = db.Column(db.DateTime(timezone=True), nullable=False)
            
            def verify_password(self, raw_password):
                return verify_django_password(raw_password, self.password)
            
            def __repr__(self):
                return f"<User {self.username}>"
        
        # ---------- PRODUCT MODELS ----------
        # Use the actual table names from your Supabase (members_productstock, members_producttransaction)
        class ProductStock(db.Model):
            __tablename__ = 'members_productstock'
            id = db.Column(db.Integer, primary_key=True)
            name = db.Column(db.String(100), nullable=False)
            quantity = db.Column(db.Integer, default=0)
            created_at = db.Column(db.DateTime, default=datetime.utcnow)
            updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        class ProductTransaction(db.Model):
            __tablename__ = 'members_producttransaction'
            id = db.Column(db.Integer, primary_key=True)
            name = db.Column(db.String(100), nullable=False)
            quantity = db.Column(db.Integer, nullable=False)
            volume_liters = db.Column(db.Numeric(10, 3), nullable=False)
            price_per_unit = db.Column(db.Numeric(10, 2), nullable=False)
            total_price = db.Column(db.Numeric(10, 2), nullable=False)
            created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # ---------- ROUTES ----------
    @app.route('/')
    def index():
        return redirect(url_for('login'))
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter_by(username=username).first()
            if user and user.verify_password(password):
                session['user_id'] = user.id
                session['username'] = user.username
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('users_list'))
            else:
                flash('Invalid username or password', 'error')
        return render_template('login.html', title='Login')
    
    @app.route('/register', methods=['POST'])
    def register():
        username = request.form.get('reg_username')
        email = request.form.get('email')
        password = request.form.get('reg_password')
        confirm = request.form.get('confirm_password')
        
        if not all([username, email, password, confirm]):
            flash('All fields are required', 'error')
            return redirect(url_for('login'))
        if password != confirm:
            flash('Passwords do not match', 'error')
            return redirect(url_for('login'))
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return redirect(url_for('login'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('login'))
        
        # Django-compatible password hash
        salt = base64.b64encode(os.urandom(18)).decode('utf-8').replace('+', '.').replace('/', '.')[:22]
        iterations = 1000000
        hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations)
        hash_b64 = base64.b64encode(hash_bytes).decode('ascii').strip()
        django_password = f"pbkdf2_sha256${iterations}${salt}${hash_b64}"
        
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
        users = User.query.all()
        return render_template('users.html', users=users, title='User List')
    
    # ---------- PRODUCT ROUTES ----------
    @app.route('/products')
    def products():
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        stock_items = ProductStock.query.all()
        transactions = ProductTransaction.query.all()
        total_quantity = sum(t.quantity for t in transactions)
        total_amount = sum(float(t.total_price) for t in transactions)
        return render_template('products.html',
                               stock_items=stock_items,
                               transactions=transactions,
                               total_quantity=total_quantity,
                               total_amount=total_amount)
    
    @app.route('/add_product_stock', methods=['POST'])
    def add_product_stock():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        name = request.form.get('name')
        quantity = request.form.get('quantity')
        if name and quantity:
            new_stock = ProductStock(name=name, quantity=int(quantity))
            db.session.add(new_stock)
            db.session.commit()
            flash(f'Added {quantity} of {name} to stock', 'success')
        else:
            flash('Please fill all fields', 'error')
        return redirect(url_for('products'))
    
    @app.route('/delete_product_stock/<int:item_id>', methods=['POST'])
    def delete_product_stock(item_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        item = ProductStock.query.get_or_404(item_id)
        db.session.delete(item)
        db.session.commit()
        flash('Product deleted from stock', 'success')
        return redirect(url_for('products'))
    
    @app.route('/add_product_transaction', methods=['POST'])
    def add_product_transaction():
        if 'user_id' not in session:
            return redirect(url_for('login'))

        name = request.form.get('name')
        quantity = request.form.get('quantity')
        price_per_unit = request.form.get('price_per_unit')

        if not all([name, quantity, price_per_unit]):
            flash('Please fill all fields', 'error')
            return redirect(url_for('products'))

        try:
            qty = int(quantity)
            price = float(price_per_unit)
            total = qty * price

            # Find the product stock
            stock_item = ProductStock.query.filter_by(name=name).first()
            if not stock_item:
                flash(f'Product "{name}" not found in stock', 'error')
                return redirect(url_for('products'))

            # Check if enough stock is available
            if stock_item.quantity < qty:
                flash(f'Insufficient stock. Only {stock_item.quantity} available.', 'error')
                return redirect(url_for('products'))

            # Decrease stock
            stock_item.quantity -= qty

            # Create transaction record
            new_trans = ProductTransaction(
                name=name,
                quantity=qty,
                volume_liters=0,          # default since volume removed from UI
                price_per_unit=price,
                total_price=total
            )

            # Commit both changes in one transaction
            db.session.add(new_trans)
            db.session.commit()

            flash(f'Transaction added. Stock of "{name}" decreased by {qty}.', 'success')

        except Exception as e:
            db.session.rollback()
            flash(f'Error processing transaction: {str(e)}', 'error')

        return redirect(url_for('products'))
    
    @app.route('/delete_product_transaction/<int:transaction_id>', methods=['POST'])
    def delete_product_transaction(transaction_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        trans = ProductTransaction.query.get_or_404(transaction_id)
        db.session.delete(trans)
        db.session.commit()
        flash('Transaction deleted', 'success')
        return redirect(url_for('products'))
    
    @app.route('/logout')
    def logout():
        session.clear()
        flash('You have been logged out', 'info')
        return redirect(url_for('login'))
    
    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
