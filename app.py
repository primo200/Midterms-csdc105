from flask import Flask, app, render_template, request, redirect, url_for, flash, session, jsonify
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
    
 
        #Models
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

    class FuelTransaction(db.Model):
            __tablename__ = 'members_fueltransaction'  
            id = db.Column(db.Integer, primary_key=True)
            machine_number = db.Column(db.Integer, nullable=False)
            fuel_type = db.Column(db.String(50), nullable=False)
            amount = db.Column(db.Numeric(10, 2), nullable=False)
            liters = db.Column(db.Numeric(10, 3), nullable=False)
            price_per_liter = db.Column(db.Numeric(6, 2), nullable=False)
            created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    class FuelPriceHistory(db.Model):
            __tablename__ = 'fuel_price_history'
            id = db.Column(db.Integer, primary_key=True)
            fuel_type = db.Column(db.String(50), nullable=False)
            old_price = db.Column(db.Numeric(6,2), nullable=False)
            new_price = db.Column(db.Numeric(6,2), nullable=False)
            changed_at = db.Column(db.DateTime, default=datetime.utcnow)

    class FuelStock(db.Model):
            __tablename__ = 'fuel_stock'
            id = db.Column(db.Integer, primary_key=True)
            machine_number = db.Column(db.Integer, nullable=False)
            fuel_type = db.Column(db.String(50), nullable=False)
            stock_liters = db.Column(db.Numeric(10, 2), nullable=False, default=1000)
            last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    #Routes
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
                return redirect(url_for('home'))
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
        
        #password hashing
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
    
    #Product Routes
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
    
    @app.route('/transactions')
    def transactions():
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        stock_items = ProductStock.query.all()
        transactions = ProductTransaction.query.order_by(ProductTransaction.created_at.desc()).all()
        fuel_transactions = FuelTransaction.query.order_by(FuelTransaction.created_at.desc()).all()
        total_quantity = sum(t.quantity for t in transactions)
        total_amount = sum(float(t.total_price) for t in transactions)
        return render_template('transactions.html',
                            stock_items=stock_items,
                            transactions=transactions,
                            fuel_transactions=fuel_transactions,
                            total_quantity=total_quantity,
                            total_amount=total_amount)

    @app.route('/delete_fuel_transaction_form/<int:trans_id>', methods=['POST'])
    def delete_fuel_transaction_form(trans_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        trans = FuelTransaction.query.get_or_404(trans_id)
        db.session.delete(trans)
        db.session.commit()
        flash('Fuel transaction deleted', 'success')
        return redirect(url_for('transactions'))

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

            #find product stock
            stock_item = ProductStock.query.filter_by(name=name).first()
            if not stock_item:
                flash(f'Product "{name}" not found in stock', 'error')
                return redirect(url_for('products'))

            #check if enough stock is available
            if stock_item.quantity < qty:
                flash(f'Insufficient stock. Only {stock_item.quantity} available.', 'error')
                return redirect(url_for('products'))

            #Decrease stock
            stock_item.quantity -= qty

            #Create transaction 
            new_trans = ProductTransaction(
                name=name,
                quantity=qty,
                volume_liters=0,          #set to zero since it is not desplayed/used in UI
                price_per_unit=price,
                total_price=total
            )

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
    
    @app.route('/sales')
    def sales():
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        product_transactions = ProductTransaction.query.order_by(ProductTransaction.created_at.desc()).all()
        return render_template('sales.html', product_transactions=product_transactions)

    @app.route('/logout')
    def logout():
        session.clear()
        flash('You have been logged out', 'info')
        return redirect(url_for('login'))
    

    @app.route('/home')
    def home():
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
    
        # Fetch data for stats
        from models import ProductStock, ProductTransaction
        stock_items = ProductStock.query.all()
        transactions = ProductTransaction.query.all()
    
        total_stock_items = len(stock_items)
        total_transactions = len(transactions)
        total_sales_value = sum(float(t.total_price) for t in transactions)
    
        return render_template('home.html',
                           total_stock_items=total_stock_items,
                           total_transactions=total_transactions,
                           total_sales_value=total_sales_value)

    @app.route('/fuel')
    def fuel():
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))

        fuel_transactions = FuelTransaction.query.order_by(FuelTransaction.created_at.desc()).all()
        fuel_transactions_json = [
            {
                'id': t.id,
                'machine_number': t.machine_number,
                'fuel_type': t.fuel_type,
                'amount': float(t.amount),
                'liters': float(t.liters),
                'price_per_liter': float(t.price_per_liter),
                'created_at': t.created_at.isoformat() if t.created_at else None
            }
            for t in fuel_transactions
        ] if fuel_transactions else []

        last_unleaded = FuelPriceHistory.query.filter_by(fuel_type='Unleaded').order_by(FuelPriceHistory.changed_at.desc()).first()
        last_diesel = FuelPriceHistory.query.filter_by(fuel_type='Diesel').order_by(FuelPriceHistory.changed_at.desc()).first()
        current_unleaded = last_unleaded.new_price if last_unleaded else 60.0
        current_diesel = last_diesel.new_price if last_diesel else 55.0

        return render_template('fuel.html',
                               fuel_transactions=fuel_transactions,
                               fuel_transactions_json=fuel_transactions_json,
                               current_unleaded=current_unleaded,
                               current_diesel=current_diesel)
        

    @app.route('/save_fuel_transaction', methods=['POST'])
    def save_fuel_transaction():
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        data = request.get_json()
        machine_number = data.get('machine_number')
        fuel_type = data.get('fuel_type')
        amount = data.get('amount')
        liters = data.get('liters')
        price_per_liter = data.get('price_per_liter')

        if not all([machine_number, fuel_type, amount, liters, price_per_liter]):
            return jsonify({'success': False, 'error': 'Missing fields'}), 400

        # Fetch stock
        stock = FuelStock.query.filter_by(
            machine_number=machine_number,
            fuel_type=fuel_type
        ).first()

        if not stock:
            return jsonify({'success': False, 'error': 'Stock record not found'}), 404

        if float(stock.stock_liters) < float(liters):
            return jsonify({
                'success': False,
                'error': f'Insufficient stock. Available: {float(stock.stock_liters):.2f} L'
            }), 400

        # Deduct stock
        stock.stock_liters = float(stock.stock_liters) - float(liters)
        stock.last_updated = datetime.utcnow()

        # Record transaction
        new_trans = FuelTransaction(
            machine_number=machine_number,
            fuel_type=fuel_type,
            amount=amount,
            liters=liters,
            price_per_liter=price_per_liter
        )
        db.session.add(new_trans)
        db.session.commit()

        return jsonify({
            'success': True,
            'transaction_id': new_trans.id,
            'new_stock': float(stock.stock_liters),
            'created_at': new_trans.created_at.isoformat()
        })

    @app.route('/get_fuel_stock', methods=['GET'])
    def get_fuel_stock():
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        stocks = FuelStock.query.all()
        return jsonify([{
            'machine_number': s.machine_number,
            'fuel_type': s.fuel_type,
            'stock_liters': float(s.stock_liters)
        } for s in stocks])

    @app.route('/add_fuel_stock', methods=['POST'])
    def add_fuel_stock():
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        data = request.get_json()
        machine_number = data.get('machine_number')
        fuel_type = data.get('fuel_type')
        add_liters = float(data.get('add_liters', 0))

        if add_liters <= 0:
            return jsonify({'success': False, 'error': 'Invalid amount'}), 400

        stock = FuelStock.query.filter_by(
            machine_number=machine_number,
            fuel_type=fuel_type
        ).first()

        if not stock:
            return jsonify({'success': False, 'error': 'Stock record not found'}), 404

        new_total = float(stock.stock_liters) + add_liters
        if new_total > 1000:
            return jsonify({'success': False, 'error': 'Cannot exceed 1000L capacity'}), 400

        stock.stock_liters = new_total
        stock.last_updated = datetime.utcnow()
        db.session.commit()

        return jsonify({'success': True, 'new_stock': float(stock.stock_liters)})

    @app.route('/delete_fuel_transaction', methods=['DELETE'])
    def delete_fuel_transaction():
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        trans_id = request.args.get('id')
        if not trans_id:
            return jsonify({'success': False, 'error': 'Missing id'}), 400
        trans = FuelTransaction.query.get(trans_id)
        if not trans:
            return jsonify({'success': False, 'error': 'Transaction not found'}), 404
        db.session.delete(trans)
        db.session.commit()
        return jsonify({'success': True})

    @app.route('/get_fuel_transactions', methods=['GET'])
    def get_fuel_transactions():
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        transactions = FuelTransaction.query.order_by(FuelTransaction.created_at.desc()).all()
        return jsonify([{
            'id': t.id,
            'machine_number': t.machine_number,
            'fuel_type': t.fuel_type,
            'amount': float(t.amount),
            'liters': float(t.liters),
            'price_per_liter': float(t.price_per_liter),
            'created_at': t.created_at.isoformat() if t.created_at else None
        } for t in transactions])

    @app.route('/get_fuel_prices', methods=['GET'])
    def get_fuel_prices():
        
        unleaded = FuelPriceHistory.query.filter_by(fuel_type='Unleaded').order_by(FuelPriceHistory.changed_at.desc()).first()
        diesel = FuelPriceHistory.query.filter_by(fuel_type='Diesel').order_by(FuelPriceHistory.changed_at.desc()).first()
        return jsonify({
            'unleaded': float(unleaded.new_price) if unleaded else 60.0,
            'diesel': float(diesel.new_price) if diesel else 55.0
        })

    @app.route('/update_fuel_price', methods=['POST'])
    def update_fuel_price():
        data = request.get_json()
        fuel_type = data.get('fuel_type')
        new_price = float(data.get('new_price'))
        # Get current price (latest history entry)
        last = FuelPriceHistory.query.filter_by(fuel_type=fuel_type).order_by(FuelPriceHistory.changed_at.desc()).first()
        old_price = float(last.new_price) if last else (60.0 if fuel_type == 'Unleaded' else 55.0)
        record = FuelPriceHistory(fuel_type=fuel_type, old_price=old_price, new_price=new_price)
        db.session.add(record)
        db.session.commit()
        return jsonify({'success': True, 'old_price': old_price, 'new_price': new_price})

    @app.route('/fuel_price_history', methods=['GET'])
    def fuel_price_history():
        history = FuelPriceHistory.query.order_by(FuelPriceHistory.changed_at.desc()).all()
        return jsonify([{
            'id': h.id,
            'fuel_type': h.fuel_type,
            'old_price': float(h.old_price),
            'new_price': float(h.new_price),
            'changed_at': h.changed_at.isoformat()
        } for h in history])

    @app.route('/history')
    def history():
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        last_unleaded = FuelPriceHistory.query.filter_by(fuel_type='Unleaded').order_by(FuelPriceHistory.changed_at.desc()).first()
        last_diesel = FuelPriceHistory.query.filter_by(fuel_type='Diesel').order_by(FuelPriceHistory.changed_at.desc()).first()
        current_unleaded = last_unleaded.new_price if last_unleaded else 60.0
        current_diesel = last_diesel.new_price if last_diesel else 55.0
        return render_template('history.html',
                               current_unleaded=current_unleaded,
                               current_diesel=current_diesel)

    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
