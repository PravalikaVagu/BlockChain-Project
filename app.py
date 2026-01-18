import hashlib
import json
import os
import pymysql
from functools import wraps
from datetime import datetime

from flask import Flask, jsonify, request, render_template, redirect, url_for, session, flash, g

app = Flask(__name__)
app.secret_key = os.urandom(24) # Used for session management

# --- Database Connection Details (for MySQL with XAMPP) ---
MYSQL_HOST = "localhost"
MYSQL_USER = "root"
MYSQL_PASSWORD = "" # Default XAMPP root password is empty
MYSQL_DB = "finalsupply"

def get_db_connection():
    """Establishes and returns a new MySQL database connection."""
    conn = None
    try:
        conn = pymysql.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB,
            cursorclass=pymysql.cursors.DictCursor # Returns rows as dictionaries
        )
        return conn
    except pymysql.Error as e:
        print(f"Error connecting to MySQL database: {e}")
        # Only flash if in a request context
        if app.has_request_context():
            flash(f"Database connection error: {e}. Please ensure MySQL is running and database '{MYSQL_DB}' exists.", 'danger')
        return None

# Close database connection at the end of the request
@app.teardown_appcontext
def close_db_connection(exception):
    conn = getattr(g, '_database', None)
    if conn is not None:
        conn.close()

# --- Jinja2 Custom Filter ---
@app.template_filter('timestamp_to_datetime')
def _jinja2_filter_datetime(value, format_string='%Y-%m-%d %H:%M:%S'):
    """
    Converts a Unix timestamp (float/int) or a datetime object
    to a human-readable datetime string.
    """
    if value is None:
        return ""
    
    # If it's already a datetime object, format it directly
    if isinstance(value, datetime):
        return value.strftime(format_string)
    # If it's a number (timestamp), convert it to datetime first
    elif isinstance(value, (int, float)):
        return datetime.fromtimestamp(value).strftime(format_string)
    # Otherwise, try to convert it to float (for robustness if it's a string timestamp)
    else:
        try:
            return datetime.fromtimestamp(float(value)).strftime(format_string)
        except (ValueError, TypeError):
            return "" # Return empty string or handle error as appropriate

# --- SHA256 Hashing Function ---
def generate_sha256_hash(data_string):
    """Generates a SHA256 hash for a given string."""
    return hashlib.sha256(data_string.encode('utf-8')).hexdigest()

# --- User Authentication Decorators ---
def login_required(f):
    """Decorator to ensure a user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('You need to be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    """Decorator to restrict access based on user role."""
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if session.get('role') not in roles:
                flash("You don't have the necessary permissions to access this page.", 'danger')
                return redirect(url_for('home'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

# --- Routes ---

@app.route('/')
def index():
    """Redirects to login page."""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        if conn is None:
            return render_template('login.html') # Stay on login if DB error
        
        cursor = conn.cursor()
        # Fetch is_active status along with other user details
        cursor.execute("SELECT id, username, password, role, is_active FROM Users WHERE username = %s AND password = %s", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Check if user is active
            if user['is_active'] == 0: # Assuming 0 for inactive/disabled
                flash('Your account is currently on hold. Please contact an administrator for assistance.', 'danger')
                return render_template('login.html')

            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Welcome, {user["username"]}!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles new user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        conn = get_db_connection()
        if conn is None:
            return render_template('register.html')
        
        cursor = conn.cursor()
        try:
            # New users default to is_active = TRUE as per table definition
            cursor.execute("INSERT INTO Users (username, password, role) VALUES (%s, %s, %s)", (username, password, role))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except pymysql.err.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'danger')
        except Exception as e:
            flash(f'An error occurred during registration: {e}', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """Logs out the current user."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    """Dashboard based on user role."""
    if session.get('role') == 'Admin':
        return redirect(url_for('admin_dashboard'))
    elif session.get('role') == 'Producer':
        return redirect(url_for('producer_dashboard'))
    elif session.get('role') == 'Consumer':
        return redirect(url_for('consumer_dashboard'))
    return redirect(url_for('login'))

# --- Producer Routes ---
@app.route('/producer_dashboard')
@login_required
@role_required(['Producer'])
def producer_dashboard():
    """Producer's dashboard to add products and view their own products."""
    conn = get_db_connection()
    if conn is None:
        return render_template('producer_dashboard.html', products=[])
    
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Products WHERE producer_username = %s ORDER BY created_at DESC", (session['username'],))
    my_products = cursor.fetchall()
    conn.close()
    return render_template('producer_dashboard.html', my_products=my_products)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
@role_required(['Producer'])
def add_product():
    """Allows producer to add a new product and its initial supply event."""
    if request.method == 'POST':
        food_item_id = request.form['food_item_id'].strip()
        product_name = request.form['product_name'].strip()
        description = request.form['description'].strip()
        price = request.form['price'].strip() # NEW: Get price from form
        event_type = request.form['event_type'].strip()
        location = request.form['location'].strip()
        details = request.form.get('details', '').strip() # Optional event details

        if not all([food_item_id, product_name, event_type, location, price]): # NEW: price is required
            flash('Please fill in all required product and initial event fields, including price.', 'danger')
            return redirect(url_for('add_product'))

        try:
            price = float(price) # Convert price to float
            if price <= 0:
                flash('Price must be a positive number.', 'danger')
                return redirect(url_for('add_product'))
        except ValueError:
            flash('Invalid price format. Please enter a number.', 'danger')
            return redirect(url_for('add_product'))


        # Data for hashing (ensure consistency for verification)
        # Using a JSON string for consistent hashing order
        data_to_hash = {
            "food_item_id": food_item_id,
            "product_name": product_name,
            "description": description,
            "producer_username": session['username'],
            "price": price # NEW: Include price in hash
        }
        hash_code = generate_sha256_hash(json.dumps(data_to_hash, sort_keys=True))

        conn = get_db_connection()
        if conn is None:
            return render_template('add_product.html')
        
        cursor = conn.cursor()
        try:
            # Insert product into Products table
            cursor.execute(
                "INSERT INTO Products (food_item_id, product_name, description, producer_username, hash_code, verification_status, price) VALUES (%s, %s, %s, %s, %s, 'Pending', %s)", # NEW: Add price
                (food_item_id, product_name, description, session['username'], hash_code, price)
            )
            
            # Insert initial supply chain event
            cursor.execute(
                "INSERT INTO SupplyChainEvents (food_item_id, event_type, location, details) VALUES (%s, %s, %s, %s)",
                (food_item_id, event_type, location, details)
            )
            conn.commit()
            flash(f'Product "{product_name}" (ID: {food_item_id}) added successfully and is awaiting Admin verification!', 'success')
            return redirect(url_for('producer_dashboard'))
        except pymysql.err.IntegrityError as e:
            if "Duplicate entry" in str(e) and "food_item_id" in str(e):
                flash(f'Product ID "{food_item_id}" already exists. Please use a unique ID.', 'danger')
            else:
                flash(f'Database error: {e}', 'danger')
        except Exception as e:
            flash(f'An unexpected error occurred: {e}', 'danger')
        finally:
            conn.close()

    return render_template('add_product.html')

@app.route('/add_supply_event/<food_item_id>', methods=['GET', 'POST'])
@login_required
@role_required(['Producer'])
def add_supply_event(food_item_id):
    """Allows producer to add a new supply chain event for an existing product."""
    conn = get_db_connection()
    if conn is None:
        return redirect(url_for('producer_dashboard'))

    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Products WHERE food_item_id = %s AND producer_username = %s", (food_item_id, session['username']))
    product = cursor.fetchone()

    if not product:
        flash('Product not found or you do not have permission to add events for it.', 'danger')
        conn.close()
        return redirect(url_for('producer_dashboard'))

    if request.method == 'POST':
        event_type = request.form['event_type'].strip()
        location = request.form['location'].strip()
        details = request.form.get('details', '').strip()

        if not all([event_type, location]):
            flash('Please fill in all required event fields.', 'danger')
            conn.close()
            return redirect(url_for('add_supply_event', food_item_id=food_item_id))
        
        try:
            cursor.execute(
                "INSERT INTO SupplyChainEvents (food_item_id, event_type, location, details) VALUES (%s, %s, %s, %s)",
                (food_item_id, event_type, location, details)
            )
            conn.commit()
            flash(f'Supply event "{event_type}" added for product "{food_item_id}".', 'success')
            return redirect(url_for('producer_dashboard'))
        except Exception as e:
            flash(f'An error occurred adding event: {e}', 'danger')
        finally:
            conn.close()
            
    conn.close() # Close connection for GET request
    return render_template('add_supply_event.html', product=product)

# --- Admin Routes ---
@app.route('/admin_dashboard')
@login_required
@role_required(['Admin'])
def admin_dashboard():
    """Admin's dashboard to manage users and verify products."""
    conn = get_db_connection()
    if conn is None:
        return render_template('admin_dashboard.html', users=[], pending_products=[], verified_products=[], tampered_products=[])
    
    cursor = conn.cursor()
    # Fetch is_active status for users
    cursor.execute("SELECT id, username, role, is_active FROM Users")
    users = cursor.fetchall()

    cursor.execute("SELECT * FROM Products WHERE verification_status = 'Pending' ORDER BY created_at DESC")
    pending_products = cursor.fetchall()

    cursor.execute("SELECT * FROM Products WHERE verification_status = 'Verified' ORDER BY verified_at DESC")
    verified_products = cursor.fetchall()

    cursor.execute("SELECT * FROM Products WHERE verification_status = 'Tampered' ORDER BY created_at DESC")
    tampered_products = cursor.fetchall()

    conn.close()
    return render_template('admin_dashboard.html', users=users, pending_products=pending_products, verified_products=verified_products, tampered_products=tampered_products)

@app.route('/admin/verify_product/<food_item_id>', methods=['POST'])
@login_required
@role_required(['Admin'])
def admin_verify_product(food_item_id):
    """Admin verifies the integrity of a product's initial data."""
    conn = get_db_connection()
    if conn is None:
        return redirect(url_for('admin_dashboard'))

    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Products WHERE food_item_id = %s", (food_item_id,))
    product = cursor.fetchone()

    if not product:
        flash('Product not found for verification.', 'danger')
        conn.close()
        return redirect(url_for('admin_dashboard'))

    # Re-calculate hash based on stored data
    data_to_hash = {
        "food_item_id": product['food_item_id'],
        "product_name": product['product_name'],
        "description": product['description'],
        "producer_username": product['producer_username'],
        "price": float(product['price']) # Include price in hash for verification
    }
    recalculated_hash = generate_sha256_hash(json.dumps(data_to_hash, sort_keys=True))

    if recalculated_hash == product['hash_code']:
        # Hashes match, data is intact
        cursor.execute(
            "UPDATE Products SET verification_status = 'Verified', verified_by = %s, verified_at = %s WHERE food_item_id = %s",
            (session['username'], datetime.now(), food_item_id)
        )
        conn.commit()
        flash(f'Product "{food_item_id}" has been VERIFIED. Data integrity confirmed.', 'success')
    else:
        # Hashes do not match, data tampering detected
        cursor.execute(
            "UPDATE Products SET verification_status = 'Tampered', verified_by = %s, verified_at = %s WHERE food_item_id = %s",
            (session['username'], datetime.now(), food_item_id)
        )
        conn.commit()
        flash(f'Product "{food_item_id}" data TAMPERING DETECTED! Cannot be trusted.', 'danger')
    
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle_user_status/<int:user_id>', methods=['POST'])
@login_required
@role_required(['Admin'])
def admin_toggle_user_status(user_id):
    """Admin toggles a user's active status (enable/disable)."""
    if session.get('user_id') == user_id:
        flash("You cannot disable or enable your own account.", 'danger')
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    if conn is None:
        return redirect(url_for('admin_dashboard'))
    
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, role, is_active FROM Users WHERE id = %s", (user_id,))
        user_to_toggle = cursor.fetchone()
        
        if user_to_toggle and user_to_toggle['role'] != 'Admin':
            new_status = not user_to_toggle['is_active'] # Toggle the current status
            cursor.execute("UPDATE Users SET is_active = %s WHERE id = %s", (new_status, user_id))
            conn.commit()
            status_message = "enabled" if new_status else "disabled"
            flash(f"User '{user_to_toggle['username']}' has been {status_message}.", 'success')
        elif user_to_toggle and user_to_toggle['role'] == 'Admin':
            flash("Cannot change the active status of an Admin account.", 'danger')
        else:
            flash("User not found.", 'danger')

    except Exception as e:
        conn.rollback()
        flash(f"Error toggling user status: {e}", 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required(['Admin'])
def admin_delete_user(user_id):
    """Admin deletes a user account."""
    if session.get('user_id') == user_id:
        flash("You cannot delete your own account.", 'danger')
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    if conn is None:
        return redirect(url_for('admin_dashboard'))
    
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, role FROM Users WHERE id = %s", (user_id,))
        user_to_delete = cursor.fetchone()

        if user_to_delete and user_to_delete['role'] != 'Admin':
            # --- IMPORTANT: Handle CASCADE DELETES for related tables ---
            # If your foreign keys in Products, Orders, OrderDetails, SupplyChainEvents, UserAddresses
            # are *not* set with ON DELETE CASCADE, you MUST manually delete records
            # from those tables that depend on this user's ID or username.
            # Example (if you don't use ON DELETE CASCADE):
            # cursor.execute("DELETE FROM Orders WHERE user_id = %s", (user_id,))
            # cursor.execute("DELETE FROM UserAddresses WHERE user_id = %s", (user_id,))
            # cursor.execute("DELETE FROM Products WHERE producer_username = %s", (user_to_delete['username'],))
            # (Note: Deleting products would also require handling SupplyChainEvents and OrderDetails if they don't cascade)

            # For a more robust solution, ensure your db.sql has ON DELETE CASCADE
            # for foreign key relationships where appropriate (e.g., Orders.user_id, UserAddresses.user_id, Products.producer_username).
            
            # Delete the user
            cursor.execute("DELETE FROM Users WHERE id = %s", (user_id,))
            conn.commit()
            flash(f"User '{user_to_delete['username']}' and their associated data have been permanently deleted.", 'success')
        elif user_to_delete and user_to_delete['role'] == 'Admin':
            flash("Cannot delete an Admin account.", 'danger')
        else:
            flash("User not found.", 'danger')

    except pymysql.err.IntegrityError as e:
        conn.rollback()
        flash(f"Cannot delete user due to existing related data. Please ensure foreign key constraints are handled (e.g., ON DELETE CASCADE) or remove dependent records manually. Error: {e}", 'danger')
    except Exception as e:
        conn.rollback()
        flash(f"Error deleting user: {e}", 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin_dashboard'))


# --- Consumer Routes (with E-commerce features) ---
@app.route('/consumer_dashboard')
@login_required
@role_required(['Consumer'])
def consumer_dashboard():
    """Consumer's dashboard to browse verified products."""
    conn = get_db_connection()
    if conn is None:
        return render_template('consumer_dashboard.html', products=[])
    
    cursor = conn.cursor()
    # Only show products that are 'Verified' by an admin
    cursor.execute("SELECT * FROM Products WHERE verification_status = 'Verified' ORDER BY product_name")
    products = cursor.fetchall()
    conn.close()
    return render_template('consumer_dashboard.html', products=products)

@app.route('/product_details/<food_item_id>')
@login_required
@role_required(['Consumer', 'Producer', 'Admin']) # Allow Producer and Admin to view details
def product_details(food_item_id):
    """Displays details and supply chain events for a specific product."""
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('consumer_dashboard'))

    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Products WHERE food_item_id = %s", (food_item_id,))
    product = cursor.fetchone()

    if not product:
        flash('Product not found.', 'danger')
        conn.close()
        return redirect(url_for('consumer_dashboard'))
    
    # Fetch supply chain events for this product
    cursor.execute("SELECT * FROM SupplyChainEvents WHERE food_item_id = %s ORDER BY event_timestamp", (food_item_id,))
    events = cursor.fetchall()

    conn.close()
    return render_template('product_details.html', product=product, events=events)

@app.route('/add_to_cart/<food_item_id>', methods=['POST'])
@login_required
@role_required(['Consumer'])
def add_to_cart(food_item_id):
    """Adds a product to the user's shopping cart (stored in session)."""
    quantity = int(request.form.get('quantity', 1))
    
    if quantity <= 0:
        flash('Quantity must be at least 1.', 'danger')
        return redirect(request.referrer or url_for('consumer_dashboard'))

    conn = get_db_connection()
    if conn is None:
        return redirect(request.referrer or url_for('consumer_dashboard'))
    
    cursor = conn.cursor()
    # Include food_item_id in the SELECT statement
    cursor.execute("SELECT product_id, product_name, price, food_item_id FROM Products WHERE food_item_id = %s AND verification_status = 'Verified'", (food_item_id,))
    product = cursor.fetchone()
    conn.close()

    if not product:
        flash('Product not found or not verified.', 'danger')
        return redirect(request.referrer or url_for('consumer_dashboard'))

    # Initialize cart in session if it doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    # Store product details needed for cart (food_item_id, name, price, quantity)
    # Using food_item_id as key for session cart
    cart_item_key = product['food_item_id'] # This will now work correctly
    
    if cart_item_key in session['cart']:
        session['cart'][cart_item_key]['quantity'] += quantity
    else:
        session['cart'][cart_item_key] = {
            'product_id_db': product['product_id'], # Database product ID
            'product_name': product['product_name'],
            'price': float(product['price']),
            'quantity': quantity
        }
    
    # Mark session as modified to ensure Flask saves changes
    session.modified = True
    flash(f"Added {quantity} x {product['product_name']} to cart!", 'success')
    return redirect(url_for('view_cart'))

@app.route('/view_cart')
@login_required
@role_required(['Consumer'])
def view_cart():
    """Displays the contents of the user's shopping cart."""
    cart = session.get('cart', {})
    cart_items_details = []
    total_cart_amount = 0.0

    # The product details are already in the session cart, no need to query DB here
    # UNLESS you want to get the *latest* price or verification status from DB.
    # For now, we rely on what was added to session.
    for food_item_id, item_data in cart.items():
        item_total = item_data['price'] * item_data['quantity']
        total_cart_amount += item_total
        cart_items_details.append({
            'food_item_id': food_item_id, # This is the unique food_item_id string
            'product_name': item_data['product_name'],
            'price': item_data['price'],
            'quantity': item_data['quantity'],
            'item_total': item_total
        })

    return render_template('cart.html', cart_items=cart_items_details, total_amount=total_cart_amount)


@app.route('/update_cart/<food_item_id>', methods=['POST'])
@login_required
@role_required(['Consumer'])
def update_cart(food_item_id):
    """Updates the quantity of an item in the cart."""
    new_quantity = int(request.form.get('quantity', 1))
    
    if 'cart' not in session or food_item_id not in session['cart']:
        flash('Item not found in cart.', 'danger')
        return redirect(url_for('view_cart'))
    
    if new_quantity <= 0:
        # If quantity is 0 or less, remove item from cart
        session['cart'].pop(food_item_id, None)
        flash(f'Removed item "{food_item_id}" from cart.', 'info')
    else:
        session['cart'][food_item_id]['quantity'] = new_quantity
        flash(f'Updated quantity for "{food_item_id}" to {new_quantity}.', 'success')
    
    session.modified = True
    return redirect(url_for('view_cart'))


@app.route('/remove_from_cart/<food_item_id>', methods=['POST'])
@login_required
@role_required(['Consumer'])
def remove_from_cart(food_item_id):
    """Removes an item from the user's shopping cart."""
    if 'cart' in session and food_item_id in session['cart']:
        product_name = session['cart'][food_item_id]['product_name']
        session['cart'].pop(food_item_id, None)
        session.modified = True
        flash(f'Removed "{product_name}" from your cart.', 'info')
    else:
        flash('Item not found in cart.', 'warning')
    return redirect(url_for('view_cart'))


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
@role_required(['Consumer'])
def checkout():
    """Handles the checkout process: shipping details and order summary."""
    cart = session.get('cart', {})
    if not cart:
        flash("Your cart is empty and cannot proceed to checkout.", 'warning')
        return redirect(url_for('consumer_dashboard'))

    cart_items_details = []
    total_cart_amount = 0.0

    # Re-fetch latest product details for current prices/status at checkout
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('view_cart'))

    cursor = conn.cursor()
    products_to_remove_from_cart = [] # List to store food_item_ids to remove
    for food_item_id, item_data in cart.items():
        cursor.execute("SELECT product_id, product_name, price, verification_status FROM Products WHERE food_item_id = %s", (food_item_id,))
        product_db = cursor.fetchone()
        
        if not product_db or product_db['verification_status'] != 'Verified':
            products_to_remove_from_cart.append(food_item_id)
            flash(f"Product '{item_data.get('product_name', food_item_id)}' is no longer available or verified and has been removed from your cart.", 'danger')
            continue # Skip to next item if not valid

        item_total = float(product_db['price']) * item_data['quantity']
        total_cart_amount += item_total
        cart_items_details.append({
            'food_item_id': food_item_id,
            'product_name': product_db['product_name'],
            'price': float(product_db['price']),
            'quantity': item_data['quantity'],
            'item_total': item_total,
            'product_id_db': product_db['product_id'] # Store actual DB product_id for OrderDetails
        })
    conn.close()

    # Remove invalid products from the session cart after iterating
    for food_item_id_to_remove in products_to_remove_from_cart:
        session['cart'].pop(food_item_id_to_remove, None)
    if products_to_remove_from_cart:
        session.modified = True # Mark session modified if items were removed

    # If cart becomes empty after removal, redirect
    if not cart_items_details:
        flash("Your cart is now empty after removing unavailable products. Cannot proceed to checkout.", 'warning')
        return redirect(url_for('consumer_dashboard'))


    # Get user's saved addresses
    user_addresses = []
    conn_addr = get_db_connection()
    if conn_addr:
        cursor_addr = conn_addr.cursor()
        cursor_addr.execute("SELECT * FROM UserAddresses WHERE user_id = %s ORDER BY is_default DESC", (session['user_id'],))
        user_addresses = cursor_addr.fetchall()
        conn_addr.close()

    if request.method == 'POST':
        # Collect shipping details from form
        address_line1 = request.form.get('address_line1').strip()
        address_line2 = request.form.get('address_line2', '').strip()
        city = request.form.get('city').strip()
        state = request.form.get('state').strip()
        zip_code = request.form.get('zip_code').strip()
        country = request.form.get('country').strip()
        save_address = request.form.get('save_address') # Checkbox

        if not all([address_line1, city, state, zip_code, country]):
            flash('Please fill in all required shipping address fields.', 'danger')
            return render_template('checkout.html', cart_items=cart_items_details, total_amount=total_cart_amount, user_addresses=user_addresses)
        
        # --- Process Order Placement ---
        conn_order = get_db_connection()
        if conn_order is None:
            flash('Database connection error. Cannot place order.', 'danger')
            return redirect(url_for('view_cart'))
        
        cursor_order = conn_order.cursor()
        try:
            # 1. Insert into Orders table
            cursor_order.execute(
                "INSERT INTO Orders (user_id, total_amount, shipping_address_line1, shipping_address_line2, shipping_city, shipping_state, shipping_zip_code, shipping_country, status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (session['user_id'], total_cart_amount, address_line1, address_line2, city, state, zip_code, country, 'Placed')
            )
            order_id = cursor_order.lastrowid # Get the ID of the newly inserted order

            # 2. Insert into OrderDetails table for each item in cart
            for item in cart_items_details:
                cursor_order.execute(
                    "INSERT INTO OrderDetails (order_id, product_id, quantity, price_at_order) VALUES (%s, %s, %s, %s)",
                    (order_id, item['product_id_db'], item['quantity'], item['price'])
                )
            
            # 3. Add 'Sold' event to SupplyChainEvents for each product
            for item in cart_items_details:
                 cursor_order.execute(
                    "INSERT INTO SupplyChainEvents (food_item_id, event_type, location, details) VALUES (%s, %s, %s, %s)",
                    (item['food_item_id'], 'Sold', f'Consumer: {session["username"]} ({city}, {country})', f'Purchased by {session["username"]} (Order #{order_id})')
                )

            # 4. If 'save_address' is checked, save/update address
            if save_address:
                # Check if this exact address already exists for the user
                cursor_order.execute(
                    "SELECT address_id FROM UserAddresses WHERE user_id = %s AND address_line1 = %s AND city = %s AND state = %s AND zip_code = %s AND country = %s",
                    (session['user_id'], address_line1, city, state, zip_code, country)
                )
                existing_address = cursor_order.fetchone()
                if not existing_address:
                    cursor_order.execute(
                        "INSERT INTO UserAddresses (user_id, address_name, address_line1, address_line2, city, state, zip_code, country, is_default) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (session['user_id'], 'Default' if not user_addresses else 'Saved Address', address_line1, address_line2, city, state, zip_code, country, False) # Can make default logic more robust
                    )

            conn_order.commit()
            session.pop('cart', None) # Clear the cart after successful order
            session.modified = True
            flash(f"Order placed successfully! Your Order ID is #{order_id}", 'success')
            return redirect(url_for('order_confirmation', order_id=order_id))

        except pymysql.Error as e:
            conn_order.rollback()
            flash(f"Error placing order: {e}", 'danger')
            return redirect(url_for('view_cart'))
        finally:
            conn_order.close()

    # GET request: Display checkout form
    return render_template('checkout.html', cart_items=cart_items_details, total_amount=total_cart_amount, user_addresses=user_addresses)

@app.route('/order_confirmation/<int:order_id>')
@login_required
@role_required(['Consumer'])
def order_confirmation(order_id):
    """Displays the confirmation details for a placed order."""
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('consumer_dashboard'))
    
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Orders WHERE order_id = %s AND user_id = %s", (order_id, session['user_id']))
    order = cursor.fetchone()

    if not order:
        flash('Order not found or you do not have permission to view it.', 'danger')
        conn.close()
        return redirect(url_for('my_orders'))

    cursor.execute(
        "SELECT od.*, p.product_name, p.food_item_id FROM OrderDetails od JOIN Products p ON od.product_id = p.product_id WHERE od.order_id = %s",
        (order_id,)
    )
    order_details = cursor.fetchall()
    conn.close()
    return render_template('order_confirmation.html', order=order, order_details=order_details)

@app.route('/my_orders')
@login_required
@role_required(['Consumer'])
def my_orders():
    """Displays a list of all orders placed by the current consumer."""
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error.', 'danger')
        return redirect(url_for('consumer_dashboard'))
    
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Orders WHERE user_id = %s ORDER BY order_date DESC", (session['user_id'],))
    orders = cursor.fetchall()
    conn.close()
    return render_template('my_orders.html', orders=orders)


# --- Run the Flask App ---
if __name__ == '__main__':
    app.run(debug=True)