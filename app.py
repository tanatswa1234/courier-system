from flask import Flask, request, redirect, session, render_template, flash,jsonify    
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import re
import os  # for environment variables
import logging
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_default_secret_key')

# MySQL configurations
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', 'Tanatswa23')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'couriersystem')

mysql = MySQL(app)
bcrypt = Bcrypt(app)
logging.basicConfig(level=logging.DEBUG)


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']

    # Basic validation
    if not validate_email(email):
        flash('Invalid email address!', 'danger')
        return redirect('/')

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create a cursor
    cur = mysql.connection.cursor()
    try:
        # Insert the new user into the database and set verified to TRUE
        cur.execute("INSERT INTO users (username, email, password, role, verified) VALUES (%s, %s, %s, %s, %s)", 
                    (username, email, hashed_password, role, True))  # Set verified to TRUE
        mysql.connection.commit()
        flash('Registration successful!', 'success')  # Removed email verification notice
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error: {str(e)}', 'danger')
    finally:
        cur.close()

    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    print(f"Attempting to log in user: {username}")  # Debugging

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    
    if user:
        print("User found in database.")  # Debugging
        if bcrypt.check_password_hash(user[3], password):  # Password is at index 3
            print("Password match!")  # Debugging
            session['user_id'] = user[0]  # User ID is at index 0
            session['role'] = user[4]      # User role is at index 4

            # Redirect based on role
            if user[4] == 'admin':
                return redirect('/admin_dashboard')
            elif user[4] == 'driver':
                return redirect('/driver_dashboard')
            else:  # default to user
                return redirect('/user_dashboard')
        else:
            flash('Invalid username or password.', 'danger')
    else:
        flash('Invalid username or password.', 'danger')
    
    cur.close()
    return redirect('/')

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect('/')

    # Fetch the user details to pass to the dashboard
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE user_id = %s", (session['user_id'],))
    user = cur.fetchone()
    cur.close()

    return render_template('user_dashboard.html', user=user)



@app.route('/driver_dashboard')
def driver_dashboard():
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect('/')

    # Get the driver’s assigned orders from the database
    driver_id = session['user_id']
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT order_id, pickup_location, dropoff_location, status, scheduled_time 
        FROM orders 
        WHERE driver_id = %s AND status != 'Delivered'
    """, (driver_id,))
    orders = cur.fetchall()
    cur.close()

    return render_template('driver_dashboard.html', orders=orders)



@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect('/')
    return render_template('admin_dashboard.html')

@app.route('/create_order', methods=['POST'])
def create_order():
    if 'user_id' not in session:
        flash('Please log in to place an order', 'warning')
        return redirect('/')

    # Retrieve form data
    pickup_location = request.form['pickup_location']
    dropoff_location = request.form['dropoff_location']
    scheduled_time = request.form.get('scheduled_time', None)

    # For now, we'll use a static distance; we’ll replace this with Google Maps API later
    distance = 5.0  # Placeholder for distance in miles

    # Create a new order
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            INSERT INTO orders (user_id, pickup_location, dropoff_location, distance, scheduled_time)
            VALUES (%s, %s, %s, %s, %s)
        """, (session['user_id'], pickup_location, dropoff_location, distance, scheduled_time))
        mysql.connection.commit()
        flash('Order created successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error: {str(e)}', 'danger')
    finally:
        cur.close()

    return redirect('/user_dashboard')

@app.route('/assign_driver', methods=['POST'])
def assign_driver():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect('/')

    order_id = request.form['order_id']
    driver_id = request.form['driver_id']

    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            UPDATE orders SET driver_id = %s, status = 'assigned'
            WHERE order_id = %s
        """, (driver_id, order_id))
        mysql.connection.commit()
        flash('Driver assigned to order successfully', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error: {str(e)}', 'danger')
    finally:
        cur.close()

    return redirect('/admin_dashboard')

@app.route('/update_order_status', methods=['POST'])
def update_order_status():
    if 'user_id' not in session or session['role'] != 'driver':
        flash('Unauthorized access', 'danger')
        return redirect('/')

    order_id = request.form['order_id']
    status = request.form['status']

    cur = mysql.connection.cursor()
    try:
        # Update the main order status
        cur.execute("""
            UPDATE orders SET status = %s WHERE order_id = %s
        """, (status, order_id))

        # Insert into the order_status history table
        cur.execute("""
            INSERT INTO order_status (order_id, status) VALUES (%s, %s)
        """, (order_id, status))
        mysql.connection.commit()
        flash('Order status updated', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error: {str(e)}', 'danger')
    finally:
        cur.close()

    return redirect('/driver_dashboard')


@app.route('/user/orders')
def user_orders():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect('/')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM orders WHERE user_id = %s ORDER BY created_at DESC", (session['user_id'],))
    orders = cur.fetchall()
    cur.close()

    return render_template('my_orders.html', orders=orders)

@app.route('/user/new-order', methods=['GET', 'POST'])
def new_order():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect('/')

    if request.method == 'POST':
        pickup_location = request.form['pickup_location']
        dropoff_location = request.form['dropoff_location']
        contact_number = request.form['contact_number']
        scheduled_time = request.form.get('scheduled_time', None)
        delivery_instructions = request.form['delivery_instructions']

        # Insert into the orders table, make sure to match the columns with your DB schema
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO orders (user_id, pickup_location, dropoff_location, contact_number, scheduled_time, delivery_instructions) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (session['user_id'], pickup_location, dropoff_location, contact_number, scheduled_time, delivery_instructions))
        mysql.connection.commit()
        cur.close()
        flash('Order created successfully!', 'success')
        return redirect('/user/orders')

    return render_template('new_order.html')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/user/profile', methods=['GET', 'POST'])
def user_profile():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect('/')

    cur = mysql.connection.cursor()
    
    # Get the user details from the database
    cur.execute("SELECT username, email, profile_picture FROM users WHERE user_id = %s", (session['user_id'],))
    user = cur.fetchone()

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        profile_picture = request.files.get('profile_picture')

        # Validate the uploaded file if it exists
        filename = None
        if profile_picture and allowed_file(profile_picture.filename):
            filename = secure_filename(profile_picture.filename)
            profile_picture.save(os.path.join('static/profile_pictures', filename))  # Adjust the path as necessary

        # Update user information in the database
        try:
            cur.execute("""
                UPDATE users 
                SET username = %s, email = %s, profile_picture = %s 
                WHERE user_id = %s
            """, (username, email, filename if profile_picture else user[2], session['user_id']))  # Retain existing picture if none uploaded
            mysql.connection.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error: {str(e)}', 'danger')

        return redirect('/user_dashboard')

    cur.close()
    
    # Render the profile page with user data
    return render_template('profile.html', user=user)

def validate_email(email):
    # Basic email validation
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email)

@app.route('/user/order-details')
def order_details():
    order_id = request.args.get('order_id')
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM orders WHERE order_id = %s", (order_id,))
    order = cur.fetchone()
    cur.close()
    if order:
        order_data = {
            "order_id": order[0],
            "status": order[4],
            "pickup_location": order[2],
            "dropoff_location": order[3],
            "distance": order[5],
            "scheduled_time": order[6],
            "created_at": order[7],
        }
        return jsonify(order_data)
    else:
        return jsonify({"error": "Order not found"}), 404


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
