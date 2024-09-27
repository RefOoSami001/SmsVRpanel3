import sqlite3
import requests
from flask import Flask, request, render_template, redirect, url_for, session, flash
from datetime import datetime
from bs4 import BeautifulSoup
import re
app = Flask(__name__)
app.secret_key = 'refooSami'  # Secret key for session management

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS user_data (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        number TEXT NOT NULL,
                        status TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (username) REFERENCES users(username)
                    )''')
    conn.commit()
    conn.close()

# Add a new user to the SQLite database
def add_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
    except sqlite3.IntegrityError:
        flash('User already exists', 'danger')
    finally:
        conn.close()
# Remove a user from the SQLite database
def remove_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    cursor.execute('DELETE FROM user_data WHERE username = ?', (username,))
    conn.commit()
    conn.close()
# Authenticate user credentials
def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()
    conn.close()
    return user

# Add data for a specific user
def add_user_data(username, number, status):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO user_data (username, number, status) VALUES (?, ?, ?)', (username, number, status))
    conn.commit()
    conn.close()

# Retrieve user data for a specific user
def get_user_data(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user_data WHERE username = ?', (username,))
    data = cursor.fetchall()
    conn.close()
    return data
# Retrieve user data by number
def get_number_data(number):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, number, status, timestamp FROM user_data WHERE number = ?', (number,))
    data = cursor.fetchall()
    conn.close()
    return data
@app.route('/manage_users', methods=['GET', 'POST'])
def add_user_route():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        action = request.form.get('action', '').strip()
        
        # Validate input fields
        if not username:
            flash('Username is required.', 'danger')
        elif action == 'add':
            if not password:
                flash('Password is required for adding a user.', 'danger')
            else:
                try:
                    add_user(username, password)
                    flash('User added successfully', 'success')
                except Exception as e:
                    flash(f'An error occurred: {str(e)}', 'danger')
        elif action == 'remove':
            try:
                remove_user(username)
                flash('User removed successfully', 'success')
            except Exception as e:
                flash(f'An error occurred: {str(e)}', 'danger')
        else:
            flash('Invalid action specified.', 'danger')

    return render_template('add_user.html')

@app.route('/search_user', methods=['GET', 'POST'])
def search_user():
    if request.method == 'POST':
        search_type = request.form.get('search_type', '').strip()
        search_value = request.form.get('search_value', '').strip()

        if search_type == 'username':
            user_data = get_user_data(search_value)
            if user_data:
                # Initialize counters
                total_success = 0
                total_failed = 0

                # Count successes and failures
                for entry in user_data:
                    if entry[3] == 'Failed':
                        total_failed += 1
                    else:
                        total_success += 1

                return render_template(
                    'user_data.html',
                    user_data=user_data,
                    search_type='username',
                    search_value=search_value,
                    total_success=total_success,
                    total_failed=total_failed
                )
            else:
                flash('No data found for the user', 'danger')

        elif search_type == 'number':
            number_data = get_number_data(search_value)
            if number_data:
                # Count successes and failures
                total_success = sum(1 for entry in number_data if entry[2] != 'Failed')
                total_failed = sum(1 for entry in number_data if entry[2] == 'Failed')
                
                return render_template(
                    'user_data.html',
                    number_data=number_data,
                    search_type='number',
                    search_value=search_value,
                    total_success=total_success,
                    total_failed=total_failed
                )
            else:
                flash('No data found for this number', 'danger')

    return render_template('user_data.html')





# Root route redirects to login
@app.route('/')
def index():
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = authenticate_user(username, password)
        if user:
            
            session['user'] = username
            session['logged_in'] = True
            session['username'] = username
            flash('Login successful', 'success')
            return redirect(url_for('verification_code_finder'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# Verification code finder route
@app.route('/verification_code_finder', methods=['GET', 'POST'])
def verification_code_finder():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if 'user' in session:
        if request.method == 'POST':
            numbers = request.form['numbers'].split()

            total_success = 0
            total_fail = 0
            codes = {}

            for number in numbers:
                code = get_panel_code(number)
                status = 'Failed'
                if code:
                    total_success += 1
                    status = code
                else:
                    total_fail += 1

                codes[number] = status
                add_user_data(session['user'], number, status)  # Save data to database

            results = {
                'total_success': total_success,
                'total_fail': total_fail,
                'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'codes': codes
            }
            return render_template('verification.html', results=results)
        return render_template('verification.html')
    else:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))



def get_panel_code(number):
    response = requests.get(f'http://51.89.151.134/crapi/viewstats?token=%20Q1FXNEVBgmBJf5Bzd2aEW0qWUV1_VWRHZYdxa0l2YIR7l3VTVnI=&record=200&filternum={number}').json()
    if response['status'] == 'success':
        message_text = response['data'][0]['message']
        # Use a regular expression to find the digits in the message
        verification_code = re.search(r'\d+', message_text)
        
        if verification_code:
            return verification_code.group()
        else:
            return None
    else:
        return None


if __name__ == '__main__':
    init_db()
    app.run(debug=False)
