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
            phpsessid = request.form['phpsessid']
            numbers = request.form['numbers'].split()

            total_success = 0
            total_fail = 0
            codes = {}

            for number in numbers:
                code = get_panel_code(phpsessid, number)
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



def get_panel_code(phpsessid, number):
    # Sanitize the phone number to ensure it starts with a '+'
    if not number.startswith('+'):
        number = f'+{number}'
    cookies = {
        'PHPSESSID': phpsessid,
        'cf_clearance': 'q215qKk3TnaopVq7.TJ9uqwoDUhikIk3c99bZcGv9oQ-1727272832-1.2.1.1-AQnFZ3fusgPSgLJpnQ3rHy_6wJphr6B5uNvj.6CjKH86WQEWXsZ1aWfVLPeAuN21UWIYuAkeFpOLXbmuIY7tA5xncJH0b.ZZo2jfSLpx8g8FAuPpfgVF0lYPmOwRVg0kMztaoEXpw9qBl2Uv3tCbatHRqTaMZNZ_MHkbVfHQ_N_XzxYO_Ewy7TqvDvGhswEi3XmJ_b_JAYcM.dLUg3N5TvU.rgl9UupdTPbvfA8zroHs8qr6TfVNmquyZpbI43.1_ef67oGM1RsUYl_513eHNJL4aV3XrhI05f6Q6KbSF0abBVvC2xvxXghzDhtzAVFc7zkzQiyICiKc2iuN9w5Okyp7QslCjDiKjCFMSdmwujPA9_oFcP335lI.cvpo4zy3rWDLqfcEaXBZ2_8uTkLM_L1RT6_yTTEI0uLFB9kUytPGCaptS32b2jzM.NbRcC9R',
    }

    headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
        'cache-control': 'max-age=0',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://mediateluk.com',
        'priority': 'u=0, i',
        'referer': 'https://mediateluk.com/sms/index.php?opt=shw_sts_today',
        'sec-ch-ua': '"Not)A;Brand";v="99", "Microsoft Edge";v="127", "Chromium";v="127"',
        'sec-ch-ua-arch': '"x86"',
        'sec-ch-ua-bitness': '"64"',
        'sec-ch-ua-full-version': '"127.0.2651.98"',
        'sec-ch-ua-full-version-list': '"Not)A;Brand";v="99.0.0.0", "Microsoft Edge";v="127.0.2651.98", "Chromium";v="127.0.6533.100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-model': '""',
        'sec-ch-ua-platform': '"Windows"',
        'sec-ch-ua-platform-version': '"15.0.0"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0',
    }

    params = {
        'opt': 'shw_sts_today_det',
    }

    data = {
        'ddi': number,
        'oad': 'CloudOTP',
    }
    try:
        response = requests.post('https://mediateluk.com/sms/index.php', params=params, cookies=cookies, headers=headers, data=data)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Use CSS selectors to target the 'MESSAGE BODY' column in the table
        verification_msg = soup.select_one('table.table.table-head-bg-warning tr.table_line_even td:nth-child(6)')

        if verification_msg:
            # Extract the text of the verification message
            message_text = verification_msg.text
            # Use a regular expression to find the digits in the message
            verification_code = re.search(r'\d+', message_text)
            
            if verification_code:
                return verification_code.group()
            else:
                return None
        else:
            return None
    except:
        return None

if __name__ == '__main__':
    init_db()
    app.run(debug=False)
