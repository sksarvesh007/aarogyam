import os
import sqlite3
import secrets
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, flash
from src.hospital import get_hospitals
from src.diet_pan import diet_plan_chatbot
from src.med_ocr import extract_image_info

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(16))

# Database initialization function
def init_db():
    """Initialize the SQLite database and create users table if it doesn't exist."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

# Password hashing function
def hash_password(password, salt=None):
    """
    Hash a password with an optional salt.
    If no salt is provided, generate a new one.
    """
    if salt is None:
        salt = secrets.token_hex(16)
    
    # Combine password and salt, then hash
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return password_hash, salt

# User registration function
def register_user(username, password):
    """Register a new user in the database."""
    try:
        # Hash the password
        password_hash, salt = hash_password(password)
        
        # Connect to the database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Insert the new user
        cursor.execute(
            'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)', 
            (username, password_hash, salt)
        )
        
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Username already exists
        return False
    finally:
        conn.close()

# User authentication function
def authenticate_user(username, password):
    """Authenticate a user against the database."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Fetch user by username
    cursor.execute('SELECT password_hash, salt FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        # Verify password
        stored_password_hash, salt = user
        input_password_hash, _ = hash_password(password, salt)
        
        return input_password_hash == stored_password_hash
    
    return False

# Routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not password:
            flash('Username and password are required', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            # Attempt to register user
            if register_user(username, password):
                flash('Signup successful! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Username already exists', 'error')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Authenticate user
        if authenticate_user(username, password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Handle user logout."""
    session.pop('username', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

# Existing routes with login protection
@app.route('/')
def index():
    """Renders the index page."""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')
message_history = None
@app.route('/diet', methods=['GET', 'POST'])
def diet():
    """Handles the diet chatbot."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    global message_history
    bot_response = None

    if request.method == 'POST':
        user_message = request.form.get('user_message')
        if user_message:
            bot_response, message_history = diet_plan_chatbot(user_message, message_history)
    visible_history = [
        message for message in (message_history or [])
        if message["role"] != "system"
    ]
    return render_template('diet.html', chat_history=visible_history)

@app.route('/hospital', methods=['GET', 'POST'])
def hospital():
    """Handles hospital search."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    hospitals = []
    query = None
    HERE_API_KEY = os.getenv("here_api")

    if request.method == 'POST':
        # Fetch  user-provided latitude, longitude, and query
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        query = request.form.get('query', 'hospital')
        limit = request.form.get('limit', 10)

        try:
            if HERE_API_KEY and latitude and longitude:
                data = get_hospitals(HERE_API_KEY, latitude, longitude, query, limit)
                hospitals = data.get('items', [])
        except Exception as e:
            print(f"Error fetching hospitals: {e}")

    return render_template('hospital.html', hospitals=hospitals, query=query)
@app.route('/medical_reports', methods=['GET', 'POST'])
def medical_reports():
    """Handles the medical report image upload and extraction."""
    if 'username' not in session:
        return redirect(url_for('login'))

    # Fetch user's previous medical reports
    user_reports = get_user_medical_reports(session['username'])

    if request.method == 'POST':
        # Get the uploaded file
        file = request.files.get('image')
        
        if file and file.filename.endswith(('png', 'jpg', 'jpeg')):
            # Ensure temp directory exists
            os.makedirs('temp', exist_ok=True)
            
            # Save the file as temp/image.jpg
            image_path = 'temp/image.jpg'  # Save as a fixed name
            file.save(image_path)

            try:
                # Use the extract_image_info function directly
                extracted_info = extract_image_info(image_path)

                if extracted_info:
                    # Save the entire returned string to database
                    save_medical_report(session['username'], extracted_info)
                    flash('Medical report saved successfully!', 'success')
                else:
                    flash('Failed to extract information from the image.', 'error')
            except Exception as e:
                flash(f'Error processing image: {str(e)}', 'error')

            return redirect(url_for('medical_reports'))

    return render_template('medical_reports.html', reports=user_reports)

def save_medical_report(username, report_text):
    """
    Save medical report as a raw text string to the database.
    
    Args:
        username (str): Username of the current user
        report_text (str): Raw text of the medical report
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'INSERT INTO medical_reports (username, report_data) VALUES (?, ?)', 
            (username, report_text)
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        flash('Error saving medical report', 'error')
    finally:
        conn.close()

def get_user_medical_reports(username):
    """
    Retrieve medical reports for a specific user.
    
    Args:
        username (str): Username of the current user
    
    Returns:
        list: List of medical reports
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'SELECT id, report_data, upload_date FROM medical_reports WHERE username = ? ORDER BY upload_date DESC', 
            (username,)
        )
        reports = cursor.fetchall()
        
        # Convert reports to a more usable format
        formatted_reports = [
            {
                'id': report_id,
                'data': report_data,
                'date': upload_date
            }
            for report_id, report_data, upload_date in reports
        ]
        
        return formatted_reports
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
    finally:
        conn.close()

init_db()

if __name__ == '__main__':
    app.run(debug=True)