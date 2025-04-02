from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import time
import os
from functools import wraps
import bcrypt  # Import bcrypt for password hashing


app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# MySQL configurations
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'quiz_app'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

WORD_PUZZLES = [
    {
        "folder": "question1",
        "image1": "image1.png",
        "image2": "image2.png",
        "answer": "Fire wall"
    },
    {
        "folder": "question2",
        "image1": "img_12.png",
        "image2": "img_13.png",
        "answer": "Profil naming"
    },
    {
        "folder": "question3",
        "image1": "img_14.png",
        "image2": "img_15.png",
        "answer": "MAILBOX"
    },
    {
        "folder": "question4",
        "image1": "img_3.png",
        "image2": "img_4.png",
        "answer": "Smart Phone"
    },
    {
        "folder": "question5",
        "image1": "img_10.png",
        "image2": "img_11.png",
        "answer": "Network"
    },
    {
        "folder": "question6",
        "image1": "img_24.png",
        "image2": "img_25.png",
        "answer": "Webcam"
    },
    {
        "folder": "question7",
        "image1": "img_26.png",
        "image2": "img_27.png",
        "answer": "Bluetooth"
    },
    {
        "folder": "question8",
        "image1": "img_32.png",
        "image2": "img_33.png",
        "answer": "File Sharing"
    },
    {
        "folder": "question9",
        "image1": "img_36.png",
        "image2": "img_37.png",
        "answer": "Login"
    },
    {
        "folder": "question10",
        "image1": "img_38.png",
        "image2": "img_39.png",
        "answer": "Hotspot"
    }

]


def no_cache(view):
    @wraps(view)
    def decorated_view(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        return response

    return decorated_view


def normalize_answer(answer):
    return re.sub(r'\s+', '', answer).upper()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def home():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor()
        cursor.execute("""
        SELECT u.username, r.score, r.time_taken 
        FROM quiz_results r 
        JOIN users u ON r.user_id = u.id 
        ORDER BY r.score DESC, r.time_taken ASC 
        LIMIT 5
        """)
        leaderboard = cursor.fetchall()

        # Get user's position if they've taken the quiz
        cursor.execute("SELECT * FROM quiz_results WHERE user_id = %s", (session['userid'],))
        user_result = cursor.fetchone()
        cursor.close()

        return render_template('home.html',
                               username=session['username'],
                               leaderboard=leaderboard,
                               user_result=user_result)
    return render_template('home.html')


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', None)
        password = request.form.get('password', None)

        if not email or not password:
            flash('Please fill in both email and password fields!', 'danger')
            return redirect(url_for('login'))

        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        account = cursor.fetchone()

        if account:
            stored_hashed_password = account['password']

            # Verify the entered password with the stored hashed password
            if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                session['loggedin'] = True
                session['userid'] = account['id']
                session['username'] = account['username']
                session['email'] = account['email']
                return redirect(url_for('home'))
            else:
                flash('Incorrect email/password!', 'danger')
        else:
            flash('Account not found!', 'danger')

    return render_template('login.html')


@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', None)
        password = request.form.get('password', None)
        email = request.form.get('email', None)

        if not username or not password or not email:
            flash('Please fill in all fields!', 'danger')
            return redirect(url_for('register'))

        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            flash('Account already exists!', 'danger')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!', 'danger')
        elif not re.match(r'^[A-Za-z0-9]+$', username):
            flash('Username must contain only characters and numbers!', 'danger')
        else:
            # Hash the password before storing it
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            cursor.execute('INSERT INTO users (username, password, email) VALUES (%s, %s, %s)',
                           (username, hashed_password.decode('utf-8'), email))
            mysql.connection.commit()
            flash('You have successfully registered!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/logout/')
def logout():
    session.pop('loggedin', None)
    session.pop('userid', None)
    session.pop('username', None)
    return redirect(url_for('home'))


@app.route('/account/')
@login_required
def account():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM users WHERE id = %s', (session['userid'],))
    account = cursor.fetchone()

    cursor.execute('SELECT * FROM quiz_results WHERE user_id = %s', (session['userid'],))
    quiz_result = cursor.fetchone()
    cursor.close()

    return render_template('account.html',
                           account=account,
                           quiz_result=quiz_result,
                           total_questions=len(WORD_PUZZLES))


@app.route('/quiz/', methods=['GET', 'POST'])
@no_cache
@login_required
def quiz():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM quiz_results WHERE user_id = %s', (session['userid'],))
    existing_result = cursor.fetchone()
    cursor.close()

    if existing_result:
        flash('You can only take the quiz once!', 'danger')
        return redirect(url_for('account'))

    if 'current_question' not in session or 'score' not in session:
        session['current_question'] = 0
        session['score'] = 0
        session['start_time'] = time.time()

    current_idx = session['current_question']

    if current_idx >= len(WORD_PUZZLES):
        return redirect(url_for('results'))

    puzzle = WORD_PUZZLES[current_idx]
    message = None  # Ensure message exists
    submitted = False

    if request.method == 'POST':
        user_answer = request.form.get('answer', '').strip()
        user_normalized = normalize_answer(user_answer)
        correct_normalized = normalize_answer(puzzle["answer"])

        if user_answer:
            submitted = True
            if user_normalized == correct_normalized:
                message = {
                    "text": f"✅ Correct! Answer: {puzzle['answer']}",
                    "class": "correct",
                    "user_input": user_answer
                }
                session['score'] += 1
            else:
                message = {
                    "text": f"❌ Wrong! Correct answer: {puzzle['answer']}",
                    "class": "wrong",
                    "user_input": user_answer
                }

        elif 'next' in request.form:
            session['current_question'] += 1
            return redirect(url_for('quiz'))

        elif 'submit' in request.form:
            return redirect(url_for('results'))

    is_last_question = current_idx == len(WORD_PUZZLES) - 1
    image1_path = f"{puzzle['folder']}/{puzzle['image1']}"
    image2_path = f"{puzzle['folder']}/{puzzle['image2']}"
    return render_template('index.html',
                           image1=image1_path,
                           image2=image2_path,
                           message=message,
                           puzzle=puzzle,  # Add this line
                           submitted=submitted,
                           current_question=current_idx + 1,
                           total_questions=len(WORD_PUZZLES),
                           is_last_question=is_last_question,
                           score=session['score'])


@app.route('/results')
@no_cache
@login_required
def results():
    # Calculate time taken
    if 'start_time' in session:
        time_taken = int(time.time() - session['start_time'])  # Convert to integer as per schema
    else:
        time_taken = 0

    score = session.get('score', 0)

    # Store results in database
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO quiz_results (user_id, score, time_taken)
            VALUES (%s, %s, %s)
        """, (session['userid'], score, time_taken))
        mysql.connection.commit()
    except Exception as e:
        print(f"Error storing quiz results: {e}")
        mysql.connection.rollback()
    finally:
        cursor.close()

    # Clean up session
    session.pop('current_question', None)
    session.pop('score', None)
    session.pop('start_time', None)

    return render_template('results.html',
                           score=score,
                           total=len(WORD_PUZZLES),
                           time_taken=time_taken)


if __name__ == '__main__':
    with app.app_context():
        cursor = mysql.connection.cursor()
        # Create users table if not exists
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # Create quiz_results table with simplified schema
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS quiz_results (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL UNIQUE,
            score INT NOT NULL,
            time_taken INT NOT NULL,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            violation_count INT DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        mysql.connection.commit()
        cursor.close()

        # Create image folders if they don't exist
        for q in ['question1', 'question2', 'question3']:
            os.makedirs(f"static/images/{q}", exist_ok=True)

    app.run(host='0.0.0.0', port=5000, debug=False)  # debug=False for production
