from flask import Flask, render_template, request, redirect, url_for, session, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User, PendingUser, DiaryEntry
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime, timedelta, date
from dotenv import load_dotenv
import os, secrets, hashlib, re

# Load environment variables
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

bcrypt = Bcrypt(app)

engine = create_engine('sqlite:///users.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
db_session = Session()

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
mail = Mail(app)

def generate_otp():
    otp = str(secrets.randbelow(10**6)).zfill(6)
    expiry = datetime.now() + timedelta(minutes=1)
    hashed_otp = hashlib.sha256(otp.encode()).hexdigest()
    return otp, hashed_otp, expiry

def send_otp_email(recipient_email, first_name, otp, subject="Your OTP for Registration"):
    try:
        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            body=f"Hello {first_name},\n\nYour OTP is: {otp}\nIt will expire in 1 minute.\nIf you did not request this, please ignore this message."
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending OTP to {recipient_email}: {e}")
        return False

def prevent_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

def cleanup_expired_pending_users():
    expiry_time = datetime.utcnow() - timedelta(hours=1)
    expired_users = db_session.query(PendingUser).filter(PendingUser.created_at < expiry_time).all()
    for user in expired_users:
        db_session.delete(user)
    db_session.commit()

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'\d', password) and
        re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
    )

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        user = db_session.query(User).filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['username'] = email
            return redirect(url_for('dashboard'))
        else:
            response = make_response(render_template('login.html', error="Invalid email or password.", site_key=os.getenv('RECAPTCHA_SITE_KEY')))
    else:
        message = request.args.get('message', '')
        error = request.args.get('error', '')
        response = make_response(render_template('login.html', message=message, error=error, site_key=os.getenv('RECAPTCHA_SITE_KEY')))
    response = prevent_cache(response)
    return response

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    email = session['username']
    user = db_session.query(User).filter_by(email=email).first()
    message = ""
    today = date.today()
    if request.method == 'POST':
        entry_text = request.form.get('diary_entry', '').strip()
        if entry_text:
            diary_entry = DiaryEntry(user_id=user.id, date=today, text=entry_text)
            db_session.add(diary_entry)
            db_session.commit()
            message = "Diary entry saved!"
    entries = db_session.query(DiaryEntry).filter_by(user_id=user.id).order_by(DiaryEntry.date.desc()).all()
    response = make_response(render_template('dashboard.html', username=email, user=user, entries=entries, message=message))
    response = prevent_cache(response)
    return response

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = ""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        confirm_email = request.form.get('confirm_email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not username:
            error = "Username is required."
        elif db_session.query(PendingUser).filter_by(username=username).first() or db_session.query(User).filter_by(username=username).first():
            error = "Username already exists."
        elif email != confirm_email:
            error = "Email addresses do not match."
        elif db_session.query(PendingUser).filter_by(email=email).first():
            error = "An account with this email already exists."
        elif db_session.query(User).filter_by(email=email).first():
            error = "An account with this email already exists."
        elif not is_strong_password(password):
            error = "Password must be at least 8 characters long and include uppercase, lowercase, number, and symbol."
        elif password != confirm_password:
            error = "Passwords do not match."

        if error:
            response = make_response(render_template('register.html', error=error, site_key=os.getenv('RECAPTCHA_SITE_KEY')))
            response = prevent_cache(response)
            return response

        otp, hashed_otp, otp_expiry = generate_otp()
        if not send_otp_email(email, first_name, otp):
            response = make_response(render_template('register.html', error="Failed to send OTP. Please check your email settings.", site_key=os.getenv('RECAPTCHA_SITE_KEY')))
            response = prevent_cache(response)
            return response

        new_user = PendingUser(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=bcrypt.generate_password_hash(password).decode('utf-8'),
            otp=hashed_otp,
            otp_expiry=otp_expiry,
            resend_count=0,
            resend_block_until=None
        )
        db_session.add(new_user)
        db_session.commit()
        return redirect(url_for('verify_otp', email=email))

    response = make_response(render_template('register.html', error=error, site_key=os.getenv('RECAPTCHA_SITE_KEY')))
    response = prevent_cache(response)
    return response

@app.route('/resend_otp/<email>', methods=['GET', 'POST'])
def resend_otp(email):
    user_data = db_session.query(PendingUser).filter_by(email=email).first()
    if not user_data:
        return redirect(url_for('register'))
    now = datetime.now()
    if user_data.resend_block_until and now < user_data.resend_block_until:
        error = "You've reached the resend limit. Please wait 1 hour before trying again."
        return render_template('verify_otp.html', email=email, error=error)
    if user_data.resend_count >= 3:
        user_data.resend_block_until = now + timedelta(hours=1)
        user_data.resend_count = 0
        db_session.commit()
        error = "OTP resend limit reached. Try again in 1 hour."
        return render_template('verify_otp.html', email=email, error=error)
    new_otp = str(secrets.randbelow(10**6)).zfill(6)
    hashed_otp = hashlib.sha256(new_otp.encode()).hexdigest()
    user_data.otp = hashed_otp
    user_data.otp_expiry = now + timedelta(minutes=1)
    user_data.resend_count += 1
    db_session.commit()
    if not send_otp_email(email, user_data.first_name, new_otp, subject="Your New OTP for Registration"):
        return render_template('verify_otp.html', email=email, error="Failed to resend OTP. Please try again.")
    message = f"A new OTP has been sent to your email. Attempt {user_data.resend_count} of 3."
    return render_template('verify_otp.html', email=email, message=message)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = db_session.query(User).filter_by(email=email).first()
        if not user:
            return render_template('forgot_password.html', error="Email not found.")
        plain_otp, hashed_otp, expiry = generate_otp()
        user.reset_otp = hashed_otp
        user.reset_expiry = expiry
        db_session.commit()
        send_otp_email(email, user.username, plain_otp, subject="Your Password Reset OTP")
        return redirect(url_for('reset_password', email=email))
    return render_template('forgot_password.html')

@app.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    user = db_session.query(User).filter_by(email=email).first()
    if not user:
        return redirect(url_for('forgot_password'))
    step = request.args.get('step', 'otp')
    if request.method == 'POST':
        if step == 'otp':
            entered_otp = request.form.get('otp', '').strip()
            if datetime.now() > (user.reset_expiry or datetime.min):
                response = make_response(render_template('reset_password.html', email=email, error="OTP expired.", step="otp"))
                response = prevent_cache(response)
                return response
            hashed_entered_otp = hashlib.sha256(entered_otp.encode()).hexdigest()
            if hashed_entered_otp != user.reset_otp:
                response = make_response(render_template('reset_password.html', email=email, error="Invalid OTP.", step="otp"))
                response = prevent_cache(response)
                return response
            response = make_response(render_template('reset_password.html', email=email, step="password"))
            response = prevent_cache(response)
            return response
        elif step == 'password':
            new_password = request.form.get('new_password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()
            if new_password != confirm_password:
                response = make_response(render_template('reset_password.html', email=email, error="Passwords do not match.", step="password"))
                response = prevent_cache(response)
                return response
            if not is_strong_password(new_password):
                response = make_response(render_template('reset_password.html', email=email, error="Password must be at least 8 characters and include uppercase, lowercase, number, and symbol.", step="password"))
                response = prevent_cache(response)
                return response
            if bcrypt.check_password_hash(user.password, new_password):
                response = make_response(render_template('reset_password.html', email=email, error="New password must be different from the old password.", step="password"))
                response = prevent_cache(response)
                return response
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.reset_otp = None
            user.reset_expiry = None
            db_session.commit()
            response = make_response(redirect(url_for('login', message="Password reset successful. Please log in.")))
            response = prevent_cache(response)
            return response
    response = make_response(render_template('reset_password.html', email=email, step=step))
    response = prevent_cache(response)
    return response

@app.route('/verify_otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    error = ""
    message = ""
    user_data = db_session.query(PendingUser).filter_by(email=email).first()
    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        if not user_data:
            error = "User data not found. Please register."
        elif datetime.now() > (user_data.otp_expiry or datetime.min):
            error = "OTP expired. Please request a new one."
        else:
            hashed_entered_otp = hashlib.sha256(entered_otp.encode()).hexdigest()
            if hashed_entered_otp == user_data.otp:
                # OTP is correct, activate the user
                user = User(
                    username=user_data.username,
                    email=user_data.email,
                    password=user_data.password
                )
                db_session.add(user)
                db_session.delete(user_data)
                db_session.commit()
                session['username'] = user.email
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid OTP. Please try again."
    return render_template('verify_otp.html', email=email, error=error, message=message)

from apscheduler.schedulers.background import BackgroundScheduler
scheduler = BackgroundScheduler()
scheduler.add_job(cleanup_expired_pending_users, 'interval', minutes=30)
scheduler.start()

if __name__ == '__main__':
    app.run(debug=True)