g# Flask 2.0 User Registration & OTP Project

This project is a Flask-based web application for user registration, login, password reset, and OTP verification. It uses SQLite for storage and supports email-based OTP for secure registration and password reset.

## Features
- User registration with OTP email verification
- Login with reCAPTCHA
- Password reset via OTP
- Dashboard with diary entry feature
- Secure password hashing (bcrypt)
- Email notifications (Flask-Mail)
- SQLite database (SQLAlchemy)
- Environment variable support (.env)

## Setup
1. Clone the repository:
   ```sh
   git clone <your-repo-url>
   cd flask2.0
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up your `.env` file with:
   - `SECRET_KEY`
   - `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER`
   - `RECAPTCHA_SITE_KEY`, `RECAPTCHA_SECRET_KEY`

4. Run the app:
   ```sh
   python3 app.py
   ```

## .env File
This project requires a `.env` file in the project root to store sensitive configuration. Create a file named `.env` and add the following variables:

```bash
SECRET_KEY=your_secret_key_here
MAIL_USERNAME=your_gmail_address@gmail.com
MAIL_PASSWORD=your_gmail_app_password
MAIL_DEFAULT_SENDER=your_gmail_address@gmail.com
RECAPTCHA_SITE_KEY=your_recaptcha_site_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
```

- `SECRET_KEY`: Any random string for Flask session security.
- `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER`: Your Gmail and app password for sending emails.
- `RECAPTCHA_SITE_KEY`, `RECAPTCHA_SECRET_KEY`: Keys from Google reCAPTCHA admin console.

**Never commit your `.env` file to version control.**

## File Structure
- `app.py` — Main Flask application
- `models.py` — SQLAlchemy models
- `key.py` — Utility script to generate a secure random secret key for your `.env` file
- `smtp_test.py` — Script to test your SMTP email configuration and ensure emails can be sent from your environment
- `templates/` — HTML templates
- `users.db` — SQLite database (SQLAlchemy)
- `.env` — Environment variables
- `requirements.txt` — Python dependencies

### File Details
- `key.py` — Run this script to generate a secure random secret key for your Flask app. Example usage:
  ```bash
  python3 key.py
  ```
  Copy the printed key and paste it into your `.env` file as `SECRET_KEY`.

- `models.py` — Contains all SQLAlchemy ORM models:
  - `User`: Stores registered users (username, email, password hash, OTP reset fields).
  - `PendingUser`: Temporarily stores users who are registering and awaiting OTP verification.
  - `DiaryEntry`: Stores diary entries linked to users.
  This file also creates the SQLite database tables if they do not exist.

- `smtp_test.py` — Use this script to test your email (SMTP) configuration. It will attempt to send a test email using your `.env` credentials. Example usage:
  ```bash
  python3 smtp_test.py
  ```
  If successful, you will see a confirmation in the terminal and receive a test email. If not, check your SMTP settings in `.env`.

## Notes
- Make sure to use a Gmail App Password for email sending.
- For local development, reCAPTCHA site key should allow localhost.
- Delete `users.db` if you change models to recreate the database.

## License
MIT
