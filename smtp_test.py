import smtplib
import os
from dotenv import load_dotenv

load_dotenv()

smtp_server = 'smtp.gmail.com'
port = 587
sender_email = os.getenv('MAIL_USERNAME')
password = os.getenv('MAIL_PASSWORD')
receiver_email = sender_email

try:
    server = smtplib.SMTP(smtp_server, port, timeout=10)
    server.starttls()
    server.login(sender_email, password)
    message = "Subject: SMTP Test\n\nThis is a test email from your Flask app."
    server.sendmail(sender_email, receiver_email, message)
    print("SMTP connection and email sent successfully!")
    server.quit()
except Exception as e:
    print(f"SMTP test failed: {e}")
