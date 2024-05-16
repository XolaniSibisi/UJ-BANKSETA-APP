from werkzeug.utils import secure_filename
from flask import render_template, redirect, url_for
from flask_mail import Message
from users.extensions import mail
import uuid
import secrets
import os

def unique_uid():
    return str(uuid.uuid4())

def unique_security_token():
    return str(secrets.token_hex())

def get_unique_filename(filename=None):
    if not filename:
        return None
        
    filename = secure_filename(filename).split(".")
    return "{}.{}".format(str(uuid.uuid4()), filename[len(filename)-1])

def remove_existing_file(path=None):
    if os.path.isfile(path=path):
        os.remove(path)

def send_mail(subject, recipients, body):
    sender = os.environ.get('MAIL_USERNAME', None)
    message = Message(
            subject=subject, sender=sender, recipients=[recipients]
        )
    message.body = body
    print(message.body)
    mail.connect()
    mail.send(message)

def send_reset_password(user=None):

    subject = "Reset Your Password."
    recipient = user.email

    reset_link = url_for('users.reset_password', token=user.security_token)
    content = f"""
    Hello, {user.username}

    We receive a request for Reset Your Password.

    Please click the following link to reset your password.
    {reset_link}
    """
    send_mail(subject=subject, recipients=recipient, body=content)

def send_reset_email(user=None):

    subject = "Confirm Your Email Address."
    recipient = user.change_email

    confirmation_link = url_for('users.confirm_email', token=user.security_token)
    content = f"""
    Hello, {user.username}
    
    We receive a request for Changing Email Address.

    Please click the following link to confirm your email address.
    {confirmation_link}
    """
    send_mail(subject=subject, recipients=recipient, body=content)
    
def send_notification_email(users, subject, body):
    """
    Send email notification to the specified users.

    Parameters:
    - users: List of User objects.
    - subject: Subject of the email.
    - body: Body of the email.
    """
    for user in users:
        msg = Message(subject,
                      sender=os.environ.get('MAIL_USERNAME'),
                      recipients=[user.email])
        msg.body = body
        mail.send(msg)
        
def send_volunteer_thank_you_email(email):
    try:
        sender = os.environ.get('MAIL_USERNAME', None)
        msg = Message('Thank You for Registering as a Volunteer', sender=sender, recipients=[email])
        msg.body = render_template('volunteer_thank_you_email.txt')
        mail.send(msg)
        print('Volunteer thank you email sent successfully.')
    except Exception as e:
        print(f'Error sending volunteer thank you email: {str(e)}')

def send_application_accepted_email(email):
    try:
        sender = os.environ.get('MAIL_USERNAME', None)
        msg = Message('Application Accepted', sender=sender, recipients=[email])
        msg.body = render_template('application_accepted_email.txt')
        mail.send(msg)
        print('Application accepted email sent successfully.')
    except Exception as e:
        print(f'Error sending application accepted email: {str(e)}')

def send_application_rejected_email(email):
    try:
        sender = os.environ.get('MAIL_USERNAME', None)
        msg = Message('Application Rejected', sender=sender, recipients=[email])
        msg.body = render_template('application_rejected_email.txt')
        mail.send(msg)
        print('Application rejected email sent successfully.')
    except Exception as e:
        print(f'Error sending application rejected email: {str(e)}')