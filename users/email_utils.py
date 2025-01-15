import os
import typing as t

from smtplib import SMTPException
from werkzeug.exceptions import ServiceUnavailable

from flask import current_app, render_template, url_for
from flask_mail import Message

from users.extensions import mail
from users.models import User
from users.utils import get_full_url
from config import BaseConfig


def send_mail(subject: t.AnyStr, recipients: t.List[str], body: t.Text):
    sender: str = os.environ.get("MAIL_USERNAME", None)

    if not sender:
        raise ValueError("`MAIL_USERNAME` environment variable is not set")

    message = Message(subject=subject, sender=sender, recipients=recipients)
    message.body = body

    print("Attempting to send email...")
    print(message.body)

    try:
        mail.send(message)
        print("Email sent successfully!")
    except SMTPException as e:
        print("SMTPException occurred:", e)
        raise ServiceUnavailable(
            description="SMTP mail service is unavailable. Please try later."
        )
    except Exception as e:
        print("General exception occurred:", e)
        raise ServiceUnavailable(
            description="An error occurred while sending the email."
        )


def send_confirmation_mail(user: User = None):
    subject: str = "Verify Your Account"

    token: str = user.generate_token(salt=current_app.config["ACCOUNT_CONFIRM_SALT"])

    verification_link: str = get_full_url(
        url_for("users.confirm_account", token=token)
    )

    context = render_template(
        "emails/verify_account.txt",
        username=user.username,
        verification_link=verification_link,
    )

    send_mail(subject=subject, recipients=[user.email], body=context)


def send_reset_password(user: User = None):
    subject: str = "Reset Your Password"

    token: str = user.generate_token(salt=current_app.config["RESET_PASSWORD_SALT"])

    reset_link: str = get_full_url(url_for("users.reset_password", token=token))

    context = render_template(
        "emails/reset_password.txt", username=user.username, reset_link=reset_link
    )

    send_mail(subject=subject, recipients=[user.email], body=context)


def send_reset_email(user: User = None):
    subject: str = "Confirm Your Email Address"

    token: str = user.generate_token(salt=current_app.config["CHANGE_EMAIL_SALT"])

    confirmation_link: str = get_full_url(
        url_for("users.confirm_email", token=token)
    )

    context = render_template(
        "emails/reset_email.txt",
        username=user.username,
        confirmation_link=confirmation_link,
    )

    send_mail(subject=subject, recipients=[user.change_email], body=context)


def send_notification_email(users: t.List[User], subject: str, body: str):
    """
    Send email notification to the specified users.
    :param users: List of User objects.
    :param subject: Subject of the email.
    :param body: Body of the email.
    """
    for user in users:
        msg = Message(subject, sender=os.environ.get("MAIL_USERNAME"), recipients=[user.email])
        msg.body = body
        mail.send(msg)


def send_volunteer_thank_you_email(email: str, user: User = None):
    try:
        sender = os.environ.get("MAIL_USERNAME", "no-reply@example.com")
        msg = Message("Thank You for Registering as a Tutor", sender=sender, recipients=[email])
        username = user.username if user else "User"
        msg.body = render_template("emails/volunteer_thank_you_email.txt", username=username)
        mail.send(msg)
        print("Thank-you email sent successfully!")
    except SMTPException as e:
        print(f"SMTP error: {str(e)}")
        raise ServiceUnavailable("SMTP mail service is currently unavailable. Please try later.")
    except Exception as e:
        print(f"General error: {str(e)}")
        raise ServiceUnavailable("An error occurred while sending the email. Please try later.")


def send_application_accepted_email(email: str, user: User = None):
    try:
        sender = os.environ.get("MAIL_USERNAME", "no-reply@example.com")
        username = user.username if user else "User"
        msg = Message("Application Accepted", sender=sender, recipients=[email])
        msg.body = render_template("emails/application_accepted_email.txt", username=username)
        mail.send(msg)
        print("Application accepted email sent successfully!")
    except SMTPException as e:
        print(f"SMTP error: {str(e)}")
        raise ServiceUnavailable("SMTP mail service is unavailable. Please try again later.")
    except Exception as e:
        print(f"General error: {str(e)}")
        raise ServiceUnavailable("An error occurred while sending the email. Please try again later.")


def send_application_rejected_email(email: str, user: User = None):
    try:
        sender = os.environ.get("MAIL_USERNAME", "no-reply@example.com")
        username = user.username if user else "User"
        msg = Message("Application Rejected", sender=sender, recipients=[email])
        msg.body = render_template("emails/application_rejected_email.txt", username=username)
        mail.send(msg)
        print("Application rejected email sent successfully!")
    except SMTPException as e:
        print(f"SMTP error: {str(e)}")
        raise ServiceUnavailable("SMTP mail service is unavailable. Please try again later.")
    except Exception as e:
        print(f"General error: {str(e)}")
        raise ServiceUnavailable("An error occurred while sending the email. Please try again later.")


def send_documents_email(user_id, id_copy_filename, certificates_filename):
    try:
        user = User.query.get(user_id)
        if not user:
            print("User not found!")
            return

        recipient = os.environ.get("MAIL_USERNAME", "admin@example.com")
        msg = Message("Documents Attached", sender=user.email, recipients=[recipient])
        msg.body = f"User {user.username} has registered as a tutor."

        # Attach ID Copy
        if id_copy_filename:
            id_copy_path = os.path.join(
                current_app.config["UPLOAD_FOLDER_SUPPORTING_DOCUMENTS"], id_copy_filename
            )
            if os.path.exists(id_copy_path):
                with open(id_copy_path, "rb") as id_copy_file:
                    msg.attach(id_copy_filename, "application/pdf", id_copy_file.read())
                print(f"ID copy attached: {id_copy_path}")
            else:
                print(f"ID copy file not found: {id_copy_path}")

        # Attach Certificates
        if certificates_filename:
            certificates_path = os.path.join(
                current_app.config["UPLOAD_FOLDER_SUPPORTING_DOCUMENTS"], certificates_filename
            )
            if os.path.exists(certificates_path):
                with open(certificates_path, "rb") as certificates_file:
                    msg.attach(certificates_filename, "application/pdf", certificates_file.read())
                print(f"Certificate attached: {certificates_path}")
            else:
                print(f"Certificate file not found: {certificates_path}")

        mail.send(msg)
        print("Documents email sent successfully!")
    except Exception as e:
        print(f"Error in send_documents_email: {str(e)}")
