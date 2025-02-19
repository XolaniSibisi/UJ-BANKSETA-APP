from tkinter.tix import Form
from flask import (
    abort,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    current_app,
)
from flask_wtf.csrf import generate_csrf
from flask import Blueprint, send_file, Response
from sqlalchemy.orm import joinedload
from werkzeug.utils import secure_filename
from flask import send_from_directory
from http import HTTPStatus
from werkzeug.exceptions import InternalServerError
import imghdr
import uuid
from sqlalchemy import or_, func, desc
from collections import Counter
from sqlalchemy.exc import IntegrityError
import pytz
from flask_login import current_user, login_required, login_user, logout_user
from users.email_utils import (
    send_reset_password,
    send_reset_email,
    send_notification_email,
    send_application_accepted_email,
    send_application_rejected_email,
    send_volunteer_thank_you_email,
    send_documents_email,
)
from users.extensions import database as db, csrf
from users.decorators import authentication_redirect
from users.models import (
    User,
    Profile,
    Content,
    Contact,
    Slots,
    Post,
    Comment,
    Like,
    Notification,
    Papers,
)
from users.catalogues import maths_catalogue, physical_science_catalogue
from users.forms import (
    RegisterForm,
    LoginForm,
    ForgotPasswordForm,
    ResetPasswordForm,
    ChangePasswordForm,
    ChangeEmailForm,
    ContactForm,
    UploadContentForm,
    EditUserProfileForm,
    CreateSlotForm,
    PostForm,
    CommentForm,
    PapersForm,
)

from flask_mail import Message
from users.extensions import mail
from datetime import datetime, timedelta, time
import re
import mimetypes
import requests
import tempfile
import os
from urllib.parse import urlparse, parse_qs
from config import (
    UPLOAD_FOLDER,
    UPLOAD_FOLDER_SUPPORTING_DOCUMENTS,
    UPLOAD_FOLDER_LOCAL_FILES,
    UPLOAD_FOLDER_PROBLEM_IMAGES,
)
import logging


"""
This accounts blueprint defines routes and templates related to user management
within our application.
"""
users = Blueprint("users", __name__, template_folder="templates")


logging.basicConfig(level=logging.DEBUG)


@users.route("/register", methods=["GET", "POST"])
@authentication_redirect
def register() -> Response:

    if request.method == "POST":
        print(request.form)

    """
    Handling user registration.
    If the user is already authenticated, they are redirected to the index page.
    This view handles both GET and POST requests:
    - GET: Renders the registration form and template.
    - POST: Processes the registration form, creates a new user, and sends a confirmation email.
    :return: Renders the registration template on GET request
    or redirects to login after successful registration.
    """
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.data.get("username")
        first_name = form.data.get("first_name")
        last_name = form.data.get("last_name")
        email = form.data.get("email")
        role = form.data.get("role")
        password = form.data.get("password")

        # Save uploaded files
        id_copy_filename = None
        certificates_filename = None
        if form.id_copy.data:
            id_copy_filename = secure_filename(form.id_copy.data.filename)
            id_copy_destination = os.path.join(
                current_app.config["UPLOAD_FOLDER_SUPPORTING_DOCUMENTS"],
                id_copy_filename,
            )
            os.makedirs(os.path.dirname(id_copy_destination), exist_ok=True)
            form.id_copy.data.save(id_copy_destination)
        if form.certificates.data:
            certificates_filename = secure_filename(form.certificates.data.filename)
            certificates_destination = os.path.join(
                current_app.config["UPLOAD_FOLDER_SUPPORTING_DOCUMENTS"],
                certificates_filename,
            )
            os.makedirs(os.path.dirname(certificates_destination), exist_ok=True)
            form.certificates.data.save(certificates_destination)

        # Attempt to create a new user and save to the database
        user = User.create(
            username=username,
            first_name=first_name,
            last_name=last_name,
            email=email,
            role=role,
            password=password,
        )

        if user:
            print(f"User {user.username} created successfully!")
        else:
            print("Failed to create user")

        if role == "tutor":
            send_volunteer_thank_you_email(user.email)
            send_documents_email(user.id, id_copy_filename, certificates_filename)
            flash(
                "Thank you for registering with us, a message with more information has been sent to your email.",
                "info",
            )
            return redirect(url_for("users.login"))
        else:
            user.send_confirmation()
            flash(
                "A confirmation link has been sent to your email. Please verify your account.",
                "info",
            )
            return redirect(url_for("users.login"))

    return render_template("register.html", form=form)


@users.route("/verification", methods=["GET", "POST"])
@login_required
def verification():
    form = ContactForm()
    if current_user.role == "admin":
        if request.method == "POST":
            volunteer_id = request.form.get("volunteer_id")
            action = request.form.get("action")

            volunteer = User.query.get(volunteer_id)
            if not volunteer:
                flash("Tutor not found.", "error")
                return redirect(url_for("users.verification"))

            if action == "verify":
                try:
                    volunteer.active = True
                    volunteer.security_token = None
                    db.session.commit()
                    send_application_accepted_email(volunteer.email, user=volunteer)
                    flash(
                        f"{volunteer.username} has been verified successfully.",
                        "success",
                    )
                except Exception as e:
                    print(f"Error verifying tutor: {str(e)}")
                    flash("An error occurred while verifying the tutor.", "error")
            else:
                flash("Invalid action.", "error")
            return redirect(url_for("users.verification"))

        volunteers_to_verify = User.query.filter_by(role="tutor", active=False).all()
        return render_template(
            "verification.html",
            user=current_user,
            volunteers=volunteers_to_verify,
            form=form,
        )
    else:
        return redirect(url_for("users.home"))


@users.route("/rejection", methods=["POST"])
@login_required
def rejection():
    if current_user.role == "admin":
        volunteer_id = request.form.get("volunteer_id")
        action = request.form.get("action")

        volunteer = User.query.get(volunteer_id)
        if not volunteer:
            flash("Tutor not found.", "error")
            return redirect(url_for("users.verification"))

        try:
            db.session.delete(volunteer)
            db.session.commit()
            send_application_rejected_email(volunteer.email, user=volunteer)
            flash(f"{volunteer.username} has been rejected.", "success")
        except Exception as e:
            print(f"Error rejecting tutor: {str(e)}")
            flash("An error occurred while rejecting the tutor.", "error")

        return redirect(url_for("users.verification"))


@users.route("/login", methods=["GET", "POST"])
@authentication_redirect
def login() -> Response:
    """
    Handling user login functionality.
    If the user is already authenticated, they are redirected to the index page.

    This view handles both GET and POST requests:
    - GET: Renders the login form and template.
    - POST: Validates the form and authenticates the user.

    :return: Renders the login template on GET request or redirects based on the login status.
    """
    form = LoginForm()

    if form.validate_on_submit():
        username = form.data.get("username", None)
        password = form.data.get("password", None)
        remember = form.data.get("remember", True)

        # Attempt to authenticate the user
        user = User.authenticate(username=username, password=password)

        if not user:
            flash("Invalid username or password. Please try again.", "error")

        else:
            if not user.is_active:
                # Check if the user is a volunteer and not verified
                if user.role == "tutor" and not user.is_active():
                    flash(
                        "Your account is not verified yet. Please wait for verification from the admin.",
                        "error",
                    )
                    return redirect(url_for("users.login"))

                user.send_confirmation()
                flash(
                    "Your account is not active. We've sent you a confirmation email. Please check your email to activate your account.",
                    "error",
                )
                return redirect(url_for("users.login"))

            login_user(user, remember=remember, duration=timedelta(days=15))

            flash("You are logged in successfully.", "success")

            # Redirect admin users to the dashboard
            if user.role == "admin":
                return redirect(url_for("users.dashboard"))
            else:
                return redirect(url_for("users.home"))

    return render_template("login.html", form=form)


@users.route("/account/confirm", methods=["GET", "POST"])
def confirm_account() -> Response:
    """
    Handling account confirmation request via a token.
    If the token is valid and not expired, the user is activated.

    This view handles both GET and POST requests:
    - GET: Renders the account confirmation template.
    - POST: Activates the user account if the token is valid,
            logs the user in, and redirects to the index page.

    :return: Renders the confirmation template on GET request,
    redirects to login or index after POST.
    """
    token: str = request.args.get("token", None)

    # Verify the provided token and return token instance.
    auth_token = User.verify_token(
        token=token, salt=current_app.config["ACCOUNT_CONFIRM_SALT"]
    )

    if auth_token:
        # Retrieve the user instance associated with the token by providing user ID.
        user = User.get_user_by_id(auth_token.user_id, raise_exception=True)

        if request.method == "POST":
            try:
                # Activate the user's account and expire the token.
                user.active = True
                auth_token.expire = True

                # Commit changes to the database.
                db.session.commit()
            except Exception as e:
                # Handle database error that occur during the account activation.
                raise InternalServerError

            # Log the user in and set the session to remember the user for (15 days).
            login_user(user, remember=True, duration=timedelta(days=15))

            flash(
                f"Welcome {user.username}, You're registered successfully.", "success"
            )
            return redirect(url_for("users.home"))

        return render_template("confirm_account.html", token=token)

    # If the token is invalid, return a 404 error
    return abort(HTTPStatus.NOT_FOUND)


@users.route("/logout", methods=["GET", "POST"])
@login_required
def logout() -> Response:
    """
    Logs out the currently authenticated user
    and redirect them to the login page.

    :return: A redirect response to the login page with a success flash message.
    """
    # Log out the user and clear the session.
    logout_user()

    flash("You're logout successfully.", "success")
    return redirect(url_for("users.login"))


@users.route("/forgot/password", methods=["GET", "POST"])
def forgot_password() -> Response:
    """
    Handling forgot password requests by validating the provided email
    and sending a password reset link if the email is registered.

    This view handles both GET and POST requests:
    - GET: Renders the forgot password form and template.
    - POST: Validates the email and sends a reset link if the email exists in the system.

    :return: Renders the forgot password form on GET,
    redirects to login on success, or reloads the form on failure.
    """
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.data.get("email")

        # Attempt to find the user by email from the database.
        user = User.get_user_by_email(email=email)

        if user:
            # Send a reset password link to the user's email.
            send_reset_password(user)

            flash("A reset password link sent to your email. Please check.", "success")
            return redirect(url_for("users.login"))

        flash("Email address is not registered with us.", "error")
        return redirect(url_for("users.forgot_password"))

    return render_template("forgot_password.html", form=form)


@users.route("/password/reset", methods=["GET", "POST"])
def reset_password() -> Response:
    """
    Handling password reset requests.

    This function allows users to reset their password by validating a token
    and ensuring the new password meets security criteria.

    This view handles both GET and POST requests:
    - GET: Renders the reset password form and template, if the token is valid.
    - POST: Validates the form, checks password strength, and updates the user's password.

    :return: Renders the reset password form on GET,
    redirects to login on success, or reloads the form on failure.
    """
    token = request.args.get("token", None)

    # Verify the provided token and return token instance.
    auth_token = User.verify_token(
        token=token, salt=current_app.config["RESET_PASSWORD_SALT"]
    )

    if auth_token:
        form = ResetPasswordForm()  # A form class to Reset User's Password.

        if form.validate_on_submit():
            password = form.data.get("password")
            confirm_password = form.data.get("confirm_password")

            # Regex pattern to validate password strength.
            re_pattern = r"(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$"

            if not (password == confirm_password):
                flash("Your new password field's not match.", "error")
            elif not re.match(re_pattern, password):
                flash(
                    "Please choose strong password. It contains at least one alphabet, number, and one special character.",
                    "warning",
                )
            else:
                try:
                    # Retrieve the user by the ID from the token and update their password.
                    user = User.get_user_by_id(auth_token.user_id, raise_exception=True)
                    user.set_password(password)

                    # Mark the token as expired after the password is reset.
                    auth_token.expire = True

                    # Commit changes to the database.
                    db.session.commit()
                except Exception as e:
                    # Handle database error by raising an internal server error.
                    raise InternalServerError

                flash("Your password is changed successfully. Please login.", "success")
                return redirect(url_for("users.login"))

            return redirect(url_for("users.reset_password", token=token))

        return render_template("reset_password.html", form=form, token=token)

    # If the token is invalid, abort with a 404 Not Found status.
    return abort(HTTPStatus.NOT_FOUND)


@users.route("/change/password", methods=["GET", "POST"])
@login_required
def change_password() -> Response:
    """
    Handling user password change requests.

    This function allows authenticated users to change their password by
    verifying the old password and ensuring the new password meets security criteria.

    This view handles both GET and POST requests:
    - GET: Renders the change password form and template.
    - POST: Validates the form, checks old password correctness, ensures the new
      password meets security standards, and updates the user's password.

    :return: Renders the change password form on GET,
    redirects to index on success, or reloads the form on failure.
    """
    form = ChangePasswordForm()  # A form class to Change User's Password.

    if form.validate_on_submit():
        old_password = form.data.get("old_password")
        new_password = form.data.get("new_password")
        confirm_password = form.data.get("confirm_password")

        # Retrieve the fresh user instance from the database.
        user = User.get_user_by_id(current_user.id, raise_exception=True)

        # Regex pattern to validate password strength.
        re_pattern = (
            r"(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$"
        )

        if not user.check_password(old_password):
            flash("Your old password is incorrect.", "error")
        elif not (new_password == confirm_password):
            flash("Your new password field's not match.", "error")
        elif not re.match(re_pattern, new_password):
            flash(
                "Please choose strong password. It contains at least one alphabet, number, and one special character.",
                "warning",
            )
        else:
            try:
                # Update the user's password.
                user.set_password(new_password)

                # Commit changes to the database.
                db.session.commit()
            except Exception as e:
                # Handle database error by raising an internal server error.
                raise InternalServerError

            flash("Your password changed successfully.", "success")
            return redirect(url_for("users.home"))

        return redirect(url_for("users.change_password"))

    return render_template("change_password.html", form=form)


@users.route("/change/email", methods=["GET", "POST"])
@login_required
def change_email() -> Response:
    """
    Handling email change requests for the logged-in user.

    Methods:
        GET: Render the email change form and template.
        POST: Process the form submission to change the user's email.

    Returns:
        Response: The rendered change email template or a redirect after form submission.
    """
    form = ChangeEmailForm()  # A form class for Change Email Address.

    if form.validate_on_submit():
        email = form.data.get("email", None)

        # Retrieve the fresh user instance based on their ID.
        user = User.get_user_by_id(current_user.id, raise_exception=True)

        if email == user.email:
            flash("Email is already verified with your account.", "warning")
        elif User.query.filter(User.email == email, User.id != user.id).first():
            flash("Email address is already registered with us.", "warning")
        else:
            try:
                # Update the new email as the pending email change.
                user.change_email = email

                # Commit changes to the database.
                db.session.commit()
            except Exception as e:
                # Handle database error by raising an internal server error.
                raise InternalServerError

            # Send a reset email to the new email address.
            send_reset_email(user)

            flash(
                "A reset email link sent to your new email address. Please verify.",
                "success",
            )
            return redirect(url_for("users.home"))

        return redirect(url_for("users.change_email"))

    return render_template("change_email.html", form=form)


@users.route("/account/email/confirm", methods=["GET", "POST"])
def confirm_email() -> Response:
    """
    Handle email confirmation via a token sent to the user's new email address.

    Methods:
        GET: Render the email confirmation template with the token.
        POST: Confirm the email change by verifying the token.

    Returns:
        Response: The rendered confirm email template, or a redirect after confirmation.
    """
    token = request.args.get("token", None)

    # Verify the provided token and return token instance.
    auth_token = User.verify_token(
        token=token, salt=current_app.config["CHANGE_EMAIL_SALT"]
    )

    if auth_token:
        if request.method == "POST":
            # Retrieve the user by the ID from the token and update email details.
            user = User.get_user_by_id(auth_token.user_id, raise_exception=True)

            try:
                # Update new email address to user.
                user.email = user.change_email
                user.change_email = None

                # Mark the token as expired after the new email is set.
                auth_token.expire = True

                # Commit changes to the database.
                db.session.commit()
            except Exception as e:
                # Handle database error by raising an internal server error.
                raise InternalServerError

            flash("Your email address updated successfully.", "success")
            return redirect(url_for("users.home"))

        return render_template("confirm_email.html", token=token)

    # If the token is invalid, abort with a 404 Not Found status.
    return abort(HTTPStatus.NOT_FOUND)


@users.route("/")
@users.route("/home")
@login_required
def home() -> Response:

    form = ContactForm()

    paper_combinations = [
        {'paper_type': 'caps', 'stem': 'maths', 'label': 'Mathematics Exam Papers (CAPS)', 'img': 'maths_caps.png'},
        {'paper_type': 'ieb', 'stem': 'maths', 'label': 'Mathematics Exam Papers (IEB)', 'img': 'maths_ieb.png'},
        {'paper_type': 'caps', 'stem': 'science', 'label': 'Physical Science Exam Papers (CAPS)', 'img': 'science_caps.png'},
        {'paper_type': 'ieb', 'stem': 'science', 'label': 'Physical Science Exam Papers (IEB)', 'img': 'science_ieb.png'}
    ]

    return render_template("home.html", form=form, paper_combinations=paper_combinations)


@users.route("/error", strict_slashes=False)
def error():
    form = ContactForm()
    return render_template("error.html", form=form)


@users.route("/profile", methods=["GET", "POST"])
@login_required
def profile() -> Response:
    """
    Handling the user's profile page,
    allowing them to view and edit their profile information.

    Methods:
        GET: Render the profile template with the user's current information.
        POST: Update the user's profile with the submitted form data.

    Returns:
        Response: The rendered profile template or a redirect after form submission.
    """
    form = EditUserProfileForm()

    user = User.get_user_by_id(current_user.id, raise_exception=True)
    profile = Profile.query.filter_by(user_id=user.id).first_or_404()

    # Fetch the taken teaching slots if the user is a volunteer
    taken_teaching_slots = []
    if current_user.role == "tutor":
        taken_teaching_slots = Slots.query.filter_by(volunteer_id=profile.id).all()

    # Fetch the taken attending slots if the user is a student
    taken_attending_slots = []
    if current_user.role == "student":
        taken_attending_slots = Slots.query.filter_by(student_id=profile.id).all()

    if form.validate_on_submit():
        username = form.data.get("username")
        first_name = form.data.get("first_name")
        last_name = form.data.get("last_name")
        profile_image = form.data.get("profile_image")
        about = form.data.get("about")

        # Check if the new username already exists and belongs to a different user.
        username_exist = User.query.filter(
            User.username == username, User.id != current_user.id
        ).first()

        if username_exist:
            flash("Username already exists. Choose another.", "error")
        else:
            try:
                # Update the user's profile details.
                user.username = username
                user.first_name = first_name
                user.last_name = last_name
                user.profile.bio = about

                # Handle profile image upload if provided.
                if profile_image and getattr(profile_image, "filename"):
                    user.profile.set_avator(profile_image)

                # Commit changes to the database.
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                # Handle database error by raising an internal server error.
                print(f"Error during profile update: {e}")
                flash("An error occurred while updating your profile.", "error")

            flash("Your profile update successfully.", "success")
            return redirect(url_for("users.home"))

        return redirect(url_for("users.profile"))

    return render_template(
        "profile.html",
        form=form,
        profile=profile,
        taken_teaching_slots=taken_teaching_slots,
        taken_attending_slots=taken_attending_slots,
        get_notification_count=get_notification_count,
    )


@users.route("/admin/profile", methods=["GET"])
@login_required
def admin_profile():
    form = ContactForm()
    if current_user.role != "admin":
        abort(403)  # Forbidden: Only admins can access this page

    # Fetch profiles for both students and volunteers
    students = User.query.filter_by(role="student").all()
    volunteers = User.query.filter_by(role="tutor").all()

    # Create dictionaries to store profiles for both user types
    student_profiles = {}
    volunteer_profiles = {}

    # Populate student profiles
    for student in students:
        profile = Profile.query.filter_by(user_id=student.id).first()
        student_profiles[student] = profile

    # Populate volunteer profiles
    for volunteer in volunteers:
        profile = Profile.query.filter_by(user_id=volunteer.id).first()
        volunteer_profiles[volunteer] = profile

    selected_role = request.args.get(
        "role", ""
    )  # Get selected role from query parameter

    return render_template(
        "admin_profile.html",
        students=students,
        volunteers=volunteers,
        student_profiles=student_profiles,
        volunteer_profiles=volunteer_profiles,
        selected_role=selected_role,
        form=form,
    )


@users.route("/view_user/<user_id>", methods=["GET"])
@login_required
def view_user(user_id):
    form = ContactForm()
    user = User.query.get_or_404(user_id)
    profile = Profile.query.filter_by(user_id=user_id).first_or_404()

    # Fetch the slots associated with the user's profile
    taken_teaching_slots = []
    taken_attending_slots = []

    if user.role == "tutor":
        taken_teaching_slots = profile.teaching_slots
    elif user.role == "student":
        taken_attending_slots = profile.attending_slots

    return render_template(
        "view_user.html",
        user=user,
        profile=profile,
        taken_teaching_slots=taken_teaching_slots,
        taken_attending_slots=taken_attending_slots,
        form=form,
    )


@users.route("/delete_user/<user_id>", methods=["POST"], strict_slashes=False)
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if not user:
        flash("User not found.", "error")
    else:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully.", "success")
    return redirect(url_for("users.admin_profile"))


@users.route("/contact", methods=["GET", "POST"])
@login_required
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        entry = Contact(
            name=form.name.data,
            email=form.email.data,
            subject=form.subject.data,
            message=form.message.data,
        )

        entry.save()

        send_email(
            form.name.data, form.email.data, form.subject.data, form.message.data
        )

        return redirect(url_for("users.contact_success"))

    return render_template("contact.html", form=form)


@users.route("/contact/success")
@login_required
def contact_success():
    form = ContactForm()
    return render_template("contact_success.html", form=form)


def send_email(name, email, subject, message):
    msg = Message(
        subject=f"New message from {name} via contact form",
        sender=current_user.email if current_user.is_authenticated else form.email.data,
        recipients=[os.environ.get("MAIL_USERNAME")],
    )
    msg.body = f"Name: {name}\nEmail: {email}\nSubject: {subject}\nMessage: {message}"

    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


# route to edit profile
@users.route("/edit_profile", methods=["GET", "POST"], strict_slashes=False)
@login_required
def edit_profile():
    form = EditUserProfileForm()

    user = User.query.get_or_404(current_user.id)
    profile = Profile.query.filter_by(user_id=user.id).first_or_404()

    if form.validate_on_submit():
        username = form.data.get("username")
        first_name = form.data.get("first_name")
        last_name = form.data.get("last_name")
        profile_image = form.data.get("profile_image")
        about = form.data.get("about")

        if username in [
            user.username
            for user in User.query.all()
            if username != current_user.username
        ]:
            flash("Username already exists. Choose another.", "error")
        else:
            user.username = username
            user.first_name = first_name
            user.last_name = last_name
            profile.bio = about

            if profile_image and getattr(profile_image, "filename"):
                profile.set_avator(profile_image)

            db.session.commit()
            flash("Your profile update successfully.", "success")
            return redirect(url_for("users.profile"))

        return redirect(url_for("users.edit_profile"))

    return render_template("edit_profile.html", form=form, profile=profile)


@users.route("/forum", methods=["GET", "POST"], strict_slashes=False)
@login_required
def forum():
    form = PostForm()
    all_users_count = User.query.filter(
        (User.role != "admin") & (User.role.isnot(None))
    ).count()
    all_post = len(Post.query.all())
    cutoff_date = datetime.utcnow() - timedelta(days=2)
    new_member = (
        User.query.filter(User.role != "admin").order_by(desc(User.created_at)).first()
    )
    all_topics_count = Post.query.with_entities(
        func.count(Post.topic.distinct())
    ).scalar()
    current_date = datetime.now()
    user = User.query.get_or_404(current_user.id)

    mark_notifications_as_read(current_user.id)

    # Query for posts with recent comments
    active_topics = (
        Post.query.join(Comment, Comment.post_id == Post.id)
        .filter(Comment.date_posted >= cutoff_date)
        .distinct()
        .all()
    )

    if request.method == "POST":
        # Perform search
        search_query = request.form.get("search_query")
        if search_query:
            posts = (
                Post.query.filter(
                    Post.topic.ilike(f"%{search_query}%")
                    | Post.content.ilike(f"%{search_query}%")
                )
                .order_by(Post.date_posted.desc())
                .all()
            )
        else:
            posts = []
    else:
        # Regular page loading
        page = request.args.get("page", 1, type=int)
        posts = Post.query.order_by(Post.date_posted.desc()).paginate(
            page=page, per_page=5
        )

    return render_template(
        "forum.html",
        posts=posts,
        form=form,
        current_date=current_date,
        format_time_difference=format_time_difference,
        all_users_count=all_users_count,
        all_post=all_post,
        all_topics_count=all_topics_count,
        new_member=new_member,
        active_topics=active_topics,
    )


# Function to mark notifications as read
def mark_notifications_as_read(user_id):
    notifications = Notification.query.filter_by(recipient_id=user_id, read=False).all()
    for notification in notifications:
        notification.read = True
    db.session.commit()


@users.route("/filter_posts", methods=["GET", "POST"])
@login_required
def filter_posts():
    form = PostForm()
    all_users_count = User.query.filter(User.role != "admin").count()
    all_post = len(Post.query.all())
    cutoff_date = datetime.utcnow() - timedelta(days=2)
    new_member = (
        User.query.order_by(desc(User.created_at)).distinct(User.username).first()
    )
    all_topics_count = Post.query.with_entities(
        func.count(Post.topic.distinct())
    ).scalar()
    page = request.args.get("page", 1, type=int)
    current_date = datetime.now()

    # Query for posts with recent comments
    active_topics = (
        Post.query.join(Comment, Comment.post_id == Post.id)
        .filter(Comment.date_posted >= cutoff_date)
        .distinct()
        .all()
    )

    if request.method == "POST":
        topic = request.form.get("topic")
        if topic == "filterby":
            posts = Post.query.order_by(Post.date_posted.desc()).paginate(
                page=page, per_page=5
            )

        else:
            posts = (
                Post.query.filter(or_(Post.topic == topic, topic == " "))
                .order_by(Post.date_posted.desc())
                .paginate(page=page, per_page=5)
            )
        return render_template(
            "forum.html",
            posts=posts,
            form=form,
            selected_topic=topic,
            current_date=current_date,
            format_time_difference=format_time_difference,
            all_users_count=all_users_count,
            all_post=all_post,
            all_topics_count=all_topics_count,
            new_member=new_member,
            active_topics=active_topics,
        )
    return render_template(
        "forum.html",
        form=form,
        current_date=current_date,
        format_time_difference=format_time_difference,
        all_users_count=all_users_count,
        all_post=all_post,
        all_topics_count=all_topics_count,
        new_member=new_member,
        active_topics=active_topics,
    )


def format_time_difference(delta):
    if delta.days == 0:
        seconds = delta.seconds
        if seconds < 60:
            return f"{seconds} seconds ago"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes} minutes ago"
        else:
            hours = seconds // 3600
            return f"{hours} hours ago"
    else:
        return f"{delta.days} day(s) ago"


def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in [
        "png",
        "jpg",
        "jpeg",
        "svg",
    ]


@users.route("/post/new", methods=["POST", "GET"])
@login_required
def new_post():
    form = PostForm()

    # Populate topic choices based on selected STEM
    if form.stem.data == "maths":
        form.topic.choices = [(chapter, chapter) for chapter in maths_catalogue.keys()]
    elif form.stem.data == "science":
        form.topic.choices = [
            (chapter, chapter) for chapter in physical_science_catalogue.keys()
        ]

    # Populate subtopic choices based on selected topic
    if form.topic.data:
        if form.stem.data == "maths" and form.topic.data in maths_catalogue:
            form.subtopic.choices = [
                (subtopic, subtopic) for subtopic in maths_catalogue[form.topic.data]
            ]
        elif (
            form.stem.data == "science"
            and form.topic.data in physical_science_catalogue
        ):
            form.subtopic.choices = [
                (subtopic, subtopic)
                for subtopic in physical_science_catalogue[form.topic.data]
            ]

    image_filename = None
    if form.validate_on_submit():
        if form.image.data:
            image_file = form.image.data
            if allowed_image(image_file.filename):
                image_filename = secure_filename(image_file.filename)
                image_path = os.path.join(
                    current_app.config["UPLOAD_FOLDER_PROBLEM_IMAGES"], image_filename
                )

                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(image_path), exist_ok=True)

                image_file.save(image_path)
            else:
                flash("Invalid image file format!", "error")
                return redirect(url_for("users.new_post"))  # Redirect back to the form

        post = Post(
            topic=form.topic.data,
            subtopic=form.subtopic.data,
            stem=form.stem.data,
            content=form.content.data,
            image=image_filename,
            author=current_user,
        )
        db.session.add(post)
        db.session.commit()

        flash("Your post has been created!", "success")
        return redirect(url_for("users.forum"))
    return render_template(
        "create_post.html",
        title="Create Post",
        form=form,
        legend="Create Post",
        maths_catalogue=maths_catalogue,
        physical_science_catalogue=physical_science_catalogue,
    )


@users.route("/post/<uuid:post_id>", methods=["GET", "POST"])
@login_required
def post(post_id):
    form = CommentForm()

    # Fetch the post and its comments
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=str(post_id)).all()
    print(f"Comments for post {post_id}: {comments}")
    current_date = datetime.now()
    date_posted = post.date_posted.strftime("%m %d, %Y")

    # Fetch profiles for comments
    comment_profiles = {}
    for comment in comments:
        profile = Profile.query.filter_by(user_id=comment.author.id).first()
        comment_profiles[comment.id] = profile  # `None` if not found

    # Fetch profile for post author
    post_profile = Profile.query.filter_by(user_id=post.author.id).first()

    if form.validate_on_submit():
        comment = Comment(
            body=form.body.data,
            author=current_user,
            user_id=current_user.id,
            post_id=post_id,
        )
        db.session.add(comment)
        db.session.commit()

        # Create a notification for the post author
        notification = Notification(
            recipient_id=post.author.id,
            sender_id=current_user.id,
            post_id=post_id,
            notification_type="comment",
        )
        db.session.add(notification)
        db.session.commit()

        flash("Your comment has been posted.", "success")
        return redirect(url_for("users.post", post_id=post_id))

    return render_template(
        "post.html",
        title=post.topic,
        post=post,
        current_date=current_date,
        format_time_difference=format_time_difference,
        form=form,
        comments=comments,
        comment_profiles=comment_profiles,
        post_profile=post_profile,
        all_comments_count=len(comments),
        date_posted=date_posted,
    )


def get_notification_count(user_id):
    return Notification.query.filter_by(recipient_id=user_id, read=False).count()


@users.route("/increment_view_count/<uuid:post_id>", methods=["POST"])
@login_required
def increment_view_count(post_id):
    post = Post.query.get_or_404(post_id)

    if post is None:
        abort(404, "Post not found")

    if current_user.id != post.user_id:
        # Increment view count
        post.views = post.views + 1 if post.views is not None else 1
        db.session.commit()
        return jsonify({"success": True, "views": post.views}), 200
    else:
        return (
            jsonify(
                {"success": False, "message": "View count not incremented for own post"}
            ),
            400,
        )


@users.route("/post/<uuid:post_id>/update", methods=["POST", "GET"])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)

    form = PostForm()

    if form.validate_on_submit():
        post.topic = form.topic.data
        post.subtopic = form.subtopic.data
        post.stem = form.stem.data
        post.content = form.content.data

        if form.image.data:
            post.image = form.image.data

        try:
            db.session.commit()
            flash("Your post has been updated!", "success")
            return redirect(url_for("users.post", post_id=post.id))
        except Exception as e:
            db.session.rollback()
            flash("Error updating post: " + str(e), "danger")

    elif request.method == "GET":
        form.topic.data = post.topic
        form.subtopic.data = post.subtopic
        form.stem.data = post.stem
        form.content.data = post.content
        form.image.data = (
            post.image
        )  # This may need to be adjusted based on how your image is handled

    return render_template(
        "create_post.html",
        title="Update Post",
        form=form,
        legend="Update Post",
        maths_catalogue=maths_catalogue,
        physical_science_catalogue=physical_science_catalogue,
    )


@users.route("/delete/<uuid:post_id>/update", methods=["POST"])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if not current_user.is_admin and post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash("Your post has been deleted ", "success")
    return redirect(url_for("users.forum"))


@users.route("/delete/<uuid:comment_id>", methods=["POST"])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    post_id = comment.post_id
    if not current_user.is_admin and comment.author != current_user:
        abort(403)
    db.session.delete(comment)
    db.session.commit()
    flash("Your comment has been deleted", "success")
    return redirect(url_for("users.post", post_id=post_id))


@users.route("/update_comment/<uuid:comment_id>/update", methods=["POST", "GET"])
@login_required
def update_comment(comment_id):

    form = CommentForm()

    comment = Comment.query.get_or_404(comment_id)
    current_date = datetime.now()
    comments = Comment.query.filter_by(post_id=comment.post_id).all()
    updated_at = comment.updated_at.strftime("%H:%M:%S")

    if comment.author != current_user:
        abort(403)

    # Retrieve profile information for each comment author
    comment_profiles = {}
    for comment in comments:
        profile = Profile.query.filter_by(user_id=comment.author.id).first_or_404()
        comment_profiles[comment.id] = profile

    if form.validate_on_submit():
        comment.body = form.body.data
        db.session.commit()
        flash("Your comment has been updated.", "success")
        return redirect(url_for("users.post", post_id=comment.post_id))
    elif request.method == "GET":
        form.body.data = comment.body

    return render_template(
        "update_comment.html",
        form=form,
        comment=comment,
        current_date=current_date,
        format_time_difference=format_time_difference,
        comment_profiles=comment_profiles,
        updated_at=updated_at,
    )


@users.route("/like-post/<uuid:post_id>", methods=["POST"])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()

    if not post:
        return jsonify({"error": "Post does not exist."}, 400)

    if like:
        # User has already liked the post, so unlike it
        db.session.delete(like)
        db.session.commit()
        # Delete existing notification if it exists
        notification = Notification.query.filter_by(
            recipient_id=post.author.id,
            sender_id=current_user.id,
            post_id=post_id,
            notification_type="like",
        ).first()
        if notification:
            db.session.delete(notification)
            db.session.commit()
    else:
        # User has not liked the post yet, so like it
        like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        db.session.commit()
        # Create notification for the post author
        notification = Notification(
            recipient_id=post.author.id,
            sender_id=current_user.id,
            post_id=post_id,
            notification_type="like",
        )
        db.session.add(notification)
        db.session.commit()

    return redirect(request.referrer)


@users.route("/user/<string:username>", methods=["GET"])
@login_required
def user_posts(username):
    form = ContactForm()
    current_date = datetime.now()
    profile = Profile.query.filter_by(user_id=current_user.id).first_or_404()
    page = request.args.get("page", 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    author_profile = Profile.query.filter_by(user_id=user.id).first()
    posts = (
        Post.query.filter_by(author=user)
        .order_by(Post.date_posted.desc())
        .paginate(page=page, per_page=5)
    )
    return render_template(
        "user_post.html",
        posts=posts,
        title=username + " Posts",
        user=user,
        current_date=current_date,
        format_time_difference=format_time_difference,
        author_profile=author_profile,
        form=form,
    )


@users.route("/search", methods=["POST"], strict_slashes=False)
@login_required
def search():
    form = ContactForm()
    search_query = request.form.get("searched")

    print("Search query:", search_query)

    # Check if search query is empty
    if not search_query:
        return render_template("search.html", search_results=[])

    # Initialize an empty list to store search results
    search_results = []

    # Search in User model
    user_results = User.query.filter(
        or_(
            User.id.ilike(f"%{search_query}%"),
            User.username.ilike(f"%{search_query}%"),
            User.first_name.ilike(f"%{search_query}%"),
            User.last_name.ilike(f"%{search_query}%"),
            User.email.ilike(f"%{search_query}%"),
            User.role.ilike(f"%{search_query}%"),
        )
    ).all()
    search_results.extend(user_results)

    # Search in Profile model
    profile_results = Profile.query.filter(
        or_(
            Profile.bio.ilike(f"%{search_query}%"),
            Profile.avatar.ilike(f"%{search_query}%"),
        )
    ).all()
    search_results.extend(profile_results)

    # Search in Content model
    content_results = Content.query.filter(
        or_(
            Content.topic.ilike(f"%{search_query}%"),
            Content.subtopic.ilike(f"%{search_query}%"),
            Content.content_type.ilike(f"%{search_query}%"),
            Content.link.ilike(f"%{search_query}%"),
        )
    ).all()
    search_results.extend(content_results)

    # Search in Slots model
    slots_results = Slots.query.filter(
        or_(
            Slots.id.ilike(f"%{search_query}%"),
            Slots.user_id.ilike(f"%{search_query}%"),
            Slots.status.ilike(f"%{search_query}%"),
            Slots.topic.ilike(f"%{search_query}%"),
            Slots.subtopic.ilike(f"%{search_query}%"),
            Slots.date.ilike(f"%{search_query}%"),
            Slots.teams_link.ilike(f"%{search_query}%"),
        )
    ).all()

    # Add 'type' attribute to slots_results
    for slot in slots_results:
        slot.type = "slots"

    search_results.extend(slots_results)

    # Render the template with the search results
    return render_template("search.html", search_results=search_results, form=form)


def preprocess_content_data(content_list):
    content_data = {}
    for content in content_list:
        topic = content.topic
        subtopic = content.subtopic
        if topic not in content_data:
            content_data[topic] = {}
        if subtopic not in content_data[topic]:
            content_data[topic][subtopic] = []
        content_data[topic][subtopic].append(content)
    return content_data


@users.route('/papers', methods=['GET','POST'])
@login_required
def papers():
    form = PapersForm()
    if form.validate_on_submit():
        title = form.title.data
        stem = form.stem.data
        year_written = form.year_written.data
        link = form.link.data
        paper_type = form.paper_type.data
        
        # Determine the link based on stem and paper_type
        if stem == 'maths':
            if paper_type == 'caps':
                maths_caps_link = link
            elif paper_type == 'ieb':
                maths_ieb_link = link
        elif stem == 'science':
            if paper_type == 'caps':
                science_caps_link = link
            elif paper_type == 'ieb':
                science_ieb_link = link
        
        # Save the paper to the database
        paper = Papers(title=title, stem=stem, year_written=year_written, paper_type=paper_type, link=link, user_id=current_user.id)
        db.session.add(paper)
        db.session.commit()
        flash('Paper uploaded successfully.', 'success')
        return redirect(url_for('users.papers'))
    
    return render_template('papers.html', form=form)


@users.route('/view_papers', methods=['GET'])
@login_required
def view_papers():
    form = ContactForm()
    papers = Papers.query.all()
    
    # Define the paper types and stems
    paper_combinations = [
        {'paper_type': 'caps', 'stem': 'maths', 'label': 'Mathematics Exam Papers (CAPS)'},
        {'paper_type': 'ieb', 'stem': 'maths', 'label': 'Mathematics Exam Papers (IEB)'},
        {'paper_type': 'caps', 'stem': 'science', 'label': 'Physical Science Exam Papers (CAPS)'},
        {'paper_type': 'ieb', 'stem': 'science', 'label': 'Physical Science Exam Papers (IEB)'}
    ]
    
    return render_template('view_papers.html', papers=papers, form=form, paper_combinations=paper_combinations)



@users.route('/papers_by_year', methods=['GET'])
@login_required
def papers_by_year():
    form = ContactForm()
    
    # Get parameters from the request
    paper_type = request.args.get('paper_type')
    stem = request.args.get('stem')
    
    # Validate parameters
    if not paper_type or not stem:
        logging.error("Invalid parameters detected.")
        flash("Invalid parameters provided for filtering papers.", "error")
        return redirect(url_for('users.view_papers'))
    
    # Filter papers based on valid parameters
    papers = Papers.query.filter_by(stem=stem, paper_type=paper_type).all()
    return render_template('papers_by_year.html', papers=papers, form=form)



@users.route('/maths_caps_papers', methods=['GET'])
@login_required
def maths_caps_papers():
    papers = Papers.query.filter_by(stem='maths', paper_type='caps').all()
    return render_template('papers_by_year.html', papers=papers)

@users.route('/maths_ieb_papers', methods=['GET'])
@login_required
def maths_ieb_papers():
    papers = Papers.query.filter_by(stem='maths', paper_type='ieb').all()
    return render_template('papers_by_year.html', papers=papers)

@users.route('/science_caps_papers', methods=['GET'])
@login_required
def science_caps_papers():
    papers = Papers.query.filter_by(stem='science', paper_type='caps').all()
    return render_template('papers_by_year.html', papers=papers)

@users.route('/science_ieb_papers', methods=['GET'])
@login_required
def science_ieb_papers():
    papers = Papers.query.filter_by(stem='science', paper_type='ieb').all()
    return render_template('papers_by_year.html', papers=papers)


@users.route("/access_content", methods=["GET"])
@login_required
def access_content():
    form = ContactForm()
    content = Content.query.all()
    content_data = preprocess_content_data(content)
    return render_template("access_content.html", content_data=content_data, form=form)


@users.route("/maths_content", methods=["GET"])
@login_required
def maths_content():
    # Fetch maths content from the database
    form = ContactForm()
    maths_content = Content.query.filter_by(stem="maths").all()

    # Organize the content into a dictionary structure based on content_type and topic
    content_data = {}
    for content in maths_content:
        if (
            content.content_type == "additional_problem"
            or content.content_type == "worksheet"
        ):
            continue  # Skip content related to additional_problem and worksheet
        if content.content_type not in content_data:
            content_data[content.content_type] = {}
        if content.topic not in content_data[content.content_type]:
            content_data[content.content_type][content.topic] = []
        content_data[content.content_type][content.topic].append(content)

    if not content_data:  # If content_data is empty or None
        return render_template("no_content.html")

    return render_template("maths_content.html", content_data=content_data, form=form)


@users.route("/science_content", methods=["GET"])
@login_required
def science_content():
    # Fetch science content from the database
    form = ContactForm()
    science_content = Content.query.filter_by(stem="science").all()

    # Organize the content into a dictionary structure based on content_type and topic
    content_data = {}
    for content in science_content:
        if (
            content.content_type == "additional_problem"
            or content.content_type == "worksheet"
        ):
            continue  # Skip content related to additional_problem and worksheet
        if content.content_type not in content_data:
            content_data[content.content_type] = {}
        if content.topic not in content_data[content.content_type]:
            content_data[content.content_type][content.topic] = []
        content_data[content.content_type][content.topic].append(content)

    if not content_data:  # If content_data is empty or None
        return render_template("no_content.html")

    return render_template("science_content.html", content_data=content_data, form=form)


@users.route("/practice", methods=["GET"])
@login_required
def practice():
    # Fetch practice content from the database
    form = ContactForm()
    practice_content = Content.query.filter(
        (Content.content_type == "worksheet")
        | (Content.content_type == "additional_problem")
    ).all()

    # Organize the content into a dictionary structure based on content_type and topic
    content_data = {}
    for content in practice_content:
        if content.content_type not in content_data:
            content_data[content.content_type] = {}
        if content.topic not in content_data[content.content_type]:
            content_data[content.content_type][content.topic] = []
        content_data[content.content_type][content.topic].append(content)

    if not content_data:  # If content_data is empty or None
        return render_template("no_content.html", form=form)

    return render_template("practice.html", content_data=content_data, form=form)


def save_file_to_server(file):
    """
    Save the uploaded file to the server.
    """
    # Check if the file is provided
    if file:
        # Get the uploads folder path
        uploads_folder = current_app.config["UPLOAD_FOLDER_LOCAL_FILES"]
        # Ensure the uploads folder exists
        os.makedirs(uploads_folder, exist_ok=True)
        # Save the file to the uploads folder
        file_path = os.path.join(uploads_folder, file.filename)
        file.save(file_path)
        return file_path
    else:
        return None


# Define a route to handle the upload_content.html template
@users.route("/upload_content", methods=["GET", "POST"])
@login_required
def upload_content():
    form = UploadContentForm()

    # Populate topic choices based on selected STEM
    if form.stem.data == "maths":
        form.topic.choices = [(chapter, chapter) for chapter in maths_catalogue.keys()]
    elif form.stem.data == "science":
        form.topic.choices = [
            (chapter, chapter) for chapter in physical_science_catalogue.keys()
        ]

    # Populate subtopic choices based on selected topic
    if form.topic.data:
        if form.stem.data == "maths" and form.topic.data in maths_catalogue:
            form.subtopic.choices = [
                (subtopic, subtopic) for subtopic in maths_catalogue[form.topic.data]
            ]
        elif (
            form.stem.data == "science"
            and form.topic.data in physical_science_catalogue
        ):
            form.subtopic.choices = [
                (subtopic, subtopic)
                for subtopic in physical_science_catalogue[form.topic.data]
            ]

    if form.validate_on_submit():
        content_type = form.content_type.data
        link = form.link.data
        file = form.file.data
        stem = form.stem.data
        topic = form.topic.data
        subtopic = form.subtopic.data

        if file:
            # Save file to the server and get the file path
            file_path = save_file_to_server(file)
            # Create Content instance with file path
            new_content = Content(
                content_type=content_type,
                link=file_path,  # Store the file path in the 'link' field
                stem=stem,
                topic=topic,
                subtopic=subtopic,
                user_id=current_user.id,
            )
        elif link:
            # Create Content instance with link
            new_content = Content(
                content_type=content_type,
                link=link,
                stem=stem,
                topic=topic,
                subtopic=subtopic,
                user_id=current_user.id,
            )
        else:
            flash("Please upload a file or provide a link.", "error")
            return redirect(url_for("users.upload_content"))

        # Save the content to the database
        db.session.add(new_content)
        db.session.commit()

        flash("Content uploaded successfully.", "success")
        return redirect(url_for("users.dashboard"))

    return render_template(
        "upload_content.html",
        form=form,
        maths_catalogue=maths_catalogue,
        physical_science_catalogue=physical_science_catalogue,
    )


# Define a route to handle the no_content.html template
@users.route("/no_content", methods=["GET"])
@login_required
def no_content():
    return render_template("no_content.html")


# favicon route
@users.route("/favicon.ico")
def favicon():
    return "", 200


# Define a function to convert YouTube watch URLs to embed URLs
def convert_to_embed_link(link):
    parsed_url = urlparse(link)
    video_id = parse_qs(parsed_url.query).get("v")
    if video_id:
        return f"https://www.youtube.com/embed/{video_id[0]}"
    return None


@users.route("/content_files/<file_name>", methods=["GET"])
def serve_content_file(file_name):
    # Construct the absolute path to the content file
    file_path = os.path.join(current_app.config["UPLOAD_FOLDER_LOCAL_FILES"], file_name)

    # Check if the file exists
    if os.path.exists(file_path):
        # Serve the file using Flask's send_file function
        return send_file(file_path)
    else:
        # If the file does not exist, return a 404 error
        abort(404)


@users.route('/view_content/<uuid:content_id>', methods=["GET"])
@login_required
def view_content(content_id):
    form = ContactForm()
    # Fetch the content data from the database based on the content_id
    content = Content.query.get(str(content_id))
    if content:
        if content.link.startswith('C:\\'):
            # Extract the file name from the path
            file_name = os.path.basename(content.link)
            # Construct the URL for serving the uploaded file
            file_url = url_for('users.serve_uploaded_file', filename=file_name)
            return render_template('view_content.html', content=content, file_url=file_url, form=form)
        else:
            # Convert YouTube link to embed link
            content.embed_link = convert_to_embed_link(content.link)
            # Render the view_content.html template and pass the content data
            return render_template('view_content.html', content=content, form=form)
    else:
        # If content is not found, redirect to a home page
        flash('Content not found', 'error')
        return redirect(url_for('users.home', form=form))


@users.route("/uploads/<path:filename>", methods=["GET"])
@login_required
def serve_uploaded_file(filename):
    uploads = current_app.config["UPLOAD_FOLDER_LOCAL_FILES"]
    return send_from_directory(uploads, filename)


# Define the download_content endpoint
@users.route("/download_content/<content_id>", methods=["GET"])
@login_required
def download_content(content_id):
    form = ContactForm()
    # Retrieve the Content object based on the content_id
    content = Content.query.get_or_404(content_id)

    if content.content_type == "video":
        return redirect(content.link)

    # If the content is uploaded from the local drive, construct the file URL
    if content.link.startswith("C:\\"):
        file_url = url_for(
            "users.serve_uploaded_file", filename=os.path.basename(content.link)
        )
        # Redirect users to the file URL for download
        return redirect(file_url)
    else:
        # For other types of content, download the file from the URL
        response = requests.get(content.link)

        # Check if the request was successful
        if response.status_code == 200:
            # Get the content type from the database
            content_type = content.content_type

            # Guess the file extension based on the content type
            file_extension = mimetypes.guess_extension(content_type)

            # If the file extension is not found, use '.pdf' as the default
            if not file_extension:
                file_extension = ".pdf"

            # Generate a temporary file with the appropriate extension
            temp_file = tempfile.NamedTemporaryFile(suffix=file_extension, delete=False)

            # Write the content of the response to the temporary file
            temp_file.write(response.content)
            temp_file.close()

            # Set the filename for download
            filename = (
                f"{content.topic}{file_extension}"
                if content.topic
                else f"Untitled{file_extension}"
            )

            # Send the temporary file as an attachment for download
            return send_file(temp_file.name, as_attachment=True, download_name=filename)
        else:
            flash("Failed to download content.", "error")
            return redirect(url_for("users.home", form=form))


# Admin dashboard route
@users.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    form = ContactForm()
    # Fetch all content from the database
    page = request.args.get("page", 1, type=int)
    per_page = 5
    all_content = Content.query.order_by(Content.created_at.desc()).paginate(
        page=page, per_page=per_page
    )

    # Get the count of students
    num_students = User.query.filter_by(role="student").count()

    # Get the count of volunteers
    num_volunteers = User.query.filter_by(role="tutor").count()

    # Get count for taken slots
    num_slots_taken = Slots.query.filter_by(status="taken").count()

    # Calculate slot attendance percentage
    num_slots_attendance = (
        round(
            Slots.query.filter(Slots.student_id.isnot(None)).count()
            / Slots.query.count()
            * 100
        )
        if Slots.query.count() > 0
        else 0
    )

    # Get the latest registration date for students
    latest_student_registration = (
        User.query.filter_by(role="student").order_by(User.created_at.desc()).first()
    )
    if latest_student_registration:
        last_student_registration_date = latest_student_registration.created_at
    else:
        last_student_registration_date = None

    # Get the latest registration date for volunteers
    latest_volunteer_registration = (
        User.query.filter_by(role="tutor").order_by(User.created_at.desc()).first()
    )
    if latest_volunteer_registration:
        last_volunteer_registration_date = latest_volunteer_registration.created_at
    else:
        last_volunteer_registration_date = None

    # Calculate the total number of students attending slots
    attended_slots = Slots.query.filter(Slots.student_id.isnot(None)).all()

    # Extract the subtopics of attended slots
    attended_subtopics = [slot.subtopic for slot in attended_slots]

    # Use Counter to count the occurrences of each subtopic
    subtopic_counter = Counter(attended_subtopics)

    # Find the most common subtopic
    most_common_subtopic = subtopic_counter.most_common(1)
    if most_common_subtopic:
        most_popular_attended_subtopic = most_common_subtopic[0][0]
    else:
        most_popular_attended_subtopic = "No attended slots yet"

    # Query the database to retrieve all slots
    all_slots = Slots.query.all()

    # Count the total number of slots
    total_slots = len(all_slots)

    # Count the number of slots that have been taken
    taken_slots = len([slot for slot in all_slots if slot.status == "taken"])

    # Calculate the average
    if total_slots > 0:
        average_taken_slots = round(taken_slots / total_slots)
    else:
        average_taken_slots = 0

    return render_template(
        "dashboard.html",
        num_students=num_students,
        num_volunteers=num_volunteers,
        last_student_registration_date=last_student_registration_date,
        last_volunteer_registration_date=last_volunteer_registration_date,
        num_slots_taken=num_slots_taken,
        num_slots_attendance=num_slots_attendance,
        all_content=all_content,
        average_taken_slots=average_taken_slots,
        most_popular_attended_subtopic=most_popular_attended_subtopic,
        form=form,
    )


# Route to edit content
@users.route("/edit_content/<content_id>", methods=["GET"])
@login_required
def edit_content(content_id):
    form = ContactForm()
    # Fetch the content by ID
    content = Content.query.get_or_404(content_id)

    return render_template("edit_content.html", content=content, form=form)


@users.route("/edit_content", methods=["POST"])
@login_required
def update_content():
    # Fetch the content by ID
    content_id = request.form.get("content_id")
    content = Content.query.get_or_404(content_id)

    # Update the content data
    content.topic = request.form.get("topic")
    content.subtopic = request.form.get("subtopic")
    content.content_type = request.form.get("content_type")
    content.link = request.form.get("link")
    content.stem = request.form.get("stem")

    # Save the updated content
    db.session.commit()

    flash("Content updated successfully.", "success")
    return redirect(url_for("users.dashboard"))


# Route to delete content
@users.route("/delete_content/<content_id>", methods=["GET", "POST"])
@login_required
def delete_content(content_id):

    # Fetch the content by ID
    content = Content.query.get_or_404(content_id)

    # Delete the content
    db.session.delete(content)
    db.session.commit()

    flash("Content deleted successfully.", "success")
    return redirect(url_for("users.dashboard"))


# Route to create a teaching slot
@users.route("/create_slot", methods=["GET", "POST"])
@login_required
def create_slot():
    form = CreateSlotForm()

    # Populate topic choices based on selected STEM
    if form.stem.data == "maths":
        form.topic.choices = [(chapter, chapter) for chapter in maths_catalogue.keys()]
    elif form.stem.data == "science":
        form.topic.choices = [
            (chapter, chapter) for chapter in physical_science_catalogue.keys()
        ]

    # Populate subtopic choices based on selected topic
    if form.topic.data:
        if form.stem.data == "maths" and form.topic.data in maths_catalogue:
            form.subtopic.choices = [
                (subtopic, subtopic) for subtopic in maths_catalogue[form.topic.data]
            ]
        elif (
            form.stem.data == "science"
            and form.topic.data in physical_science_catalogue
        ):
            form.subtopic.choices = [
                (subtopic, subtopic)
                for subtopic in physical_science_catalogue[form.topic.data]
            ]

    if form.validate_on_submit():
        stem = form.stem.data
        topic = form.topic.data
        subtopic = form.subtopic.data
        date = form.date.data
        start_time = form.start_time.data
        end_time = form.end_time.data
        teams_link = form.teams_link.data

        # Get the current user's ID
        user_id = current_user.id

        # Create a new Slots object
        new_slot = Slots(
            topic=topic,
            subtopic=subtopic,
            date=date,
            start_time=start_time,
            end_time=end_time,
            teams_link=teams_link,
            stem=stem,
            user_id=user_id,
        )

        db.session.add(new_slot)
        db.session.commit()

        # Retrieve all volunteer users
        volunteers = User.query.filter_by(role="tutor").all()
        # Send email notification to volunteers
        for volunteer in volunteers:
            send_notification_email(
                [volunteer],
                "New Teaching Slot Created",
                f"Hi {volunteer.username},\n\nA new teaching slot has been created.\n\nTopic: {topic}\nSubtopic: {subtopic}\nDate: {date}\nStart Time: {start_time}\nEnd Time: {end_time}\nTeams Link: {teams_link}",
            )

        # Retrieve all student users
        students = User.query.filter_by(role="student").all()
        # Send email notification to students
        for student in students:
            send_notification_email(
                [student],
                "New Teaching Slot Created",
                f"Hi {student.username},\n\nA new teaching slot has been created.\n\nTopic: {topic}\nSubtopic: {subtopic}\nDate: {date}\nStart Time: {start_time}\nEnd Time: {end_time}\nTeams Link: {teams_link}",
            )

        flash(
            "Teaching slot created successfully. Email notifications sent to volunteers and students.",
            "success",
        )
        return redirect(url_for("users.dashboard"))

    return render_template(
        "create_slot.html",
        form=form,
        maths_catalogue=maths_catalogue,
        physical_science_catalogue=physical_science_catalogue,
    )


@users.route("/delete_slot/<slot_id>", methods=["POST"], strict_slashes=False)
@login_required
def delete_slot(slot_id):
    slot = Slots.query.get_or_404(slot_id)
    if not slot:
        flash("Teaching slot not found.", "error")
    else:
        db.session.delete(slot)
        db.session.commit()
        flash("Teaching slot deleted successfully.", "success")
    return redirect(url_for("users.dashboard"))


@users.route("/edit_slot/<slot_id>", methods=["GET"], strict_slashes=False)
@login_required
def edit_slot(slot_id):
    form = ContactForm()
    # Fetch the slot by ID
    slot = Slots.query.get_or_404(slot_id)
    return render_template("edit_slot.html", slot=slot, form=form)


@users.route("/edit_slot", methods=["POST"], strict_slashes=False)
@login_required
def update_slot():
    form = ContactForm()
    # Fetch the slot by ID
    slot_id = request.form.get("slot_id")
    slot = Slots.query.get_or_404(slot_id)

    # Update the slot data
    if request.method == "POST":
        slot.topic = request.form.get("topic")
        slot.subtopic = request.form.get("subtopic")
        slot.stem = request.form.get("stem")
        teams_link = request.form.get("teams_link")

        # Extract time component from datetime strings and convert to time objects
        slot.date = datetime.strptime(request.form.get("date"), "%Y-%m-%d").date()
        slot.start_time = datetime.strptime(
            request.form.get("start_time"), "%H:%M:%S"
        ).time()
        slot.end_time = datetime.strptime(
            request.form.get("end_time"), "%H:%M:%S"
        ).time()

    # Save the updated slot
    db.session.commit()

    flash("Teaching slot updated successfully.", "success")
    return redirect(url_for("users.dashboard", form=form))


@users.route("/live_classes", methods=["GET"], strict_slashes=False)
@login_required
def live_classes():
    form = ContactForm()
    # Retrieve all slots
    slots = Slots.query.all()
    return render_template("live_classes.html", slots=slots, form=form)


@users.route("/attend_event/<slot_id>", methods=["GET"], strict_slashes=False)
@login_required
def attend_event(slot_id):

    slot = Slots.query.get(slot_id)
    if not slot:
        flash("Attending slot not found.", "error")
        return redirect(url_for("users.dashboard"))

    # Check if the current user is a volunteer
    if current_user.role != "student":
        flash("You are not authorized to take attending slots.", "error")
        return redirect(url_for("users.live_classes"))

    # Get the profile of the current user
    profile = Profile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        flash("Profile not found.", "error")
        return redirect(url_for("users.live_classes"))

    # Check if the slot is already taken by the user
    if slot.student_id == profile.id:
        flash("You have already taken this attending slot.", "warning")
        return redirect(url_for("users.profile"))

    # Assign the slot to the current volunteer profile
    slot.student_id = profile.id
    db.session.commit()

    flash("Attending slot taken successfully.", "success")
    return redirect(url_for("users.profile"))


@users.route("/take_slot/<slot_id>", methods=["GET"], strict_slashes=False)
@login_required
def take_slot(slot_id):
    form = ContactForm
    slot = Slots.query.get(slot_id)
    if not slot:
        flash("Teaching slot not found.", "error")
        return redirect(url_for("users.dashboard", form=form))

    # Check if the current user is a volunteer
    if current_user.role != "tutor":
        flash("You are not authorized to take teaching slots.", "error")
        return redirect(url_for("users.live_classes", form=form))

    # Get the profile of the current user
    profile = Profile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        flash("Profile not found.", "error")
        return redirect(url_for("users.live_classes", form=form))

    # Check if the slot is already taken
    if slot.status == "taken":
        flash("This teaching slot has already been taken.", "warning")
        return redirect(url_for("users.profile", form=form))

    # Assign the slot to the current volunteer profile
    slot.volunteer_id = profile.id
    slot.status = "taken"
    db.session.commit()

    flash("Teaching slot taken successfully.", "success")
    return redirect(url_for("users.profile", form=form))
