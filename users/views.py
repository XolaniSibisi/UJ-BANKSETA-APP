from flask import abort, render_template, request, redirect, url_for, flash, jsonify
from flask_wtf.csrf import generate_csrf
from flask import Blueprint, send_file
import logging
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user
)

from users.extensions import database as db, csrf
from users.models import User, Profile, Content, Contact, Counter
from users.forms import (
    RegisterForm,
    LoginForm,
    ForgotPasswordForm,
    ResetPasswordForm,
    ChangePasswordForm,
    ChangeEmailForm,
    ContactForm,
    UploadContentForm,
    EditUserProfileForm
)
from users.utils import (
    unique_security_token,
    get_unique_filename,
    send_reset_password,
    send_reset_email
)

from flask_mail import Message
from users.extensions import mail
from datetime import datetime, timedelta
import re
import mimetypes
import requests
import tempfile
import os
from flask_cors import CORS, cross_origin
from urllib.parse import urlparse, parse_qs


"""
This accounts blueprint defines routes and templates related to user management
within our application.
"""
users = Blueprint('users', __name__, template_folder='templates')

CORS(users)

@users.route('/register', methods=['GET', 'POST'], strict_slashes=False)
def register():
    form = RegisterForm()

    if current_user.is_authenticated:
        return redirect(url_for('users.home'))

    if form.validate_on_submit():
        username = form.data.get('username')
        first_name = form.data.get('first_name')
        last_name = form.data.get('last_name')
        email = form.data.get('email')
        role = form.data.get('role')
        password = form.data.get('password')

        try:
            user = User(
                username=username,
                first_name=first_name,
                last_name=last_name,
                email=email,
                role=role,
                password=password
            )
            user.set_password(password)

            if role == 'admin':
                user.is_superuser = True  # Assign superuser privileges
            user.save()
            user.send_confirmation()
            flash(
                "A confirmation link sent to your email. Please verify your account.", 'info')
            return redirect(url_for('users.login'))
            
            # Increment the appropriate counter
            if role == 'student':
                Counter.query.filter_by(name='num_students').update({'count': Counter.count + 1})
            elif role == 'volunteer':
                Counter.query.filter_by(name='num_volunteers').update({'count': Counter.count + 1})
            
            db.session.commit()
        except Exception as e:
            flash("Something went wrong", 'error')
            print("Exception occurred during user registration:")
            return redirect(url_for('users.register'))

    return render_template('register.html', form=form)


@users.route('/login', methods=['GET', 'POST'], strict_slashes=False)
def login():
    form = LoginForm()

    if current_user.is_authenticated:
        return redirect(url_for('users.home'))

    if form.validate_on_submit():
        username = form.data.get('username')
        password = form.data.get('password')

        user = User.get_user_by_username(
            username) or User.get_user_by_email(username)

        if not user:
            flash("User account doesn't exists.", 'error')
        elif not user.check_password(password):
            flash("Your password is incorrect. Please try again.", 'error')
        else:
            if not user.is_active():
                user.send_confirmation()
                flash("Your account is not active. We've sent you a confirmation email. Please check your email to activate your account.", 'error')
                return redirect(url_for('users.login'))

            login_user(user, remember=True, duration=timedelta(days=15))
            # flash("You are logged in successfully.", 'success')
            return redirect(url_for('users.profile'))

        return redirect(url_for('users.login'))

    return render_template('login.html', form=form)


@users.route('/account/confirm?token=<string:token>', methods=['GET', 'POST'], strict_slashes=False)
def confirm_account(token=None):
    auth_user = User.query.filter_by(security_token=token).first_or_404()

    if auth_user and not auth_user.is_token_expire():
        if request.method == "POST":
            try:
                auth_user.active = True
                auth_user.security_token = None
                db.session.commit()
                login_user(auth_user, remember=True,
                           duration=timedelta(days=15))
                flash(
                    f"Welcome {auth_user.username}, You're registered successfully.", 'success')
                return redirect(url_for('users.home'))
            except Exception as e:
                flash("Something went wrong.", 'error')
                return redirect(url_for('users.login'))

        return render_template('confirm_account.html', token=token)

    return abort(404)


@users.route('/logout', strict_slashes=False)
@login_required
def logout():
    logout_user()
    flash("You're logout successfully.", 'success')
    return redirect(url_for('users.login'))


@users.route('/forgot/password', methods=['GET', 'POST'], strict_slashes=False)
def forgot_password():
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.data.get('email')
        user = User.get_user_by_email(email=email)

        if user:
            try:
                user.security_token = unique_security_token()
                user.is_send = datetime.now()
                db.session.commit()
                send_reset_password(user)
                flash(
                    "A reset password link sent to your email. Please check.", 'success')
                return redirect(url_for('users.login'))
            except Exception as e:
                flash("Something went wrong", 'error')
                return redirect(url_for('users.forgot_password'))

        flash("Email address is not registered with us.", 'error')
        return redirect(url_for('users.forgot_password'))

    return render_template('forget_password.html', form=form)


@users.route('/password/reset/token?<string:token>', methods=['GET', 'POST'], strict_slashes=False)
def reset_password(token=None):
    user = User.query.filter_by(security_token=token).first_or_404()

    if user and not user.is_token_expire():
        form = ResetPasswordForm()

        if form.validate_on_submit():
            password = form.data.get('password')
            confirm_password = form.data.get('confirm_password')

            if not (password == confirm_password):
                flash("Your new password field's not match.", 'error')
            elif not re.match(r"(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$", password):
                flash("Please choose strong password. It contains at least one alphabet, number, and one special character.", 'warning')
            else:
                user.set_password(password)
                user.security_token = None
                db.session.commit()
                flash("Your password is changed successfully. Please login.", 'success')
                return redirect(url_for('users.login'))

            return redirect(url_for('users.reset_password', token=token))

        return render_template('reset_password.html', form=form, token=token)

    return abort(404)


@users.route('/change/password', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        old_password = form.data.get('old_password')
        new_password = form.data.get('new_password')
        confirm_password = form.data.get('confirm_password')

        user = User.query.get_or_404(current_user.id)

        if not user.check_password(old_password):
            flash("Your old password is incorrect.", 'error')
        elif not (new_password == confirm_password):
            flash("Your new password field's not match.", 'error')
        elif not re.match(r"(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$", new_password):
            flash("Please choose strong password. It contains at least one alphabet, number, and one special character.", 'warning')
        else:
            user.set_password(new_password)
            db.session.commit()
            flash("Your password changed successfully.", 'success')
            return redirect(url_for('users.home'))

        return redirect(url_for('users.change_password'))
    return render_template('change_password.html', form=form)


@users.route('/change/email', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def change_email():
    form = ChangeEmailForm()

    if form.validate_on_submit():
        email = form.data.get('email')

        user = User.query.get_or_404(current_user.id)

        if email == user.email:
            flash("Email is already verified with your account.", 'warning')
        elif email in [u.email for u in User.query.all() if email != user.email]:
            flash("Email address is already registered with us.", 'warning')
        else:
            try:
                user.change_email = email
                user.security_token = unique_security_token()
                user.is_send = datetime.now()
                db.session.commit()
                send_reset_email(user=user)
                flash(
                    "A reset email link sent to your new email address. Please verify.", 'success')
                return redirect(url_for('users.home'))
            except Exception as e:
                flash("Something went wrong.", 'error')
                return redirect(url_for('users.change_email'))

        return redirect(url_for('users.change_email'))

    return render_template('change_email.html', form=form)


@users.route('/account/email/confirm?token=<string:token>', methods=['GET', 'POST'], strict_slashes=False)
def confirm_email(token=None):
    user = User.query.filter_by(security_token=token).first_or_404()

    if user and not user.is_token_expire():
        if request.method == "POST":
            try:
                user.email = user.change_email
                user.change_email = None
                user.security_token = None
                db.session.commit()
                flash(f"Your email address updated successfully.", 'success')
                return redirect(url_for('users.home'))
            except Exception as e:
                flash("Something went wrong", 'error')
                return redirect(url_for('users.home'))

        return render_template('confirm_email.html', token=token)

    return abort(404)


@users.route('/', strict_slashes=False)
@users.route('/home', strict_slashes=False)
def home():
    return render_template('home.html', profile=profile)


@users.route('/profile', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def profile():
    form = EditUserProfileForm()

    user = User.query.get_or_404(current_user.id)
    profile = Profile.query.filter_by(user_id=user.id).first_or_404()

    if form.validate_on_submit():
        username = form.data.get('username')
        first_name = form.data.get('first_name')
        last_name = form.data.get('last_name')
        profile_image = form.data.get('profile_image')
        about = form.data.get('about')

        if username in [user.username for user in User.query.all() if username != current_user.username]:
            flash("Username already exists. Choose another.", 'error')
        else:
            user.username = username
            user.first_name = first_name
            user.last_name = last_name
            profile.bio = about

            if profile_image and getattr(profile_image, "filename"):
                profile.set_avator(profile_image)

            db.session.commit()
            flash("Your profile update successfully.", 'success')
            return redirect(url_for('users.profile'))

        return redirect(url_for('users.edit_profile'))

    return render_template('profile.html', form=form, profile=profile)


@users.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        entry = Contact(
            name=form.name.data,
            email=form.email.data,
            subject=form.subject.data,
            message=form.message.data
        )
        
        entry.save()
        
        
        send_email(form.name.data, form.email.data, form.subject.data, form.message.data)
        
        
        return redirect(url_for('users.contact_success'))
    
    return render_template('contact.html', form=form)

@users.route('/contact/success')
def contact_success():
    return render_template('contact_success.html')

def send_email(name, email, subject, message):
    msg = Message(subject=f"New message from {name} via contact form",
                  sender=current_user.email if current_user.is_authenticated else form.email.data,
                  recipients=[os.environ.get('MAIL_USERNAME')])
    msg.body = f"Name: {name}\nEmail: {email}\nSubject: {subject}\nMessage: {message}"
    
    try:
        mail.send(msg)  
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
        

# route to edit profile
@users.route('/edit_profile', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def edit_profile():
    form = EditUserProfileForm()

    user = User.query.get_or_404(current_user.id)
    profile = Profile.query.filter_by(user_id=user.id).first_or_404()

    if form.validate_on_submit():
        username = form.data.get('username')
        first_name = form.data.get('first_name')
        last_name = form.data.get('last_name')
        profile_image = form.data.get('profile_image')
        about = form.data.get('about')

        if username in [user.username for user in User.query.all() if username != current_user.username]:
            flash("Username already exists. Choose another.", 'error')
        else:
            user.username = username
            user.first_name = first_name
            user.last_name = last_name
            profile.bio = about

            if profile_image and getattr(profile_image, "filename"):
                profile.set_avator(profile_image)

            db.session.commit()
            flash("Your profile update successfully.", 'success')
            return redirect(url_for('users.profile'))

        return redirect(url_for('users.edit_profile'))

    return render_template('edit_profile.html', form=form, profile=profile)


@users.route('/forum', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def forum():
    return render_template('forum.html')


@users.route('/live_classes', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def live_classes():
    return render_template('live_classes.html')


@users.route('/related_links', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def related_links():
    return render_template('related_links.html')


@users.route('/search', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def search():
    return render_template('search.html')


@users.route('/maths_content', methods=['GET'])
@login_required
def maths_content():
    # Fetch maths content from the database
    maths_content = Content.query.filter_by(stem='maths').all()

    # Organize the content into a dictionary structure based on content_type
    content_data = {}
    for content in maths_content:
        content_data.setdefault(content.content_type, []).append(content)

    if not content_data:  # If content_data is empty or None
        return render_template('no_content.html')

    return render_template('maths_content.html', content_data=content_data)


@users.route('/science_content', methods=['GET'])
@login_required
def science_content():
    # Fetch science content from the database
    science_content = Content.query.filter_by(stem='science').all()

    # Organize the content into a dictionary structure based on content_type
    content_data = {}
    for content in science_content:
        content_data.setdefault(content.content_type, []).append(content)

    if not content_data:  # If content_data is empty or None
        return render_template('no_content.html')

    return render_template('science_content.html', content_data=content_data)


# Define a route to handle the upload_content.html template
@users.route('/upload_content', methods=['POST', 'GET'])
@login_required
def upload_content():
    form = UploadContentForm()
    if form.validate_on_submit():
        title = form.title.data
        content_type = form.content_type.data
        link = form.link.data
        stem = form.stem.data

        # Get the current user's ID
        user_id = current_user.id

        # Create a new Content object
        new_content = Content(
            title=title,
            content_type=content_type,
            link=link,
            stem=stem,
            user_id=user_id
        )

        db.session.add(new_content)
        db.session.commit()

        flash('Content uploaded successfully', 'success')
        return redirect(url_for('users.dashboard'))

    return render_template('upload_content.html', form=form)

# Define a route to handle the no_content.html template
@users.route('/no_content', methods=['GET'])
@login_required
def no_content():
    return render_template('no_content.html')

# favicon route
@users.route("/favicon.ico")
def favicon():
    return "", 200

# Define a function to convert YouTube watch URLs to embed URLs
def convert_to_embed_link(link):
    parsed_url = urlparse(link)
    video_id = parse_qs(parsed_url.query).get('v')
    if video_id:
        return f"https://www.youtube.com/embed/{video_id[0]}"
    return None

# Define the view_content endpoint
@users.route('/view_content/<content_id>')
@login_required
def view_content(content_id):
    # Fetch the content data from the database based on the content_id
    content = Content.query.get(content_id)
    if content:
        # Convert YouTube link to embed link
        content.embed_link = convert_to_embed_link(content.link)
        # Render the view_content.html template and pass the content data
        return render_template('view_content.html', content=content)
    else:
        # If content is not found, redirect to a home page
        flash('Content not found', 'error')
        return redirect(url_for('users.home'))
    
@users.route('/increment_view/<content_id>')
@login_required
def increment_view(content_id):
    # Fetch the content data from the database based on the content_id
    content = Content.query.get(content_id)
    if content:
        # Increment the total_views counter
        total_views_counter = Counter.query.filter_by(name='total_views').first()
        if total_views_counter:
            total_views_counter.count += 1
            db.session.commit()
        
        # Redirect back to the view_content page
        return redirect(url_for('users.view_content', content_id=content_id))
    else:
        # If content is not found, redirect to a home page
        flash('Content not found', 'error')
        return redirect(url_for('users.home'))

# Define the download_content endpoint
@users.route('/download_content/<content_id>', methods=['GET'])
@login_required
def download_content(content_id):
    # Retrieve the Content object based on the content_id
    content = Content.query.get_or_404(content_id)

    # If the content type is a video (e.g., YouTube link)
    if content.content_type == 'video':
        # Redirect users to the YouTube video page
        return redirect(content.link)
    else:
        # For other types of content, download the file
        # Retrieve the file from the URL
        response = requests.get(content.link)

        # Check if the request was successful
        if response.status_code == 200:
            # Get the content type from the database
            content_type = content.content_type

            file_extension = mimetypes.guess_extension(content_type)

            if not file_extension:
                file_extension = ".pdf"

            temp_file = tempfile.NamedTemporaryFile(
                suffix=file_extension, delete=False)
            temp_file.write(response.content)
            temp_file.close()

            title = content.title if content.title else "Untitled"
            filename = title + file_extension

            return send_file(temp_file.name, as_attachment=True, download_name=filename)
        
        else:
            
            flash('Failed to download content.', 'error')
            return redirect(url_for('users.home'))

@users.route('/increment_download/<content_id>')
@login_required
def increment_download(content_id):
    # Fetch the content data from the database based on the content_id
    content = Content.query.get(content_id)
    if content:
        # Increment the total_downloads counter
        total_downloads_counter = Counter.query.filter_by(name='total_downloads').first()
        if total_downloads_counter:
            total_downloads_counter.count += 1
            db.session.commit()
        
        # Redirect back to the view_content page
        return redirect(url_for('users.download_content', content_id=content_id))
    else:
        # If content is not found, redirect to a home page
        flash('Content not found', 'error')
        return redirect(url_for('users.home'))


# Admin dashboard route
@users.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    # Fetch all content from the database
    all_content = Content.query.all()
    
    # Fetch counter values from the database
    num_students_counter = Counter.query.filter_by(name='num_students').first()
    num_students = num_students_counter.count if num_students_counter else 0

    num_volunteers_counter = Counter.query.filter_by(name='num_volunteers').first()
    num_volunteers = num_volunteers_counter.count if num_volunteers_counter else 0

    total_downloads_counter = Counter.query.filter_by(name='total_downloads').first()
    total_downloads = total_downloads_counter.count if total_downloads_counter else 0

    total_views_counter = Counter.query.filter_by(name='total_views').first()
    total_views = total_views_counter.count if total_views_counter else 0
    return render_template('dashboard.html', all_content=all_content, num_students=num_students, num_volunteers=num_volunteers, total_downloads=total_downloads, total_views=total_views)

# Route to edit content
@users.route('/edit_content/<content_id>', methods=['GET'])
@login_required
def edit_content(content_id):
    # Fetch the content by ID
    content = Content.query.get_or_404(content_id)

    return render_template('edit_content.html', content=content)

@users.route('/edit_content', methods=['POST'])
@login_required
def update_content():
    # Fetch the content by ID
    content_id = request.form.get('content_id')
    content = Content.query.get_or_404(content_id)

    # Update the content data
    content.title = request.form.get('title')
    content.content_type = request.form.get('content_type')
    content.link = request.form.get('link')
    content.stem = request.form.get('stem')

    # Save the updated content
    db.session.commit()

    flash('Content updated successfully.', 'success')
    return redirect(url_for('users.dashboard'))

# Route to delete content
@users.route('/delete_content/<content_id>', methods=['GET','POST'])
@login_required
def delete_content(content_id):
    
    # Fetch the content by ID
    content = Content.query.get_or_404(content_id)

    # Delete the content
    db.session.delete(content)
    db.session.commit()

    flash('Content deleted successfully.', 'success')
    return redirect(url_for('users.dashboard'))

