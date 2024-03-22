from flask import abort, render_template, request, redirect, url_for, flash, jsonify
from flask_wtf.csrf import generate_csrf
from flask import Blueprint, send_file
from sqlalchemy.orm import joinedload
from werkzeug.utils import secure_filename
from flask import send_from_directory
from flask import current_app
from collections import Counter
import logging
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user
)

from users.extensions import database as db, csrf
from users.models import User, Profile, Content, Contact, Slots
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
    CreateSlotForm
)
from users.utils import (
    unique_security_token,
    get_unique_filename,
    send_reset_password,
    send_reset_email,
    send_notification_email
)

from flask_mail import Message
from users.extensions import mail
from datetime import datetime, timedelta, time
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
        
        # Save uploaded files
        id_copy_filename = None
        certificates_filename = None
        if form.id_copy.data:
            id_copy_filename = secure_filename(form.id_copy.data.filename)
            form.id_copy.data.save(os.path.join(current_app.config['UPLOAD_FOLDER'], id_copy_filename))
        if form.certificates.data:
            certificates_filename = secure_filename(form.certificates.data.filename)
            form.certificates.data.save(os.path.join(current_app.config['UPLOAD_FOLDER'], certificates_filename))

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
            user.save()
            user.send_confirmation()
            
            # Send documents via email
            if role == 'volunteer':
                send_documents_email(user.id, id_copy_filename, certificates_filename)
                
            flash("A confirmation link sent to your email. Please verify your account.", 'info')
            return redirect(url_for('users.login'))
            
        except Exception as e:
            flash("Something went wrong", 'error')
            return redirect(url_for('users.register'))

    return render_template('register.html', form=form)

def send_documents_email(user_id, id_copy_filename, certificates_filename):
    try:
        # Get the user information
        user = User.query.get(user_id)
        if user:
            # Create the email message
            msg = Message('Documents Attached', sender=user.email, recipients=[os.environ.get('MAIL_USERNAME', None)])
            msg.body = f'User {user.username} has registered as a volunteer.'
            
            # Attach the documents
            if id_copy_filename:
                with current_app.open_resource(os.path.join(current_app.config['UPLOAD_FOLDER'], id_copy_filename)) as id_copy_file:
                    msg.attach(id_copy_filename, 'application/pdf', id_copy_file.read())
            if certificates_filename:
                with current_app.open_resource(os.path.join(current_app.config['UPLOAD_FOLDER'], certificates_filename)) as certificates_file:
                    msg.attach(certificates_filename, 'application/pdf', certificates_file.read())
            
            # Send the email
            mail.send(msg)
            print('Documents email sent successfully.')  # Debugging statement
        else:
            print('User not found.')  # Debugging statement
    except Exception as e:
        print(f'Error sending documents email: {str(e)}')  # Debugging statement


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
            flash("You are logged in successfully.", 'success')

            # Redirect admin users to the dashboard
            if user.role == 'admin':
                return redirect(url_for('users.dashboard'))
            else:
                return redirect(url_for('users.profile'))

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

    # Fetch the taken teaching slots if the user is a volunteer
    taken_teaching_slots = []
    if current_user.role == 'volunteer':
        taken_teaching_slots = Slots.query.filter_by(volunteer_id=profile.id).all()

    # Fetch the taken attending slots if the user is a student
    taken_attending_slots = []
    if current_user.role == 'student':
        taken_attending_slots = Slots.query.filter_by(student_id=profile.id).all()

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

    return render_template('profile.html', form=form, profile=profile, taken_teaching_slots=taken_teaching_slots, taken_attending_slots=taken_attending_slots)


@users.route('/admin/profile', methods=['GET'])
@login_required
def admin_profile():
    if current_user.role != 'admin':
        abort(403)  # Forbidden: Only admins can access this page
    
    # Fetch profiles for both students and volunteers
    students = User.query.filter_by(role='student').all()
    volunteers = User.query.filter_by(role='volunteer').all()

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

    return render_template('admin_profile.html', students=students, volunteers=volunteers,
                           student_profiles=student_profiles, volunteer_profiles=volunteer_profiles)


@users.route('/view_user/<user_id>', methods=['GET'])
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    profile = Profile.query.filter_by(user_id=user_id).first_or_404()

    # Fetch the slots associated with the user's profile
    taken_teaching_slots = []
    taken_attending_slots = []

    if user.role == 'volunteer':
        taken_teaching_slots = profile.teaching_slots
    elif user.role == 'student':
        taken_attending_slots = profile.attending_slots

    return render_template('view_user.html', user=user, profile=profile,
                           taken_teaching_slots=taken_teaching_slots,
                           taken_attending_slots=taken_attending_slots)



@users.route('/delete_user/<user_id>', methods=['POST'], strict_slashes=False)
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if not user:
        flash("User not found.", 'error')
    else:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully.", 'success')
    return redirect(url_for('users.admin_profile'))

@users.route('/contact', methods=['GET', 'POST'])
@login_required
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
@login_required
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


@users.route('/related_links', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def related_links():
    return render_template('related_links.html')


@users.route('/search', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def search():
    return render_template('search.html')

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

@users.route('/maths_content', methods=['GET'])
@login_required
def maths_content():
    # Fetch maths content from the database
    maths_content = Content.query.filter_by(stem='maths').all()

    # Organize the content into a dictionary structure based on content_type and topic
    content_data = {}
    for content in maths_content:
        if content.content_type not in content_data:
            content_data[content.content_type] = {}
        if content.topic not in content_data[content.content_type]:
            content_data[content.content_type][content.topic] = []
        content_data[content.content_type][content.topic].append(content)

    if not content_data:  # If content_data is empty or None
        return render_template('no_content.html')

    return render_template('maths_content.html', content_data=content_data)


@users.route('/science_content', methods=['GET'])
@login_required
def science_content():
    # Fetch science content from the database
    science_content = Content.query.filter_by(stem='science').all()

    # Organize the content into a dictionary structure based on content_type and topic
    content_data = {}
    for content in science_content:
        if content.content_type not in content_data:
            content_data[content.content_type] = {}
        if content.topic not in content_data[content.content_type]:
            content_data[content.content_type][content.topic] = []
        content_data[content.content_type][content.topic].append(content)

    if not content_data:  # If content_data is empty or None
        return render_template('no_content.html')

    return render_template('science_content.html', content_data=content_data)

def save_file_to_server(file):
    """
    Save the uploaded file to the server.
    """
    # Check if the file is provided
    if file:
        # Get the uploads folder path
        uploads_folder = current_app.config['UPLOAD_FOLDER']
        # Ensure the uploads folder exists
        os.makedirs(uploads_folder, exist_ok=True)
        # Save the file to the uploads folder
        file_path = os.path.join(uploads_folder, file.filename)
        file.save(file_path)
        return file_path
    else:
        return None

# Define a route to handle the upload_content.html template
@users.route('/upload_content', methods=['GET', 'POST'])
@login_required
def upload_content():
    form = UploadContentForm()

    # Populate topic choices based on selected STEM
    if form.stem.data == 'maths':
        form.topic.choices = [(chapter, chapter) for chapter in maths_catalogue.keys()]
    elif form.stem.data == 'science':
        form.topic.choices = [(chapter, chapter) for chapter in physical_science_catalogue.keys()]

    # Populate subtopic choices based on selected topic
    if form.topic.data:
        if form.stem.data == 'maths' and form.topic.data in maths_catalogue:
            form.subtopic.choices = [(subtopic, subtopic) for subtopic in maths_catalogue[form.topic.data]]
        elif form.stem.data == 'science' and form.topic.data in physical_science_catalogue:
            form.subtopic.choices = [(subtopic, subtopic) for subtopic in physical_science_catalogue[form.topic.data]]

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
                user_id=current_user.id
            )
        elif link:
            # Create Content instance with link
            new_content = Content(
                content_type=content_type,
                link=link,
                stem=stem,
                topic=topic,
                subtopic=subtopic,
                user_id=current_user.id
            )
        else:
            flash('Please upload a file or provide a link.', 'error')
            return redirect(url_for('users.upload_content'))

        # Save the content to the database
        db.session.add(new_content)
        db.session.commit()

        flash('Content uploaded successfully.', 'success')
        return redirect(url_for('users.dashboard'))

    return render_template('upload_content.html', form=form, maths_catalogue=maths_catalogue, physical_science_catalogue=physical_science_catalogue)

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

@users.route('/content_files/<file_name>', methods=['GET'])
def serve_content_file(file_name):
    # Construct the absolute path to the content file
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_name)

    # Check if the file exists
    if os.path.exists(file_path):
        # Serve the file using Flask's send_file function
        return send_file(file_path)
    else:
        # If the file does not exist, return a 404 error
        abort(404)

# Define the view_content endpoint
@users.route('/view_content/<content_id>')
@login_required
def view_content(content_id):
    # Fetch the content data from the database based on the content_id
    content = Content.query.get(content_id)
    if content:
        if content.link.startswith('C:\\'):
            # Extract the file name from the path
            file_name = os.path.basename(content.link)
            # Construct the URL for serving the uploaded file
            file_url = url_for('users.serve_uploaded_file', filename=file_name)
            return render_template('view_content.html', content=content, file_url=file_url)
        else:
            # Convert YouTube link to embed link
            content.embed_link = convert_to_embed_link(content.link)
            # Render the view_content.html template and pass the content data
            return render_template('view_content.html', content=content)
    else:
        # If content is not found, redirect to a home page
        flash('Content not found', 'error')
        return redirect(url_for('users.home'))

@users.route('/uploads/<path:filename>', methods=['GET'])
@login_required
def serve_uploaded_file(filename):
    uploads = current_app.config['UPLOAD_FOLDER']
    return send_from_directory(uploads, filename)   

# Define the download_content endpoint
@users.route('/download_content/<content_id>', methods=['GET'])
@login_required
def download_content(content_id):
    # Retrieve the Content object based on the content_id
    content = Content.query.get_or_404(content_id)
    
    if content.content_type == 'video':
        return redirect(content.link)

    # If the content is uploaded from the local drive, construct the file URL
    if content.link.startswith('C:\\'):
        file_url = url_for('users.serve_uploaded_file', filename=os.path.basename(content.link))
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
            filename = f'{content.topic}{file_extension}' if content.topic else f'Untitled{file_extension}'

            # Send the temporary file as an attachment for download
            return send_file(temp_file.name, as_attachment=True, download_name=filename)
        else:
            flash('Failed to download content.', 'error')
            return redirect(url_for('users.home'))


# Admin dashboard route
@users.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    # Fetch all content from the database
    all_content = Content.query.all()
    
    # Get the count of students
    num_students = User.query.filter_by(role='student').count()

    # Get the count of volunteers
    num_volunteers = User.query.filter_by(role='volunteer').count()
    
    # Get count for taken slots
    num_slots_taken = Slots.query.filter_by(status='taken').count()

    # Calculate slot attendance percentage
    num_slots_attendance = Slots.query.filter(Slots.student_id.isnot(None)).count()/Slots.query.count()*100 if Slots.query.count() > 0 else 0

    # Get the latest registration date for students
    latest_student_registration = User.query.filter_by(role='student').order_by(User.created_at.desc()).first()
    if latest_student_registration:
        last_student_registration_date = latest_student_registration.created_at
    else:
        last_student_registration_date = None

    # Get the latest registration date for volunteers
    latest_volunteer_registration = User.query.filter_by(role='volunteer').order_by(User.created_at.desc()).first()
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
    taken_slots = len([slot for slot in all_slots if slot.status == 'taken'])

    # Calculate the average
    if total_slots > 0:
        average_taken_slots = taken_slots / total_slots
    else:
        average_taken_slots = 0
        
    
    return render_template('dashboard.html', num_students=num_students, num_volunteers=num_volunteers,
                           last_student_registration_date=last_student_registration_date,
                           last_volunteer_registration_date=last_volunteer_registration_date, num_slots_taken=num_slots_taken, 
                           num_slots_attendance=num_slots_attendance, all_content=all_content, average_taken_slots=average_taken_slots, most_popular_attended_subtopic=most_popular_attended_subtopic)

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
    content.topic = request.form.get('topic')
    content.subtopic = request.form.get('subtopic')
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

# Route to create a teaching slot
@users.route('/create_slot', methods=['GET', 'POST'])
@login_required
def create_slot():
    form = CreateSlotForm()

    # Populate topic choices based on selected STEM
    if form.stem.data == 'maths':
        form.topic.choices = [(chapter, chapter) for chapter in maths_catalogue.keys()]
    elif form.stem.data == 'science':
        form.topic.choices = [(chapter, chapter) for chapter in physical_science_catalogue.keys()]

    # Populate subtopic choices based on selected topic
    if form.topic.data:
        if form.stem.data == 'maths' and form.topic.data in maths_catalogue:
            form.subtopic.choices = [(subtopic, subtopic) for subtopic in maths_catalogue[form.topic.data]]
        elif form.stem.data == 'science' and form.topic.data in physical_science_catalogue:
            form.subtopic.choices = [(subtopic, subtopic) for subtopic in physical_science_catalogue[form.topic.data]]

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
            user_id=user_id
        )

        db.session.add(new_slot)
        db.session.commit()

       # Retrieve all volunteer users
        volunteers = User.query.filter_by(role='volunteer').all()
        # Send email notification to volunteers
        for volunteer in volunteers:
            send_notification_email([volunteer], 'New Teaching Slot Created', 
                         f'Hi {volunteer.username},\n\nA new teaching slot has been created.\n\nTopic: {topic}\nSubtopic: {subtopic}\nDate: {date}\nStart Time: {start_time}\nEnd Time: {end_time}\nTeams Link: {teams_link}')
        
        # Retrieve all student users
        students = User.query.filter_by(role='student').all()
        # Send email notification to students
        for student in students:
            send_notification_email([student], 'New Teaching Slot Created',
                         f'Hi {student.username},\n\nA new teaching slot has been created.\n\nTopic: {topic}\nSubtopic: {subtopic}\nDate: {date}\nStart Time: {start_time}\nEnd Time: {end_time}\nTeams Link: {teams_link}')

        flash('Teaching slot created successfully. Email notifications sent to volunteers and students.', 'success')
        return redirect(url_for('users.dashboard'))

    return render_template('create_slot.html', form=form, maths_catalogue=maths_catalogue, physical_science_catalogue=physical_science_catalogue, )

@users.route('/delete_slot/<slot_id>', methods=['POST'], strict_slashes=False)
@login_required
def delete_slot(slot_id):
    slot = Slots.query.get_or_404(slot_id)
    if not slot:
        flash('Teaching slot not found.', 'error')
    else:
        db.session.delete(slot)
        db.session.commit()
        flash('Teaching slot deleted successfully.', 'success')
    return redirect(url_for('users.dashboard'))

@users.route('/edit_slot/<slot_id>', methods=['GET'], strict_slashes=False)
@login_required
def edit_slot(slot_id):
    # Fetch the slot by ID
    slot = Slots.query.get_or_404(slot_id)

    return render_template('edit_slot.html', slot=slot)

@users.route('/edit_slot', methods=['POST'], strict_slashes=False)
@login_required
def update_slot():
    # Fetch the slot by ID
    slot_id = request.form.get('slot_id')
    slot = Slots.query.get_or_404(slot_id)

    # Update the slot data
    if request.method == 'POST':
        slot.topic = request.form.get('topic')
        slot.subtopic = request.form.get('subtopic')
        slot.stem = request.form.get('stem')
        teams_link = request.form.get('teams_link')

        # Extract time component from datetime strings and convert to time objects
        slot.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        slot.start_time = datetime.strptime(request.form.get('start_time'), '%H:%M:%S').time()
        slot.end_time = datetime.strptime(request.form.get('end_time'), '%H:%M:%S').time()

    # Save the updated slot
    db.session.commit()

    flash('Teaching slot updated successfully.', 'success')
    return redirect(url_for('users.dashboard'))


@users.route('/live_classes', methods=['GET'], strict_slashes=False)
@login_required
def live_classes():
    # Retrieve all slots
    slots = Slots.query.all()
    return render_template('live_classes.html', slots=slots)

@users.route('/attend_event/<slot_id>', methods=['GET'], strict_slashes=False)
@login_required
def attend_event(slot_id):
    
    slot = Slots.query.get(slot_id)
    if not slot:
        flash('Attending slot not found.', 'error')
        return redirect(url_for('users.dashboard'))

    # Check if the current user is a volunteer
    if current_user.role != 'student':
        flash('You are not authorized to take attending slots.', 'error')
        return redirect(url_for('users.live_classes'))

    # Get the profile of the current user
    profile = Profile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        flash('Profile not found.', 'error')
        return redirect(url_for('users.live_classes'))
    
    # Check if the slot is already taken by the user
    if slot.student_id == profile.id:
        flash('You have already taken this attending slot.', 'warning')
        return redirect(url_for('users.profile'))

    # Assign the slot to the current volunteer profile
    slot.student_id = profile.id
    db.session.commit()

    flash('Attending slot taken successfully.', 'success')
    return redirect(url_for('users.profile'))


@users.route('/take_slot/<slot_id>', methods=['GET'], strict_slashes=False)
@login_required
def take_slot(slot_id):
    slot = Slots.query.get(slot_id)
    if not slot:
        flash('Teaching slot not found.', 'error')
        return redirect(url_for('users.dashboard'))

    # Check if the current user is a volunteer
    if current_user.role != 'volunteer':
        flash('You are not authorized to take teaching slots.', 'error')
        return redirect(url_for('users.live_classes'))

    # Get the profile of the current user
    profile = Profile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        flash('Profile not found.', 'error')
        return redirect(url_for('users.live_classes'))
    
    # Check if the slot is already taken
    if slot.status == 'taken':
        flash('This teaching slot has already been taken.', 'warning')
        return redirect(url_for('users.profile'))

    # Assign the slot to the current volunteer profile
    slot.volunteer_id = profile.id
    slot.status = 'taken'
    db.session.commit()

    flash('Teaching slot taken successfully.', 'success')
    return redirect(url_for('users.profile'))

