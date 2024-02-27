from flask import abort, render_template, request, redirect, url_for, flash
from flask import Blueprint
from flask_login import (
        current_user,
        login_required,
        login_user,
        logout_user
    )

from users.extensions import database as db
from users.models import User, Profile
from users.forms import (
        RegisterForm, 
        LoginForm, 
        ForgotPasswordForm,
        ResetPasswordForm,
        ChangePasswordForm,
        ChangeEmailForm,
        ContactForm,
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
import os
import sqlite3


"""
This accounts blueprint defines routes and templates related to user management
within our application.
"""
users = Blueprint('users', __name__, template_folder='templates')

@users.route('/register', methods=['GET', 'POST'], strict_slashes=False)
def register():
    form = RegisterForm()

    if current_user.is_authenticated:
        return redirect(url_for('users.index'))

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
            flash("A confirmation link sent to your email. Please verify your account.", 'info')
            return redirect(url_for('users.login'))
        except Exception as e:
            flash("Something went wrong", 'error')
            print("Exception occurred during user registration:")
            traceback.print_exc()  # Print the traceback for debugging
            return redirect(url_for('users.register'))

    return render_template('register.html', form=form)


@users.route('/login', methods=['GET', 'POST'], strict_slashes=False)
def login():
    form = LoginForm()

    if current_user.is_authenticated:
        return redirect(url_for('users.index'))

    if form.validate_on_submit():
        username = form.data.get('username')
        password = form.data.get('password')

        user = User.get_user_by_username(username) or User.get_user_by_email(username)

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
                login_user(auth_user, remember=True, duration=timedelta(days=15))
                flash(f"Welcome {auth_user.username}, You're registered successfully.", 'success')
                return redirect(url_for('users.index'))
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
                flash("A reset password link sent to your email. Please check.", 'success')
                return redirect(url_for('users.login'))
            except Exception as e:
                flash("Something went wrong", 'error')
                return redirect(url_for('accounts.forgot_password'))

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
        
        if current_user.username == 'test_user':
            flash("Test user limited to read-only access.", 'error')
        elif not user.check_password(old_password):
            flash("Your old password is incorrect.", 'error')
        elif not (new_password == confirm_password):
            flash("Your new password field's not match.", 'error')
        elif not re.match(r"(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$", new_password):
            flash("Please choose strong password. It contains at least one alphabet, number, and one special character.", 'warning')
        else:
            user.set_password(new_password)
            db.session.commit()
            flash("Your password changed successfully.", 'success')
            return redirect(url_for('users.index'))

        return redirect(url_for('users.change_password'))
    return render_template('change_password.html', form=form)


@users.route('/change/email', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def change_email():
    form = ChangeEmailForm()

    if form.validate_on_submit():
        email = form.data.get('email')

        user = User.query.get_or_404(current_user.id)

        if current_user.username == 'test_user':
            flash("Guest user limited to read-only access.", 'error')
        elif email == user.email:
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
                flash("A reset email link sent to your new email address. Please verify.", 'success')
                return redirect(url_for('users.index'))
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
                return redirect(url_for('accounts.index'))
            except Exception as e:
                flash("Something went wrong", 'error')
                return redirect(url_for('users.index'))

        return render_template('confirm_email.html', token=token)

    return abort(404)


@users.route('/', strict_slashes=False)
@users.route('/home', strict_slashes=False)
def index():
    return render_template('index.html', profile=profile)

@users.route('/maths_content', strict_slashes=False)
@login_required
def maths_content():
    return render_template('maths_content.html')

@users.route('/science_content', strict_slashes=False)
@login_required
def science_content():
    return render_template('science_content.html')


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
    if request.method == 'POST':
        if form.validate() == False:
            flash('All fields are required.')
            return render_template('contact.html', form=form)
        else:
            sender_email = current_user.email if current_user.is_authenticated else form.email.data
            msg = Message(form.subject.data, sender=sender_email, recipients=[os.environ.get('MAIL_USERNAME')])
            msg.body = f"""
            From: {form.name.data} <{sender_email}>
            {form.message.data}
            """
            mail.send(msg)
            flash('Thank you for contacting us, we will get back to you soon.', 'success')
            return redirect(url_for('users.contact'))
    elif request.method == 'GET':
        return render_template('contact.html', form=form)
    
@users.route('/ediit_profile', methods=['GET', 'POST'], strict_slashes=False)
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
