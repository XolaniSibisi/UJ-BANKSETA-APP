from flask import url_for
from markupsafe import Markup
from flask_login.mixins import UserMixin
from werkzeug.security import (
        check_password_hash,
        generate_password_hash
    )

from users import UPLOAD_FOLDER
from users.extensions import database as db
from users.utils import (
        get_unique_filename,
        remove_existing_file,
        unique_security_token,
        unique_uid,
        send_mail
    )

from datetime import datetime, timedelta
import os

class User(db.Model, UserMixin):
    """
    A Base User model class.
    """

    __tablename__ = 'user'

    id = db.Column(db.String(38), primary_key=True, default=unique_uid, unique=True, nullable=False)
    username = db.Column(db.String(30), unique=True, nullable=False)
    first_name = db.Column(db.String(25), nullable=False)
    last_name = db.Column(db.String(25), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    active = db.Column(db.Boolean, default=False, nullable=False)
    security_token = db.Column(db.String(138), default=unique_security_token)
    is_send = db.Column(db.DateTime, default=datetime.now)
    change_email = db.Column(db.String(120), default="")

    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    profile = db.Relationship('Profile', backref='user', cascade='save-update, merge, delete')
    
    def is_admin(self):
        return self.role == 'admin'

    def is_student(self):
        return self.role == 'student'

    def is_volunteer(self):
        return self.role == 'volunteer'


    def send_confirmation(self):
        """
        A method for sending an email for account confirmation.
        """
        self.security_token = unique_security_token()
        self.is_send = datetime.now()
        db.session.commit()
        subject = "Verify Your Account."
        verification_link = f"http://127.0.0.1:5000{url_for('users.confirm_account', token=self.security_token)}"
        content = f"""
        Hi, {self.username}
        Your Registration is completed. 

        Please click the following link to confirm your account.
        
        {verification_link}
        
        """
        return send_mail(subject, self.email, content)

    @classmethod
    def get_user_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def get_user_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def save_profile(self):
        profile = Profile(user_id=self.id)
        profile.save()

    def save(self):
        db.session.add(self)
        db.session.commit()
        self.save_profile()
    
    def is_active(self):
        return self.active
    
    def is_token_expire(self):
        expiry_time = (
            self.is_send
            + timedelta(minutes=15)
        )
        current_time = datetime.now()
        return expiry_time <= current_time
        
    def __repr__(self):
        return '<User> {}'.format(self.email)


class Profile(db.Model):
    """
    A User profile model class.
    """

    __tablename__ = 'profile'

    id = db.Column(db.String(38), primary_key=True, default=unique_uid, unique=True, nullable=False)
    bio = db.Column(db.String(200), default='')
    avatar = db.Column(db.String(250), default='')
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Define a relationship to the Slots model for attending slots
    attending_slots = db.relationship('Slots', backref='student_profile', lazy=True, foreign_keys='Slots.student_id')
    
    # Define a relationship to the Slots model for teaching slots
    teaching_slots = db.relationship('Slots', backref='volunteer_profile', lazy=True, foreign_keys='Slots.volunteer_id')

    user_id = db.Column(db.String(38), db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)

    def __repr__(self):
        return '<Profile> {}'.format(self.user.username)

    def set_avator(self, profile_image):
        if self.avator:
            path = os.path.join(UPLOAD_FOLDER, self.avator)
            remove_existing_file(path=path)
            
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(os.path.join(UPLOAD_FOLDER), exist_ok=True)
            
        self.avator = get_unique_filename(profile_image.filename)
        profile_image.save(os.path.join(UPLOAD_FOLDER, self.avator))

    def save(self):
        db.session.add(self)
        db.session.commit()
        
class Contact(db.Model):
    """
    A Contact model class.
    """

    __tablename__ = 'contact'

    id = db.Column(db.String(38), primary_key=True, default=unique_uid, unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f"Contact(id={self.id}, name={self.name}, email={self.email}), subject={self.subject}), message={self.message})"

    def save(self):
        db.session.add(self)
        db.session.commit()

    def get_absolute_url(self):
        return url_for('users.contact', contact_id=self.id)

    def get_delete_url(self):
        return url_for('users.delete_contact', contact_id=self.id)

    def get_user(self):
        return User.query.filter_by(email=self.email).first()
        
class Content(db.Model):
    """
    A Content model class.
    """

    __tablename__ = 'content'

    id = db.Column(db.String(38), primary_key=True, default=unique_uid, unique=True, nullable=False)
    topic = db.Column(db.String(200), nullable=False)
    subtopic = db.Column(db.String(200), nullable=False)
    content_type = db.Column(db.String(20), nullable=False)
    link = db.Column(db.String(250), nullable=False)
    stem = db.Column(db.String(250))
    published = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    user_id = db.Column(db.String(38), db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)

    def __repr__(self):
        return f"Content(id={self.id}, topic={self.topic}, subtopic={self.subtopic}, content_type={self.content_type}, link={self.link}, stem={self.stem})"

    def save(self):
        db.session.add(self)
        db.session.commit()
        
    def delete(self):
        db.session.delete(self)
        db.session.commit()
        
    def get_absolute_url(self):
        return url_for('users.content', content_id=self.id)
    
    def get_edit_url(self):
        return url_for('users.edit_content', content_id=self.id)
    
    def get_delete_url(self):
        return url_for('users.delete_content', content_id=self.id)
    
    def get_publish_url(self):
        return url_for('users.publish_content', content_id=self.id)
    
    def get_unpublish_url(self):
        return url_for('users.unpublish_content', content_id=self.id)
    
    def get_user(self):
        return User.query.filter_by(id=self.user_id).first()
    
    def get_published(self):
        return Content.query.filter_by(published=True).all()
    
    def get_unpublished(self):
        return Content.query.filter_by(published=False).all()
    
    def get_published_by_user(self, user_id):
        return Content.query.filter_by(published=True, user_id=user_id).all()
    
    def get_unpublished_by_user(self, user_id):
        return Content.query.filter_by(published=False, user_id=user_id).all()
    
    def get_published_by_username(self, username):
        user = User.query.filter_by(username=username).first()
        return Content.query.filter_by(published=True, user_id=user.id).all()
    
    def get_unpublished_by_username(self, username):
        user = User.query.filter_by(username=username).first()
        return Content.query.filter_by(published=False, user_id=user.id).all()
    
class Counter(db.Model):
    """
    A Counter model class.
    """

    __tablename__ = 'counter'

    id = db.Column(db.String(38), primary_key=True)
    name = db.Column(db.String(200), unique=True)
    count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def __repr__(self):
        return f"Counter(id={self.id}, name={self.name}, count={self.count})"

    def save(self):
        db.session.add(self)
        db.session.commit()
        
    def increment(self):
        self.count += 1
        db.session.commit()
        
    def decrement(self):
        self.count -= 1
        db.session.commit()
        
    def get_absolute_url(self):
        return url_for('users.counter', counter_id=self.id)
    
    def get_edit_url(self):
        return url_for('users.edit_counter', counter_id=self.id)
    
    def get_delete_url(self):
        return url_for('users.delete_counter', counter_id=self.id)
    
class Slots(db.Model):
    """
    A Slots model class.
    """

    __tablename__ = 'slots'

    id = db.Column(db.String(38), primary_key=True, default=unique_uid, unique=True, nullable=False)
    topic = db.Column(db.String(200), nullable=False)
    subtopic = db.Column(db.String(200), nullable=False)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    stem = db.Column(db.String(250))
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    # Define a foreign key for the student who attends the slot
    student_id = db.Column(db.String(38), db.ForeignKey('profile.id', ondelete="CASCADE"), nullable=True)

    # Define a foreign key for the volunteer who teaches the slot
    volunteer_id = db.Column(db.String(38), db.ForeignKey('profile.id', ondelete="CASCADE"), nullable=True)
    
    user_id = db.Column(db.String(38), db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)

    def __repr__(self):
        return f"Slots(id={self.id}, topic={self.topic}, subtopic={self.subtopic}, date={self.date}, start_time={self.start_time}, end_time={self.end_time}, stem={self.stem})"

    def save(self):
        db.session.add(self)
        db.session.commit()
        
    def delete(self):
        db.session.delete(self)
        db.session.commit()
        
    def get_absolute_url(self):
        return url_for('users.slots', slots_id=self.id)
    
    def get_edit_url(self):
        return url_for('users.edit_slots', slots_id=self.id)
    
    def get_delete_url(self):
        return url_for('users.delete_slots', slots_id=self.id)
    
    def get_user(self):
        return User.query.filter_by(id=self.user_id).first()
    
    def get_user_slots(self, user_id):
        return Slots.query.filter_by(user_id=user_id).all()
    
    def get_user_slots_by_username(self, username):
        user = User.query.filter_by(username=username).first()
        return Slots.query.filter_by(user_id=user.id).all()

