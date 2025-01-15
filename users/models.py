from email.policy import default
import os
from signal import raise_signal
import typing as t
from datetime import datetime, timedelta

from sqlalchemy import Index
from sqlalchemy import event, or_
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Mapper
from sqlalchemy.ext.declarative import DeclarativeMeta

from werkzeug.exceptions import InternalServerError, HTTPException
from werkzeug.security import check_password_hash, generate_password_hash


from flask import url_for
from flask_login.mixins import UserMixin

from users.extensions import database as db
from users.utils import (
    get_unique_filename,
    remove_existing_file,
    unique_security_token,
    get_unique_id,
)


class BaseModel(db.Model):
    """
    A Base Model class for other models.
    """

    __abstract__ = True

    id = db.Column(
        db.String(38),
        primary_key=True,
        default=get_unique_id,
        nullable=False,
        unique=True,
    )

    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def save(self):
        db.session.add(self)
        db.session.commit()


class User(BaseModel, UserMixin):
    """
    A Base User model class.
    """

    __tablename__ = "user"

    username = db.Column(db.String(30), unique=True, nullable=False)
    first_name = db.Column(db.String(25), nullable=False)
    last_name = db.Column(db.String(25), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    active = db.Column(db.Boolean, default=False, nullable=False, server_default="0")
    change_email = db.Column(db.String(120), default="")
    posts = db.relationship("Post", backref="author", lazy=True)
    comments = db.relationship("Comment", backref="author", lazy=True)
    likes = db.relationship("Like", backref="author", lazy=True)

    def is_admin(self):
        return self.role == "admin"

    def is_student(self):
        return self.role == "student"

    def is_tutor(self):
        return self.role == "tutor"

    @classmethod
    def authenticate(
        cls, username: t.AnyStr = None, password: t.AnyStr = None
    ) -> t.Optional["User"]:
        """
        Authenticate a user by username and password.
        Args:
            username (str): A username string.
            password (str): A password string.
        Returns:
            User: A User object if the username and password match, otherwise None.
        """
        user = cls.query.filter(
            or_(
                cls.username == username,
                cls.email == username,
            )
        ).first()

        if user and user.check_password(password):
            return user

        return None

    @classmethod
    def create(cls, **kwargs):
        """
        Create a new user instance, set the password,
        and save it to the database.

        :return: The newly created user instance.
        :raises InternalServerError: If there is an error while creating or saving the user.
        """
        password = kwargs.get("password")

        try:
            # Instantiate the user object
            user = cls(**kwargs)

            # Hash the password
            user.set_password(password)

            # Save to the database
            user.save()

            return user
        except Exception as e:
            db.session.rollback()
            # Log the exception for debugging
            print(f"Error while creating user: {e}")

            raise InternalServerError(description=f"Failed to create user: {str(e)}")

    @classmethod
    def get_user_by_id(cls, user_id: t.AnyStr, raise_exception: bool = False):
        """
        Retrieves a user instance from the database
        based on their User ID.

        :param user_id: The user ID to search for.
        """
        if raise_exception:
            return cls.query.get_or_404(user_id)

        return cls.query.get(user_id)

    @classmethod
    def get_user_by_username(cls, username: t.AnyStr):
        """
        Retrieves a user instance from the database
        based on their username.
        :param username: The username to search for.
        """
        return cls.query.filter_by(username=username).first()

    @classmethod
    def get_user_by_email(cls, email: t.AnyStr):
        """
        Retrieves a user instance from the database
        based on their email address.
        :param email: The email address to search for.
        """
        return cls.query.filter_by(email=email).first()

    def set_password(self, password: t.AnyStr):
        """
        Set the password for the user.
        :param password: The password to set.
        """
        self.password = generate_password_hash(password)

    def check_password(self, password: t.AnyStr) -> bool:
        """
        Check if the provided password matches the hashed password.
        :param paasword: The plain-text password to check.
        """
        return check_password_hash(self.password, password)

    def generate_token(self, salt: str) -> t.AnyStr:
        """
        Generates a new security token for the user.

        :return: The newly created security token.
        """
        instance = UserSecurityToken.create_new(salt=salt, user_id=self.id)
        return instance.token

    @staticmethod
    def verify_token(
        token: t.AnyStr, salt: str, raise_exception: bool = True
    ) -> t.Union[t.Optional["UserSecurityToken"], HTTPException, None]:
        """
        Verify the provided security token.
        :param token: The security token to verify.
        :param salt: The salt used to generate the token.
        :param raise_signal: Whether to raise an exception if the token is invalid.
        """
        instance = UserSecurityToken.query.filter_by(token=token, salt=salt)

        if raise_exception:  # type: ignore
            token = instance.first_or_404()

        else:
            token = instance.first()

        if token and not token.is_expired:
            return token

        return None

    def send_confirmation(self):
        """
        Send a confirmation email to the user.
        """
        from users.email_utils import send_confirmation_mail

        send_confirmation_mail(self)

    @property
    def profile(self):
        """
        Retrieves the user's profile instance from the database.

        :return: The user's profile object, or None if it does not exist.
        """
        profile = Profile.query.filter_by(user_id=self.id).first()
        return profile

    @property
    def is_active(self) -> bool:
        """
        Checks if the user's account is active.

        :return: `True` if the user account is active, otherwise `False`.
        """
        return self.active

    def __repr__(self):
        return format(self.username)


class Profile(BaseModel):
    """
    A User profile model class.
    """

    __tablename__ = "user_profile"

    bio = db.Column(db.String(200), default="")
    avatar = db.Column(db.String(250), default="")

    user_id = db.Column(
        db.String(38), db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )

    user = db.relationship("User", foreign_keys=[user_id])

    # Define a relationship to the Slots model for attending slots
    attending_slots = db.relationship(
        "Slots", backref="student_profile", lazy=True, foreign_keys="Slots.student_id"
    )

    # Define a relationship to the Slots model for teaching slots
    teaching_slots = db.relationship(
        "Slots",
        backref="volunteer_profile",
        lazy=True,
        foreign_keys="Slots.volunteer_id",
    )

    def set_avator(self, profile_image):
        """
        Set a new avatar for the user by removing the existing avatar (if any), saving the new one,
        and updating the user's avatar field in the database.

        :param profile_image: The uploaded image file to be set as the new avatar.

        :raises InternalServerError: If there is an error during the file-saving process.
        """
        from config import UPLOAD_FOLDER

        if self.avatar:
            path = os.path.join(UPLOAD_FOLDER, self.avatar)
            remove_existing_file(path=path)

        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(os.path.join(UPLOAD_FOLDER), exist_ok=True)

        self.avatar = get_unique_filename(profile_image.filename)

        try:
            # Save the new avatar file to the file storage.
            profile_image.save(os.path.join(UPLOAD_FOLDER, self.avatar))
        except Exception as e:
            # Handle exceptions that might occur during file saving.
            print("Error saving avatar: %s" % e)
            raise InternalServerError

    def __repr__(self):
        return "<Profile '{}'>".format(self.user.username)


class UserSecurityToken(BaseModel):
    """
    A token class for storing security token for url.
    """

    __tablename__ = "user_token"

    __table_args__ = (
        Index("ix_user_token_token", "token"),
        Index("ix_user_token_expire", "expire"),
    )

    token = db.Column(
        db.String(72), default=unique_security_token, nullable=False, unique=True
    )

    salt = db.Column(db.String(20), nullable=False)

    expire = db.Column(db.Boolean, default=False, nullable=False, server_default="0")

    user_id = db.Column(
        db.String(38), db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )

    user = db.relationship("User", foreign_keys=[user_id])

    @classmethod
    def create_new(cls, **kwargs) -> t.AnyStr:
        """
        Creates a new security token instance for a user
        and saves it to the database.

        :param user_id: The ID of the user for whom the token is being created.
        :return: The generated security token string.

        :raises InternalServerError: If there is an error saving the token to the database.
        """
        try:
            instance = cls(**kwargs)
            instance.save()
        except Exception as e:
            raise InternalServerError

        return instance

    @property
    def is_expired(self) -> bool:
        """
        Checks if the token has expired based
        on its creation time and expiration period.
        """
        if not self.expire:
            expiry_time = self.created_at + timedelta(minutes=15)
            current_time = datetime.now()

            if not expiry_time <= current_time:
                return False

        self.delete()
        return True

    @classmethod
    def is_exists(cls, token: t.AnyStr = None):
        """
        Check if a token already exists in the database.

        :param token: The token to check for existence.

        :return: The first instance found with the specified token,
        or None if not found.
        """
        return cls.query.filter_by(token=token).first()

    def __repr__(self):
        return "<Token '{}' by {}>".format(self.token, self.user)


@event.listens_for(User, "after_insert")
def create_profile_for_user(
    mapper: Mapper, connection: Connection, target: DeclarativeMeta
):
    # Create a Profile instance for the recently created user.
    profile = Profile(user_id=target.id)

    # Execute an INSERT statement to add the user's profile table to the database.
    connection.execute(Profile.__table__.insert(), {"user_id": profile.user_id})


class Contact(BaseModel):
    """
    A Contact model class.
    """

    __tablename__ = "contact"

    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f"Contact(id={self.id}, name={self.name}, email={self.email}), subject={self.subject}), message={self.message})"

    def get_absolute_url(self):
        return url_for("users.contact", contact_id=self.id)

    def get_delete_url(self):
        return url_for("users.delete_contact", contact_id=self.id)

    def get_user(self):
        return User.query.filter_by(email=self.email).first()


class Content(BaseModel):
    """
    A Content model class.
    """

    __tablename__ = "content"

    topic = db.Column(db.String(200), nullable=False)
    subtopic = db.Column(db.String(200), nullable=False)
    content_type = db.Column(db.String(20), nullable=False)
    link = db.Column(db.String(250), nullable=True)
    stem = db.Column(db.String(250))
    published = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    user_id = db.Column(
        db.String(38), db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )

    def __repr__(self):
        return f"Content(topic={self.topic}, subtopic={self.subtopic}, content_type={self.content_type}, link={self.link}, stem={self.stem})"


class Slots(BaseModel):
    """
    A Slots model class.
    """

    __tablename__ = "slots"

    topic = db.Column(db.String(200), nullable=False)
    subtopic = db.Column(db.String(200), nullable=False)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    teams_link = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default="available")  # Add status field
    stem = db.Column(db.String(250))
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    # Define a foreign key for the student who attends the slot
    student_id = db.Column(
        db.String(38),
        db.ForeignKey("user_profile.id", ondelete="CASCADE"),
        nullable=True,
    )

    # Define a foreign key for the volunteer who teaches the slot
    volunteer_id = db.Column(
        db.String(38),
        db.ForeignKey("user_profile.id", ondelete="CASCADE"),
        nullable=True,
    )

    user_id = db.Column(
        db.String(38), db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )

    def __repr__(self):
        return f"Slots(topic={self.topic}, subtopic={self.subtopic}, date={self.date}, start_time={self.start_time}, end_time={self.end_time}, teams_link={self.teams_link} stem={self.stem})"

    def get_user_slots(self, user_id):
        return Slots.query.filter(
            (Slots.student_id == user_id) | (Slots.volunteer_id == user_id)
        ).all()

    def get_user_slots_by_username(self, username):
        user = User.query.filter_by(username=username).first()
        if user:
            return self.get_user_slots(user.id)
        return []


class Post(BaseModel):
    """
    A Post model class.
    """

    __tablename__ = "post"

    topic = db.Column(db.String(200), nullable=False)
    subtopic = db.Column(db.String(200), nullable=False)
    stem = db.Column(db.String(250))
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now())
    content = db.Column(db.Text, nullable=False)
    views = db.Column(db.Integer, default=0)
    image = db.Column(db.String(250), default="")
    user_id = db.Column(
        db.String(38), db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )
    comments = db.relationship(
        "Comment", backref="post", passive_deletes=True, lazy=True
    )
    likes = db.relationship("Like", backref="post", passive_deletes=True, lazy=True)

    def __repr__(self):
        return f"Post('{self.title}', '{self.content}', '{self.date_posted}')"


class Comment(BaseModel):
    """
    A Comment model class.
    """

    __tablename__ = "comment"

    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now())
    updated_at = db.Column(db.DateTime, default=datetime.now(), onupdate=datetime.now())
    body = db.Column(db.Text, nullable=False)
    user_id = db.Column(
        db.String(38), db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )
    post_id = db.Column(
        db.String(38), db.ForeignKey("post.id", ondelete="CASCADE"), nullable=False
    )

    def __repr__(self):
        return f"Comment('{self.body}', '{self.date_posted}', '{self.post_id}')"


class Like(BaseModel):
    """
    A Like model class.
    """

    __tablename__ = "like"

    user_id = db.Column(
        db.String(38), db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )
    post_id = db.Column(
        db.String(38), db.ForeignKey("post.id", ondelete="CASCADE"), nullable=False
    )

    def __repr__(self):
        return f"Like('{self.user_id}', '{self.post_id}')"


class Notification(BaseModel):
    """
    A Notification model class.
    """

    __tablename__ = "notification"

    recipient_id = db.Column(
        db.String(38), db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )
    sender_id = db.Column(
        db.String(38), db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )
    post_id = db.Column(
        db.String(38), db.ForeignKey("post.id", ondelete="CASCADE"), nullable=False
    )
    notification_type = db.Column(db.String(20), nullable=False)  # 'like' or 'comment'
    read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    recipient = db.relationship("User", foreign_keys=[recipient_id])
    sender = db.relationship("User", foreign_keys=[sender_id])
    post = db.relationship("Post")


class Papers(BaseModel):
    """
    A Papers model class.
    """

    __tablename__ = "papers"

    title = db.Column(db.String(200), nullable=False)
    link = db.Column(db.String(250), nullable=False)
    stem = db.Column(db.String(250))
    paper_type = db.Column(db.String(50), nullable=False)
    year_written = db.Column(db.String(50), nullable=False)

    user_id = db.Column(
        db.String(38), db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )

    def __repr__(self):
        return f"Papers(title={self.title}, paper_type={self.paper_type}, link={self.link}, stem={self.stem}, year_written={self.year_written})"