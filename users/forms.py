from flask_wtf.form import FlaskForm
from flask_wtf.file import FileAllowed, FileSize
from flask_wtf.recaptcha import RecaptchaField
from flask_datepicker import datepicker
from wtforms.validators import URL
from wtforms.fields import (
    StringField,
    PasswordField,
    EmailField,
    BooleanField,
    SubmitField,
    FileField,
    TextAreaField,
    SelectField,
    DateField,
    TimeField,
    FileField
)
from wtforms.validators import (
    DataRequired,
    InputRequired,
    Length,
    Email
)
from users.validators import (
    Unique,
    StrongNames,
    StrongUsername,
    StrongPassword
)
from users.models import User, Content, Contact


class RegisterForm(FlaskForm):

    username = StringField('Username',
                           validators=[DataRequired(), Length(1, 30), StrongUsername(),
                                       Unique(User, User.username, message='Username already exists choose another.')]
                           )
    first_name = StringField('First Name', validators=[
                             DataRequired(), Length(3, 20), StrongNames()])
    last_name = StringField('Last Name', validators=[
                            DataRequired(), Length(3, 20), StrongNames()])
    email = EmailField('Email Address',
                       validators=[DataRequired(), Length(8, 150), Email(),
                                   Unique(User, User.email, message='Email Address already registered with us.')]
                       )
    role = SelectField('Role', choices=[('admin', 'Admin'), ('student', 'Student'), (
        'volunteer', 'Volunteer')], validators=[DataRequired()])
    
    # Additional fields for volunteer
    id_copy = FileField('Upload ID Copy', validators=[FileAllowed(['pdf'], message='Please upload PDF only.'), FileSize(max_size=2000000, message='ID copy size should not greater than 2MB.')])
    certificates = FileField('Upload Certificates', validators=[FileAllowed(['pdf'], message='Please upload PDF only.'), FileSize(max_size=2000000, message='Certificates size should not greater than 2MB.')])
    
    password = PasswordField('Password',
                             validators=[DataRequired(), Length(
                                 8, 20), StrongPassword()]
                             )
    remember = BooleanField(
        'I agree & accept all terms of services. ', validators=[DataRequired()])
    submit = SubmitField('Continue')


class LoginForm(FlaskForm):

    username = StringField('Username or Email Address', validators=[
                           DataRequired(), Length(5, 150)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(8, 20)])
    # recaptcha = RecaptchaField()
    remember = BooleanField('Remember me', validators=[DataRequired()])
    submit = SubmitField('Continue')


class ForgotPasswordForm(FlaskForm):

    email = EmailField('Email Address',
                       validators=[DataRequired(), Length(8, 150), Email()]
                       )
    remember = BooleanField(
        'I agree & accept all terms of services.', validators=[DataRequired()])
    submit = SubmitField('Send Reset Link')


class ResetPasswordForm(FlaskForm):

    password = PasswordField('Password',
                             validators=[DataRequired(), Length(
                                 8, 20), StrongPassword()]
                             )
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), Length(
                                         8, 20), StrongPassword()]
                                     )
    remember = BooleanField('Remember me', validators=[DataRequired()])
    submit = SubmitField('Submit')


class ChangePasswordForm(FlaskForm):

    old_password = PasswordField('Old Password', validators=[
                                 DataRequired(), Length(8, 20)])
    new_password = PasswordField('New Password', validators=[
                                 DataRequired(), Length(8, 20)])
    confirm_password = PasswordField('Confirm New Password', validators=[
                                     DataRequired(), Length(8, 20)])
    remember = BooleanField('Remember me', validators=[DataRequired()])
    submit = SubmitField('Submit')


class ChangeEmailForm(FlaskForm):

    email = EmailField('Email Address',
                       validators=[DataRequired(), Length(8, 150), Email()]
                       )
    remember = BooleanField(
        'I agree & accept all terms of services.', validators=[DataRequired()])
    submit = SubmitField('Send Confirmation Mail')


class EditUserProfileForm(FlaskForm):

    username = StringField('Username',
                           validators=[DataRequired(), Length(
                               1, 30), StrongUsername()]
                           )
    first_name = StringField('First Name', validators=[
                             DataRequired(), Length(3, 25), StrongNames()])
    last_name = StringField('Last Name', validators=[
                            DataRequired(), Length(3, 25), StrongNames()])
    profile_image = FileField('Profile Image',
                              validators=[
                                  FileAllowed(['jpg', 'jpeg', 'png', 'svg'],
                                              'Please upload images only.'),
                                  FileSize(max_size=2000000,
                                           message='Profile image size should not greater than 2MB.')
                              ]
                              )
    about = TextAreaField('About')
    submit = SubmitField('Save Profile')


class ContactForm(FlaskForm):
  name = StringField("Name",  validators=[
                     DataRequired(message="Please enter your name.")])
  email = StringField("Email", validators=[DataRequired(
      message="Please enter your email address"), Email()])
  subject = StringField("Subject", validators=[
                        DataRequired(message="Please enter a subject.")])
  message = TextAreaField("Message", validators=[
                          DataRequired(message="Please enter a message.")])
  submit = SubmitField("Send")


class UploadContentForm(FlaskForm):
    content_type = SelectField('Content Type', choices=[
        ('textbook', 'Textbook'),
        ('worksheet', 'Worksheet'),
        ('study_guide', 'Study Guide'),
        ('additional_problem', 'Additional Problem'),
        ('video', 'Video')
    ], validators=[InputRequired()])
    file = FileField('Upload File', validators=[FileAllowed(['pdf', 'docx', 'doc', 'ppt', 'pptx', 'xlsx', 'xls', 'csv', 'mp4', 'avi', 'mkv', 'mov', 'flv', 'wmv', 'webm', 'ogg', 'mp3', 'wav', 'flac', 'aac', 'wma', 'm4a', 'm4p', 'm4r', 'm4b', 'm4v', '3gp', '3g2', 'amr', 'awb'])])
    link = StringField('Link', validators=[])
    stem = SelectField('STEM', choices=[
                       ('maths', 'Maths'), ('science', 'Science')], validators=[InputRequired()])
    topic = SelectField('Topic', choices=[], validators=[InputRequired()])
    subtopic = SelectField('Subtopic', choices=[],
                           validators=[InputRequired()])
    published = BooleanField('Published', default=True)
    
class CreateSlotForm(FlaskForm):
    stem = SelectField('STEM', choices=[
                       ('maths', 'Maths'), ('science', 'Science')], validators=[InputRequired()])
    topic = SelectField('Topic', choices=[], validators=[InputRequired()])
    subtopic = SelectField('Subtopic', choices=[],
                           validators=[InputRequired()])
    date = DateField('Date', validators=[DataRequired()], 
                     format=['%m-%d-%Y', '%Y-%m-%d', '%m/%d/%Y', '%Y/%m/%d', '%m.%d.%Y', '%Y.%m.%'])
    start_time = TimeField('Start Time', validators=[DataRequired()], format='%H:%M')
    end_time = TimeField('End Time', validators=[DataRequired()], format='%H:%M')
    teams_link = StringField('Teams Meeting Link', validators=[URL(), InputRequired()], render_kw={"placeholder": "Enter Teams meeting link"})
    submit = SubmitField('Create Slot')
    
class PostForm(FlaskForm):
    stem = SelectField('STEM', choices=[
                       ('maths', 'Maths'), ('science', 'Science')], validators=[InputRequired()])
    topic = SelectField('Topic', choices=[], validators=[InputRequired()])
    subtopic = SelectField('Subtopic', choices=[],
                           validators=[InputRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    image = FileField('Attachment', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'svg'], 'Please upload images only.'), FileSize(max_size=2000000, message='Image size should not greater than 2MB.')])
    submit = SubmitField('Post')
    
class CommentForm(FlaskForm):
    body = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Submit Comment')

class PapersForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    link = StringField('Link', validators=[URL(), DataRequired()])
    paper_type = SelectField('Paper Type', choices=[('choose paper type', 'Choose paper type'),('caps', 'CAPS'), ('ieb', 'IEB')], validators=[InputRequired()])
    stem = SelectField('STEM', choices=[('choose subject', 'Choose Subject'),('maths', 'Maths'), ('science', 'Science')], validators=[InputRequired()])
    year_written = StringField('Year Written', validators=[DataRequired()])
    submit = SubmitField('Upload')