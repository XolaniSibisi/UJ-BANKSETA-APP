from flask_bootstrap import Bootstrap5
from flask_login import LoginManager
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from flask_wtf import CSRFProtect
from flask_mail import Mail
from flask_migrate import Migrate

metadata = MetaData(
    naming_convention={
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
    }
)


# A bootstrap5 class for styling client side. 
bootstrap = Bootstrap5()

# csrf protection for form submission.
csrf = CSRFProtect()

# database for managing user data.
database = SQLAlchemy(metadata=metadata)

# login manager for managing user authentication.
login_manager = LoginManager()

# flask-mail for sending email.
mail = Mail()

# Moment for date and time formatting.
moment = Moment()

# flask_migrate - Migration for database
migrate = Migrate(command='db', render_as_batch=True) 