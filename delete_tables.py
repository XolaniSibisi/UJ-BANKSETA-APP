from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from users.extensions import database as db
from users.models import Content, Contact, User, Slots

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
db = SQLAlchemy(app)


with app.app_context():
    # Drop specific tables
    db.session.execute(text('DROP TABLE IF EXISTS response;'))
    db.session.execute(text('DROP TABLE IF EXISTS question;'))
    db.session.commit()

with app.app_context():
    try:
        db.session.query(Slots).delete()
        db.session.commit()
        print("All content deleted successfully.")
    except Exception as e:
        db.session.rollback()
        print(f"An error occurred: {str(e)}")
    