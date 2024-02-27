from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
db = SQLAlchemy(app)


with app.app_context():
    # Drop specific tables
    db.session.execute(text('DROP TABLE IF EXISTS response;'))
    db.session.execute(text('DROP TABLE IF EXISTS question;'))
    db.session.commit()