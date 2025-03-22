# __init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_mail import Mail

# Initialize Flask app
app = Flask(__name__)

# Direct configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///waf.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['LOG_FILE'] = 'waf.log'
app.config['RATE_LIMIT'] = 100
app.config['RATE_LIMIT_WINDOW'] = 60
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-username'
app.config['MAIL_PASSWORD'] = 'your-password'
app.config['MAIL_DEFAULT_SENDER'] = 'waf@example.com'

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
mail = Mail(app)

# Import models and routes after initializing app and extensions
from . import models, routes