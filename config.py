class Config:
    SECRET_KEY = 'your-secret-key-change-this'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///waf.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LOG_FILE = 'waf.log'
    RATE_LIMIT = 100  # Maximum requests per window
    RATE_LIMIT_WINDOW = 60  # Window size in seconds
    
    # Mail settings
    MAIL_SERVER = 'smtp.example.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'your-username'
    MAIL_PASSWORD = 'your-password'
    MAIL_DEFAULT_SENDER = 'waf@example.com'