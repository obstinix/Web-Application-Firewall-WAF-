# run.py
from __init__ import app

if __name__ == '__main__':
    # Create database tables if they don't exist
    from __init__ import db
    from models import User
    
    with app.app_context():
        db.create_all()
        
        # Create default admin user if no users exist
        if not User.query.first():
            from __init__ import bcrypt
            default_admin = User(
                username='admin',
                email='admin@example.com',
                password=bcrypt.generate_password_hash('admin').decode('utf-8'),
                role='admin',
                created_at=datetime.utcnow()
            )
            db.session.add(default_admin)
            db.session.commit()
    
    app.run(debug=True, host='0.0.0.0')