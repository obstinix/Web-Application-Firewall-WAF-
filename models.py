# models.py - Database models for the WAF
from datetime import datetime
from . import db

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Request(db.Model):
    __tablename__ = 'requests'
    
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.String(36), unique=True, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6-compatible length
    method = db.Column(db.String(10), nullable=False)
    path = db.Column(db.String(255), nullable=False)
    query_string = db.Column(db.Text)
    user_agent = db.Column(db.String(255))
    status = db.Column(db.String(20), nullable=False)  # 'allowed' or 'blocked'
    reason = db.Column(db.String(255))  # Reason for blocking if status is 'blocked'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Request {self.request_id}>'

class Rule(db.Model):
    __tablename__ = 'rules'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    rule_type = db.Column(db.String(20), nullable=False)  # 'regex' or 'exact'
    target = db.Column(db.String(20), nullable=False)  # 'path', 'query', 'body', 'headers', 'all'
    pattern = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='medium')  # 'low', 'medium', 'high'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    # Relationship with alerts
    alerts = db.relationship('Alert', backref='rule', lazy=True)
    
    def __repr__(self):
        return f'<Rule {self.name}>'

class IPBlacklist(db.Model):
    __tablename__ = 'ip_blacklist'
    
    id = db.Column(db.Integer, primary_
