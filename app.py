# app.py - Main application file
from flask import Flask, request, render_template, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import re
import json
import logging
import ipaddress
import threading
import os
from functools import wraps
import time
import uuid

# Initialize Flask app
app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
mail = Mail(app)

# Set up logging
logging.basicConfig(
    filename=app.config['LOG_FILE'],
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('waf')

# Import models after db initialization to avoid circular imports
from models import Request, Rule, IPBlacklist, User, Alert

# Initialize in-memory rate limiting cache
# Structure: {ip_address: [timestamp1, timestamp2, ...]}
rate_limit_cache = {}
# Lock for thread-safe operations on the cache
rate_limit_lock = threading.Lock()

# Global request counter for statistics
request_counter = {'total': 0, 'blocked': 0}

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# WAF Middleware
@app.before_request
def waf_middleware():
    # Skip WAF for static files and admin panel
    if request.path.startswith('/static/') or request.path.startswith('/admin/assets/'):
        return None
    
    # Generate unique request ID
    request_id = str(uuid.uuid4())
    
    # Increment total request counter
    request_counter['total'] += 1
    
    # Extract request data
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    request_method = request.method
    request_path = request.path
    query_string = request.query_string.decode('utf-8', errors='ignore')
    request_body = request.get_data(as_text=True) if request.method in ['POST', 'PUT', 'PATCH'] else ''
    headers = dict(request.headers)
    
    # Check if IP is blacklisted
    if is_ip_blacklisted(client_ip):
        log_blocked_request(request_id, client_ip, 'Blacklisted IP')
        return jsonify({"error": "Access denied"}), 403
    
    # Perform rate limiting
    if is_rate_limited(client_ip):
        log_blocked_request(request_id, client_ip, 'Rate limited')
        return jsonify({"error": "Too many requests"}), 429
    
    # Combine all request data for rule checking
    request_data = {
        'path': request_path,
        'query': query_string,
        'body': request_body,
        'headers': headers,
        'method': request_method,
        'ip': client_ip,
        'user_agent': user_agent
    }
    
    # Check against security rules
    rule_violation = check_security_rules(request_data)
    if rule_violation:
        rule_name = rule_violation.get('name', 'Unknown rule')
        log_blocked_request(request_id, client_ip, f'Rule violation: {rule_name}')
        
        # Send alert for high severity violations
        if rule_violation.get('severity', 'medium') == 'high':
            send_alert(rule_violation, request_data)
        
        # Return 403 Forbidden
        return jsonify({"error": "Request blocked due to security policy"}), 403
    
    # Log legitimate request
    log_request(request_id, client_ip, request_method, request_path, 
                query_string, user_agent, 'allowed')

# Security rule checking function
def check_security_rules(request_data):
    # Get all active rules from database
    rules = Rule.query.filter_by(is_active=True).all()
    
    for rule in rules:
        # Determine which part of the request to check
        target_data = ''
        if rule.target == 'path':
            target_data = request_data['path']
        elif rule.target == 'query':
            target_data = request_data['query']
        elif rule.target == 'body':
            target_data = request_data['body']
        elif rule.target == 'headers':
            # Convert headers to string for pattern matching
            target_data = json.dumps(request_data['headers'])
        elif rule.target == 'all':
            # Combine all request data
            target_data = (
                request_data['path'] + ' ' +
                request_data['query'] + ' ' +
                request_data['body'] + ' ' +
                json.dumps(request_data['headers'])
            )
        
        # Check if rule pattern matches the target data
        if rule.rule_type == 'regex':
            if re.search(rule.pattern, target_data, re.IGNORECASE):
                return {
                    'id': rule.id,
                    'name': rule.name,
                    'severity': rule.severity
                }
        elif rule.rule_type == 'exact':
            if rule.pattern in target_data:
                return {
                    'id': rule.id,
                    'name': rule.name,
                    'severity': rule.severity
                }
    
    return None

# IP blacklist checking function
def is_ip_blacklisted(ip):
    # Check if IP is in database blacklist
    blacklist_entry = IPBlacklist.query.filter_by(ip_address=ip, is_active=True).first()
    return blacklist_entry is not None

# Rate limiting function
def is_rate_limited(ip):
    # Get rate limit settings from config
    rate_limit = app.config['RATE_LIMIT']
    rate_window = app.config['RATE_LIMIT_WINDOW']
    
    with rate_limit_lock:
        # Initialize entry for this IP if it doesn't exist
        if ip not in rate_limit_cache:
            rate_limit_cache[ip] = []
        
        # Remove timestamps older than the window
        current_time = time.time()
        rate_limit_cache[ip] = [t for t in rate_limit_cache[ip] 
                                if current_time - t < rate_window]
        
        # Check if request count is within limit
        if len(rate_limit_cache[ip]) >= rate_limit:
            return True
        
        # Add current timestamp
        rate_limit_cache[ip].append(current_time)
        return False

# Request logging function
def log_request(request_id, ip, method, path, query, user_agent, status):
    # Log to database
    new_request = Request(
        request_id=request_id,
        ip_address=ip,
        method=method,
        path=path,
        query_string=query,
        user_agent=user_agent,
        status=status,
        timestamp=datetime.utcnow()
    )
    db.session.add(new_request)
    db.session.commit()
    
    # Log to file
    logger.info(f"Request {request_id}: {ip} {method} {path}?{query} - {status}")

# Blocked request logging function
def log_blocked_request(request_id, ip, reason):
    # Increment blocked counter
    request_counter['blocked'] += 1
    
    # Log to database
    new_request = Request(
        request_id=request_id,
        ip_address=ip,
        method=request.method,
        path=request.path,
        query_string=request.query_string.decode('utf-8', errors='ignore'),
        user_agent=request.headers.get('User-Agent', ''),
        status='blocked',
        reason=reason,
        timestamp=datetime.utcnow()
    )
    db.session.add(new_request)
    db.session.commit()
    
    # Log to file
    logger.warning(f"Blocked {request_id}: {ip} - {reason}")

# Alert sending function
def send_alert(rule_violation, request_data):
    admin_emails = [user.email for user in User.query.filter_by(role='admin').all()]
    
    if not admin_emails:
        logger.warning("No admin emails configured for alerts")
        return
    
    # Create alert record
    alert = Alert(
        rule_id=rule_violation['id'],
        ip_address=request_data['ip'],
        request_data=json.dumps(request_data),
        timestamp=datetime.utcnow()
    )
    db.session.add(alert)
    db.session.commit()
    
    # Send email
    subject = f"WAF Alert: {rule_violation['name']} violation detected"
    body = f"""
    A high severity security rule violation was detected:
    
    Rule: {rule_violation['name']}
    IP Address: {request_data['ip']}
    Path: {request_data['path']}
    Method: {request_data['method']}
    User Agent: {request_data['user_agent']}
    Time: {datetime.utcnow()}
    
    Please check the admin dashboard for more details.
    """
    
    try:
        msg = Message(subject=subject, recipients=admin_emails, body=body)
        mail.send(msg)
    except Exception as e:
        logger.error(f"Failed to send alert email: {str(e)}")

# Routes for admin panel
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get statistics for the dashboard
    total_requests = Request.query.count()
    blocked_requests = Request.query.filter_by(status='blocked').count()
    active_rules = Rule.query.filter_by(is_active=True).count()
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()
    
    # Get recent request logs
    recent_logs = Request.query.order_by(Request.timestamp.desc()).limit(10).all()
    
    return render_template('dashboard.html', 
                           total_requests=total_requests,
                           blocked_requests=blocked_requests,
                           active_rules=active_rules,
                           recent_alerts=recent_alerts,
                           recent_logs=recent_logs)

# Rules management routes
@app.route('/rules')
@login_required
def rules_list():
    rules = Rule.query.all()
    return render_template('rules.html', rules=rules)

@app.route('/rules/add', methods=['GET', 'POST'])
@login_required
def add_rule():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        rule_type = request.form.get('rule_type')
        target = request.form.get('target')
        pattern = request.form.get('pattern')
        severity = request.form.get('severity')
        is_active = request.form.get('is_active') == 'on'
        
        # Validate the regex pattern if it's a regex rule
        if rule_type == 'regex':
            try:
                re.compile(pattern)
            except re.error:
                return render_template('add_rule.html', error="Invalid regex pattern")
        
        new_rule = Rule(
            name=name,
            description=description,
            rule_type=rule_type,
            target=target,
            pattern=pattern,
            severity=severity,
            is_active=is_active,
            created_at=datetime.utcnow()
        )
        db.session.add(new_rule)
        db.session.commit()
        
        return redirect(url_for('rules_list'))
    
    return render_template('add_rule.html')

@app.route('/rules/edit/<int:rule_id>', methods=['GET', 'POST'])
@login_required
def edit_rule(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    
    if request.method == 'POST':
        rule.name = request.form.get('name')
        rule.description = request.form.get('description')
        rule.rule_type = request.form.get('rule_type')
        rule.target = request.form.get('target')
        rule.pattern = request.form.get('pattern')
        rule.severity = request.form.get('severity')
        rule.is_active = request.form.get('is_active') == 'on'
        
        # Validate the regex pattern if it's a regex rule
        if rule.rule_type == 'regex':
            try:
                re.compile(rule.pattern)
            except re.error:
                return render_template('edit_rule.html', rule=rule, error="Invalid regex pattern")
        
        rule.updated_at = datetime.utcnow()
        db.session.commit()
        
        return redirect(url_for('rules_list'))
    
    return render_template('edit_rule.html', rule=rule)

@app.route('/rules/delete/<int:rule_id>', methods=['POST'])
@login_required
def delete_rule(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    
    return redirect(url_for('rules_list'))

# IP blacklist management routes
@app.route('/blacklist')
@login_required
def blacklist():
    ips = IPBlacklist.query.all()
    return render_template('blacklist.html', ips=ips)

@app.route('/blacklist/add', methods=['GET', 'POST'])
@login_required
def add_blacklist():
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')
        reason = request.form.get('reason')
        is_active = request.form.get('is_active') == 'on'
        
        # Validate IP address
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return render_template('add_blacklist.html', error="Invalid IP address format")
        
        new_blacklist = IPBlacklist(
            ip_address=ip_address,
            reason=reason,
            is_active=is_active,
            created_at=datetime.utcnow()
        )
        db.session.add(new_blacklist)
        db.session.commit()
        
        return redirect(url_for('blacklist'))
    
    return render_template('add_blacklist.html')

@app.route('/blacklist/edit/<int:blacklist_id>', methods=['GET', 'POST'])
@login_required
def edit_blacklist(blacklist_id):
    blacklist_entry = IPBlacklist.query.get_or_404(blacklist_id)
    
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')
        reason = request.form.get('reason')
        is_active = request.form.get('is_active') == 'on'
        
        # Validate IP address
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return render_template('edit_blacklist.html', blacklist=blacklist_entry, 
                                  error="Invalid IP address format")
        
        blacklist_entry.ip_address = ip_address
        blacklist_entry.reason = reason
        blacklist_entry.is_active = is_active
        blacklist_entry.updated_at = datetime.utcnow()
        db.session.commit()
        
        return redirect(url_for('blacklist'))
    
    return render_template('edit_blacklist.html', blacklist=blacklist_entry)

@app.route('/blacklist/delete/<int:blacklist_id>', methods=['POST'])
@login_required
def delete_blacklist(blacklist_id):
    blacklist_entry = IPBlacklist.query.get_or_404(blacklist_id)
    db.session.delete(blacklist_entry)
    db.session.commit()
    
    return redirect(url_for('blacklist'))

# Request logs routes
@app.route('/logs')
@login_required
def logs():
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'all')
    ip_filter = request.args.get('ip', '')
    
    # Base query
    query = Request.query
    
    # Apply filters
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    if ip_filter:
        query = query.filter(Request.ip_address.like(f'%{ip_filter}%'))
    
    # Paginate results
    logs = query.order_by(Request.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False)
    
    return render_template('logs.html', logs=logs, status_filter=status_filter, 
                           ip_filter=ip_filter)

# Alert management routes
@app.route('/alerts')
@login_required
def alerts():
    page = request.args.get('page', 1, type=int)
    alerts = Alert.query.order_by(Alert.timestamp.desc()).paginate(
        page=page, per_page=20, error_out=False)
    
    return render_template('alerts.html', alerts=alerts)

@app.route('/alerts/<int:alert_id>')
@login_required
def alert_detail(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    
    # Parse JSON request data
    request_data = json.loads(alert.request_data)
    
    return render_template('alert_detail.html', alert=alert, request_data=request_data)

# API endpoints for AJAX requests
@app.route('/api/stats')
@login_required
def api_stats():
    # Get time range from query parameters (default to last 24 hours)
    days = request.args.get('days', 1, type=int)
    start_time = datetime.utcnow() - timedelta(days=days)
    
    # Get requests by status
    total = Request.query.filter(Request.timestamp >= start_time).count()
    blocked = Request.query.filter(Request.timestamp >= start_time, 
                                  Request.status == 'blocked').count()
    allowed = total - blocked
    
    # Get requests by hour for charts
    hourly_data = []
    for i in range(24):
        hour_start = datetime.utcnow() - timedelta(hours=24-i)
        hour_end = datetime.utcnow() - timedelta(hours=23-i)
        
        hour_total = Request.query.filter(
            Request.timestamp >= hour_start,
            Request.timestamp < hour_end
        ).count()
        
        hour_blocked = Request.query.filter(
            Request.timestamp >= hour_start,
            Request.timestamp < hour_end,
            Request.status == 'blocked'
        ).count()
        
        hourly_data.append({
            'hour': hour_start.strftime('%H:00'),
            'total': hour_total,
            'blocked': hour_blocked,
            'allowed': hour_total - hour_blocked
        })
    
    # Get top blocked IPs
    top_blocked_ips = db.session.query(
        Request.ip_address, 
        db.func.count(Request.id).label('count')
    ).filter(
        Request.status == 'blocked',
        Request.timestamp >= start_time
    ).group_by(Request.ip_address).order_by(db.desc('count')).limit(5).all()
    
    # Get top triggered rules
    top_rules = db.session.query(
        Request.reason, 
        db.func.count(Request.id).label('count')
    ).filter(
        Request.status == 'blocked',
        Request.timestamp >= start_time,
        Request.reason.like('Rule violation:%')
    ).group_by(Request.reason).order_by(db.desc('count')).limit(5).all()
    
    return jsonify({
        'summary': {
            'total': total,
            'blocked': blocked,
            'allowed': allowed,
            'block_rate': round((blocked / total * 100) if total > 0 else 0, 2)
        },
        'hourly_data': hourly_data,
        'top_blocked_ips': [{'ip': ip, 'count': count} for ip, count in top_blocked_ips],
        'top_rules': [{'rule': reason.replace('Rule violation:', '').strip(), 
                       'count': count} for reason, count in top_rules]
    })

# User management routes
@app.route('/users')
@login_required
def users():
    # Check if user is admin
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    # Check if user is admin
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            return render_template('add_user.html', error="Username already exists")
        
        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            role=role,
            created_at=datetime.utcnow()
        )
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('users'))
    
    return render_template('add_user.html')

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    # Check if user is admin
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        password = request.form.get('password')
        
        # Check if username already exists for another user
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != user_id:
            return render_template('edit_user.html', user=user, error="Username already exists")
        
        user.username = username
        user.email = email
        user.role = role
        
        # Update password if provided
        if password:
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return redirect(url_for('users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    # Check if user is admin
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    
    # Prevent deleting own account
    if user_id == session.get('user_id'):
        return redirect(url_for('users'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    return redirect(url_for('users'))

# Settings route
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        # Update rate limiting settings
        app.config['RATE_LIMIT'] = int(request.form.get('rate_limit', 100))
        app.config['RATE_LIMIT_WINDOW'] = int(request.form.get('rate_window', 60))
        
        # Update email notification settings
        app.config['MAIL_SERVER'] = request.form.get('mail_server')
        app.config['MAIL_PORT'] = int(request.form.get('mail_port', 587))
        app.config['MAIL_USE_TLS'] = request.form.get('mail_use_tls') == 'on'
        app.config['MAIL_USERNAME'] = request.form.get('mail_username')
        app.config['MAIL_PASSWORD'] = request.form.get('mail_password')
        app.config['MAIL_DEFAULT_SENDER'] = request.form.get('mail_sender')
        
        # Reinitialize mail extension with new settings
        mail = Mail(app)
        
        # Save settings to config file
        with open('config.py', 'w') as f:
            f.write("class Config:\n")
            for key, value in app.config.items():
                if isinstance(value, str):
                    f.write(f"    {key} = '{value}'\n")
                else:
                    f.write(f"    {key} = {value}\n")
        
        return redirect(url_for('settings'))
    
    return render_template('settings.html', config=app.config)

# Help route
@app.route('/help')
@login_required
def help_page():
    return render_template('help.html')

# Custom error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('errors/500.html'), 500

# Start the application
if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
        
        # Create default admin user if no users exist
        if not User.query.first():
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