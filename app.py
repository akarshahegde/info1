from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps

app = Flask(__name__)

# Update these configurations with your MySQL connection details
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:123456@localhost/INFY'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'

db = SQLAlchemy(app)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(10), unique=True, nullable=False)

class LogInCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    role = db.relationship('Role', backref=db.backref('credentials', lazy=True))

class SEData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    projectname = db.Column(db.String(50), nullable=False)
    supervisor = db.Column(db.String(50), nullable=False)
    deadline = db.Column(db.String(20), nullable=False)

class EmpSE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(100), nullable=False)
    phone_no = db.Column(db.String(20), nullable=False)
    salary = db.Column(db.Float, nullable=False)
    bloodgroup = db.Column(db.String(10), nullable=False)

class HRData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    supervisor = db.Column(db.String(50), nullable=False)

class EmpHR(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(100), nullable=False)
    phone_no = db.Column(db.String(20), nullable=False)
    rank = db.Column(db.String(20), nullable=False)

class EmpPR(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(100), nullable=False)
    phone_no = db.Column(db.String(20), nullable=False)
    salary = db.Column(db.Float, nullable=False)

class PRData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    dob = db.Column(db.Date, nullable=False)

class AuditTrail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

def log_action(user, action):
    entry = AuditTrail(user=user, action=action)
    db.session.add(entry)
    db.session.commit()

def role_required(*roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'role' in session and session['role'] in roles:
                return func(*args, **kwargs)
            else:
                flash('Access Denied. Insufficient privileges.', 'error')
                return redirect(url_for('index'))
        return wrapper
    return decorator

# Utility function for checking admin role
def is_admin():
    return 'role' in session and session['role'] == 'Admin'

# Decorator for admin access
def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if is_admin():
            return func(*args, **kwargs)
        else:
            flash('Access Denied. Only Admins are allowed.', 'error')
            return redirect(url_for('index'))
    return wrapper

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logout')
def logout():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    print(username)
    print(password)
    user = LogInCredential.query.filter_by(username=username, password=password).first()
    print(user)

    if user:
        session['username'] = user.username
        session['role'] = user.role.name
        log_action(session['username'], 'Logged In')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid username or password', 'error')
        return redirect(url_for('index'))

@app.route('/dashboard')
@role_required('Admin', 'SE')
def dashboard():
    log_action(session['username'], 'Accessed Dashboard')
    return render_template('dashboard.html')

@app.route('/audit-trail')
@role_required('Admin')
def audit_trail():
    entries = AuditTrail.query.order_by(AuditTrail.timestamp.desc()).all()
    return render_template('audit_trail.html', entries=entries)

@app.route('/assign-role', methods=['POST'])
@role_required('Admin')
def assign_role():
    username = request.form['username']
    role_name = request.form['role']
    
    user = LogInCredential.query.filter_by(username=username).first()
    if not user:
        flash('User not found', 'error')
    else:
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            flash('Role not found', 'error')
        else:
            user.role = role
            db.session.commit()
            flash(f'Role "{role_name}" assigned to user "{username}" successfully', 'success')
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create all database tables
        
        # Delete credentials associated with roles
        LogInCredential.query.delete()
        db.session.commit()
        
        # Clear existing roles
        Role.query.delete()
        db.session.commit()
        print('main')

        # Insert initial roles if they don't already exist
        initial_roles = ['Admin', 'SE', 'HR', 'PR', 'General']
        for role_name in initial_roles:
            role = Role.query.filter_by(name=role_name).first()
            print(role)
            if not role:
                role = Role(name=role_name)
                db.session.add(role)
        
        db.session.commit()

        # Insert initial admin user if it doesn't already exist
        admin_user = LogInCredential.query.filter_by(username='admin').first()
        if not admin_user:
            admin_role = Role.query.filter_by(name='Admin').first()
            admin_user = LogInCredential(username='admin', password='admin', role=admin_role)
            db.session.add(admin_user)
            db.session.commit()

        # Insert sample user details
        sample_users = [
    {'username': 'john_doe', 'password': 'password', 'role_name': 'SE'},
    {'username': 'jane_smith', 'password': 'password', 'role_name': 'SE'},
    {'username': 'alex_miller', 'password': 'password', 'role_name': 'SE'},
    {'username': 'amy_jones', 'password': 'password', 'role_name': 'HR'},
    {'username': 'peter_parker', 'password': 'password', 'role_name': 'HR'},
    {'username': 'emma_stone', 'password': 'password', 'role_name': 'HR'},
    {'username': 'jim_carrey', 'password': 'password', 'role_name': 'PR'},
    {'username': 'jennifer_lopez', 'password': 'password', 'role_name': 'PR'},
    {'username': 'brad_pitt', 'password': 'password', 'role_name': 'PR'}
]
        for user_data in sample_users:
            user = LogInCredential.query.filter_by(username=user_data['username']).first()
            if not user:
                role = Role.query.filter_by(name=user_data['role_name']).first()
                user = LogInCredential(username=user_data['username'], password=user_data['password'], role=role)
                db.session.add(user)
        
        db.session.commit()

    app.run(debug=True)
