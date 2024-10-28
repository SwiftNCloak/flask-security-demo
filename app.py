from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, auth_required, roles_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators
import secrets
import uuid

app = Flask(__name__)

# Security Step 1: Strong Secret Key
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Security Step 2: Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Security Step 3: Secure Cookie Settings
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Flask-Security Configuration
app.config['SECURITY_PASSWORD_SALT'] = secrets.token_hex(16)
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
app.config['SECURITY_LOGIN_URL'] = '/'
app.config['SECURITY_REGISTER_URL'] = '/register'
app.config['SECURITY_POST_LOGIN_VIEW'] = '/home'
app.config['SECURITY_POST_LOGOUT_VIEW'] = '/'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

# Define Role Model for Flask-Security
class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

# Define Users-Roles Relationship
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

# Enhanced User Model with Flask-Security
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    active = db.Column(db.Boolean(), default=True)
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Security Step 5: Form Validation
class RegistrationForm(FlaskForm):
    username = StringField('Username', [
        validators.Length(min=4, max=25),
        validators.Regexp(r'^[\w]+$',
            message="Username must contain only letters, numbers, and underscores")
    ])
    password = PasswordField('Password', [
        validators.Length(min=8,
            message="Password must be at least 8 characters long"),
        validators.Regexp(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])',
            message="Password must include uppercase, lowercase, and numbers")
    ])

# Security Step 7: Secure Login Route using Flask-Security's `auth_required`
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    if not username or not password:
        flash('All fields are required', 'error')
        return render_template('index.html')

    user = User.query.filter_by(username=username).first()
    
    if user and bcrypt.check_password_hash(user.password, password):
        session['user_id'] = user.id
        return redirect(url_for('home'))

    flash('Invalid credentials', 'error')
    return render_template('index.html')

# Security Step 8: Secure Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html', form=form)
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = user_datastore.create_user(username=username, password=hashed_password)
        
        try:
            db.session.commit()
            flash('Registration successful', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            return render_template('register.html', form=form)
            
    return render_template('register.html', form=form)

# Security Step 9: Protected Home Route (requires login)
@app.route('/home')
@auth_required()
def home():
    return render_template('home.html')

# Secure API endpoint example (requires 'admin' role)
@app.route('/admin')
@roles_required('admin')
def admin():
    return "This is a protected admin endpoint."

# Security Step 10: Secure Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=False)
