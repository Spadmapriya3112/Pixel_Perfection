import os
import cv2
import numpy as np
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer as Serializer
from PIL import Image, ImageEnhance, ImageOps, ImageDraw, ImageFont

app = Flask(__name__)

# --- CONFIGURATION ---
app.config['SECRET_KEY'] = 'pixel_perfection_pro_2026_secure'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Folder Configurations
UPLOAD_FOLDER = os.path.join('static', 'uploads')
PROCESSED_FOLDER = os.path.join('static', 'processed')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROCESSED_FOLDER'] = PROCESSED_FOLDER

# --- MAIL CONFIGURATION ---
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'e23ai023@sdnbvc.edu.in'
app.config['MAIL_PASSWORD'] = 'jbny qhgn kljc ajmf'

# Ensure the directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)

login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- HELPER FUNCTIONS ---
def send_reset_email(user):
    s = Serializer(app.config['SECRET_KEY'])
    token = s.dumps({'user_id': user.id})
    msg = Message('Pixel Perfection - Password Reset Request',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request, simply ignore this email.
'''
    mail.send(msg)

# --- Public Routes ---
@app.route('/')
def splash():
    return render_template('splash.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

# --- Auth Routes ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        try:
            db.session.add(user)
            db.session.commit()
            flash('Account created! Welcome to Pixel Perfection.', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Username or Email already exists.', 'danger')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('splash'))

# --- PASSWORD RESET ROUTES ---
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
            flash('Instructions to reset your password have been sent to your email.', 'info')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email.', 'warning')
    return render_template('reset_request.html', title='Reset Password')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    s = Serializer(app.config['SECRET_KEY'])
    try:
        user_id = s.loads(token, max_age=1800)['user_id']
    except:
        flash('Invalid or expired token.', 'warning')
        return redirect(url_for('reset_request'))
    
    user = User.query.get(user_id)
    if request.method == 'POST':
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password')

# --- Protected Routes ---
@app.route('/editor', methods=['GET', 'POST'])
@login_required
def editor():
    image_url = None
    if request.method == 'POST':
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_url = filename
                
    return render_template('editor.html', image_url=image_url)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            filename = secure_filename(file.filename)
            input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(input_path)

            output_name = 'perfected_' + filename
            output_path = os.path.join(app.config['PROCESSED_FOLDER'], output_name)
            
            img = cv2.imread(input_path)
            if img is not None:
                denoised_img = cv2.fastNlMeansDenoisingColored(img, None, 10, 10, 7, 21)
                cv2.imwrite(output_path, denoised_img)

                # Updated return statement below
                return render_template('create.html', 
                                       original='uploads/' + filename, 
                                       processed='processed/' + output_name,
                                       image_url=filename) 
    
    return render_template('create.html')

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['PROCESSED_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)