import os
import cv2
import numpy as np
import boto3
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from botocore.exceptions import ClientError
from itsdangerous import URLSafeTimedSerializer as Serializer

app = Flask(__name__)

# --- AWS & APP CONFIGURATION ---
app.secret_key = 'pixel_perfection_aws_secure_2026'
REGION = 'us-east-1' 
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:881490100674:pixel_perfection'

# --- LOCAL STORAGE CONFIG (Replacing S3) ---
# On EC2, we use a local folder instead of an S3 bucket
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- MAIL CONFIGURATION ---
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'e23ai023@sdnbvc.edu.in'
app.config['MAIL_PASSWORD'] = 'jbny qhgn kljc ajmf'

# Initialize AWS Services (S3 removed)
dynamodb = boto3.resource('dynamodb', region_name=REGION)
sns = boto3.client('sns', region_name=REGION)
users_table = dynamodb.Table('Users')

bcrypt = Bcrypt(app)
mail = Mail(app)

# --- HELPER FUNCTIONS ---
def send_notification(subject, message):
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    except ClientError as e:
        print(f"SNS Error: {e}")

def send_reset_email(user_email, username):
    s = Serializer(app.secret_key)
    token = s.dumps({'username': username})
    msg = Message('Pixel Perfection - Password Reset Request',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user_email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request, simply ignore this email.
'''
    mail.send(msg)

# Route to serve images from the EC2 local storage
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- PUBLIC ROUTES ---
@app.route('/')
def splash():
    return render_template('splash.html')

@app.route('/home')
def home():
    username = session.get('username')
    return render_template('home.html', username=username)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

# --- AUTH ROUTES (DYNAMODB) ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            response = users_table.get_item(Key={'username': username})
            if 'Item' in response:
                flash('Username already exists!', 'danger')
                return redirect(url_for('signup'))
            
            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            users_table.put_item(Item={
                'username': username,
                'email': email,
                'password': hashed_pw
            })
            
            send_notification("New User", f"{username} has joined Pixel Perfection.")
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except ClientError as e:
            flash('Database Error. Check AWS Credentials.', 'danger')
            print(e)
            
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            response = users_table.get_item(Key={'username': username})
            if 'Item' in response:
                user = response['Item']
                if bcrypt.check_password_hash(user['password'], password):
                    session['username'] = username
                    return redirect(url_for('home'))
            
            flash('Invalid credentials!', 'danger')
        except ClientError as e:
            flash('Could not connect to DynamoDB.', 'danger')
            print(e)
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('splash'))

# --- PASSWORD RESET ---
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form.get('email')
        response = users_table.scan(FilterExpression=boto3.dynamodb.conditions.Attr('email').eq(email))
        items = response.get('Items', [])
        if items:
            user = items[0]
            send_reset_email(user['email'], user['username'])
            flash('Instructions sent to your email.', 'info')
            return redirect(url_for('login'))
        flash('No account found with that email.', 'warning')
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    s = Serializer(app.secret_key)
    try:
        username = s.loads(token, max_age=1800)['username']
    except:
        flash('Invalid or expired token.', 'warning')
        return redirect(url_for('reset_request'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        users_table.update_item(
            Key={'username': username},
            UpdateExpression="set password = :p",
            ExpressionAttributeValues={':p': hashed_pw}
        )
        flash('Password updated!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html')

# --- CORE EDITOR ROUTES (LOCAL EC2 STORAGE) ---
@app.route('/create', methods=['GET', 'POST'])
def create():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            
            # Save original to EC2 storage
            original_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(original_path)

            img = cv2.imread(original_path)
            if img is not None:
                # Process image
                denoised_img = cv2.fastNlMeansDenoisingColored(img, None, 10, 10, 7, 21)
                processed_name = "perfected_" + unique_filename
                processed_path = os.path.join(app.config['UPLOAD_FOLDER'], processed_name)
                cv2.imwrite(processed_path, denoised_img)

                # Generate Local URLs for the browser
                original_url = url_for('uploaded_file', filename=unique_filename)
                processed_url = url_for('uploaded_file', filename=processed_name)

                return render_template('create.html', 
                                       original=original_url, 
                                       processed=processed_url,
                                       image_url=processed_url) 
    return render_template('create.html')

@app.route('/editor', methods=['GET', 'POST'])
def editor():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    image_url = None
    if request.method == 'POST' and 'image' in request.files:
        file = request.files['image']
        if file.filename != '':
            filename = secure_filename(file.filename)
            unique_name = f"{uuid.uuid4()}_{filename}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
            file.save(save_path)
            image_url = url_for('uploaded_file', filename=unique_name)
            
    return render_template('editor.html', image_url=image_url)

if __name__ == '__main__':
    # Using 0.0.0.0 allows access via the EC2 Public IP
    app.run(host='0.0.0.0', port=5000, debug=True) 
