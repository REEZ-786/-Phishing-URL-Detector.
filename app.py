import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re
from urllib.parse import urlparse
import requests
import logging
from functools import wraps

# Load environment variables from .env file at the very beginning
load_dotenv()

# --- Flask App Initialization and Configuration ---
app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_very_secret_key_that_should_be_in_env')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Logging Configuration ---
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
app.logger.addHandler(console_handler)

app.logger.setLevel(logging.INFO)
app.logger.info("Application starting up...")

# --- Database and Login Manager Setup ---
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- Google Safe Browse API Configuration ---
GOOGLE_SAFE_Browse_API_KEY = os.getenv("GOOGLE_SAFE_Browse_API_KEY") 
GOOGLE_SAFE_Browse_API_URL = "https://safeBrowse.googleapis.com/v4/threatMatches:find"

if not GOOGLE_SAFE_Browse_API_KEY:
    app.logger.warning("GOOGLE_SAFE_Browse_API_KEY not found in .env. Google Safe Browse API will not be used.")

# --- User Loader for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Database Models ---
# CORRECTED: Relationships have been fixed
# app.py

# ... (rest of your models) ...

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='client', nullable=False)

    # Use back_populates to explicitly link relationships
    url_checks = db.relationship('URLCheck', back_populates='checker', lazy=True)
    feedback_entries = db.relationship('Feedback', back_populates='author', lazy=True)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.role}')"

# ... (rest of your app.py) ...
class URLCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.String(10), nullable=True)
    score = db.Column(db.Integer, nullable=True)
    reason = db.Column(db.String(500), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Use back_populates to explicitly link the relationships
    checker = db.relationship('User', back_populates='url_checks', lazy=True)

    def __repr__(self):
        return f"URLCheck('{self.url}', '{self.status}', '{self.timestamp}')"

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url_submitted = db.Column(db.String(500), nullable=False)
    feedback_text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending', nullable=False)
    admin_reply = db.Column(db.Text, nullable=True)
    
    author = db.relationship('User', back_populates='feedback_entries', lazy=True)

    def __repr__(self):
        return f"Feedback('{self.url_submitted}', '{self.status}')"


# --- Google Safe Browse API Function ---
def check_with_google_safe_Browse(url):
    if not GOOGLE_SAFE_Browse_API_KEY:
        return None

    headers = {"Content-Type": "application/json"}
    payload = {
        "client": {
            "clientId": "PhishingDetector",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_UNWANTED_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    try:
        params = {"key": GOOGLE_SAFE_Browse_API_KEY}
        response = requests.post(
            GOOGLE_SAFE_Browse_API_URL,
            headers=headers,
            params=params,
            json=payload,
            timeout=8
        )
        response.raise_for_status()

        data = response.json()
        app.logger.info(f"GSB API Response for URL: {url} - Status Code: {response.status_code}, JSON: {data}")

        if data and "matches" in data:
            threat_type = data["matches"][0]["threatType"]
            return threat_type
        else:
            return "SAFE"

    except requests.exceptions.Timeout:
        app.logger.error(f"Google Safe Browse API request timed out for URL: {url}")
        return "API_TIMEOUT"
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error checking with Google Safe Browse API for URL {url}: {e}")
        return "API_ERROR"
    except Exception as e:
        app.logger.error(f"Unexpected error with Google Safe Browse API for URL {url}: {e}")
        return "API_ERROR"

# --- URL Heuristics Analysis Function ---
def analyze_url_heuristics(url):
    is_phishing = False
    score = 0
    reasons = []

    google_safe_Browse_result = check_with_google_safe_Browse(url)

    if google_safe_Browse_result == "SOCIAL_ENGINEERING":
        is_phishing = True
        score += 15
        reasons.append("Google Safe Browse: Identified as Social Engineering (Phishing)")
    elif google_safe_Browse_result == "MALWARE":
        is_phishing = True
        score += 20
        reasons.append("Google Safe Browse: Identified as Malware Site")
    elif google_safe_Browse_result == "UNWANTED_SOFTWARE":
        is_phishing = True
        score += 10
        reasons.append("Google Safe Browse: Identified as Unwanted Software Site")
    elif google_safe_Browse_result == "POTENTIALLY_UNWANTED_APPLICATION":
        is_phishing = True
        score += 8
        reasons.append("Google Safe Browse: Identified as Potentially Unwanted Application Site")
    elif google_safe_Browse_result in ["API_TIMEOUT", "API_ERROR", None]:
        if google_safe_Browse_result is not None:
            app.logger.warning(f"Safe Browse API issue or skip. Proceeding with heuristics only for URL: {url}")
    elif google_safe_Browse_result == "SAFE":
        pass

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else ''
    path = parsed_url.path if parsed_url.path else ''
    query = parsed_url.query if parsed_url.query else ''

    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        score += 3
        reasons.append("IP address used in hostname")

    if len(url) > 75:
        score += 2
        reasons.append(f"Excessive URL length ({len(url)} characters)")

    if "@" in url:
        score += 4
        reasons.append("Contains '@' symbol (potential obfuscation)")

    suspicious_keywords = ["login", "signin", "verify", "account", "bank", "secure", "webscr", "update", "confirm", "service", "support", "billing", "ebay", "paypal", "amazon", "appleid", "icloud"]
    url_lower = url.lower()
    for keyword in suspicious_keywords:
        if keyword in url_lower:
            if f".{keyword}." not in url_lower and f"//{keyword}." not in url_lower:
                score += 1
                reasons.append(f"Contains suspicious keyword: '{keyword}'")

    common_brands_for_mimicry = ["paypal", "google", "microsoft", "apple", "amazon", "ebay", "facebook", "whatsapp", "netflix", "bank", "secure"]
    domain_parts = hostname.split('.')
    if len(domain_parts) > 2:
        main_domain = ".".join(domain_parts[-2:])
        for brand in common_brands_for_mimicry:
            if brand in hostname.lower() and brand not in main_domain.lower():
                score += 3
                reasons.append(f"Mismatched/suspicious brand '{brand}' in subdomain or path")
                break

    if len(domain_parts) > 4:
        score += 2
        reasons.append(f"Excessive number of subdomains ({len(domain_parts) - 2} beyond primary domain)")

    shortening_services = ["bit.ly", "tinyurl.com", "ow.ly", "goo.gl", "t.co", "rebrand.ly", "is.gd", "cli.gs"]
    if any(service in hostname for service in shortening_services):
        score += 5
        reasons.append("Uses a known URL shortening service")

    if "Google Safe Browse" in "".join(reasons):
        is_phishing = True
        confidence = "High"
        if google_safe_Browse_result == "SOCIAL_ENGINEERING":
            status = "Phishing (High - GSB)"
        elif google_safe_Browse_result == "MALWARE":
            status = "Malware (High - GSB)"
        elif google_safe_Browse_result == "UNWANTED_SOFTWARE":
            status = "Unwanted Software (High - GSB)"
        elif google_safe_Browse_result == "POTENTIALLY_UNWANTED_APPLICATION":
            status = "PUA (High - GSB)"
        else:
            status = "Phishing (High - GSB & Heuristics)"
    else:
        if score >= 10:
            is_phishing = True
            confidence = "High"
        elif score >= 5:
            is_phishing = True
            confidence = "Medium"
        elif score >= 2:
            is_phishing = True
            confidence = "Low"
        else:
            is_phishing = False
            confidence = "None"

        if is_phishing:
            status = f"Phishing ({confidence})"
        else:
            status = "Legitimate (None)"

    final_reason = ", ".join(reasons) if reasons else "No specific issues detected by heuristics."
    if google_safe_Browse_result == "API_TIMEOUT":
        final_reason += " (Note: Safe Browse API check timed out.)"
    elif google_safe_Browse_result == "API_ERROR":
        final_reason += " (Note: Safe Browse API check encountered an error.)"

    return {
        "url": url,
        "is_phishing": is_phishing,
        "status": status,
        "confidence": confidence,
        "score": score,
        "reason": final_reason
    }

# --- Flask Routes ---
@app.route('/')
@app.route('/home')
def home():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('client_dashboard'))
    return render_template('login.html')

# app.py

# ... (rest of your imports) ...

# --- Flask Routes ---
# NEW: Main login page with two buttons
@app.route('/login')
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('client_dashboard'))
    return render_template('login.html')

# NEW: Admin login page with a specific form
@app.route('/login/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username, role='admin').first() # Filter by role
        if user and user.check_password(password):
            login_user(user)
            app.logger.info(f"User '{username}' logged in successfully as admin.")
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            app.logger.warning(f"Failed admin login attempt for username: '{username}' from IP: {request.remote_addr}")
            flash('Admin login unsuccessful. Please check your credentials.', 'danger')
    return render_template('admin_login.html') # A new template for admin login

# NEW: Client login page with a specific form
@app.route('/login/client', methods=['GET', 'POST'])
def client_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username, role='client').first() # Filter by role
        if user and user.check_password(password):
            login_user(user)
            app.logger.info(f"User '{username}' logged in successfully as client.")
            flash('Client login successful!', 'success')
            return redirect(url_for('client_dashboard'))
        else:
            app.logger.warning(f"Failed client login attempt for username: '{username}' from IP: {request.remote_addr}")
            flash('Client login unsuccessful. Please check your credentials.', 'danger')
    return render_template('client_login.html') # A new template for client login

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        app.logger.info(f"User '{current_user.username}' (already logged in) attempted to access registration page.")
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username:
            app.logger.warning("Registration attempt failed: Username cannot be empty.")
            flash('Username cannot be empty.', 'danger')
            return render_template('register.html', username=username if username is not None else '', password='', confirm_password='')
        if not password:
            app.logger.warning(f"Registration attempt failed for '{username}': Password cannot be empty.")
            flash('Password cannot be empty.', 'danger')
            return render_template('register.html', username=username, password='', confirm_password='')
        if not confirm_password:
            app.logger.warning(f"Registration attempt failed for '{username}': Confirm Password cannot be empty.")
            flash('Confirm Password cannot be empty.', 'danger')
            return render_template('register.html', username=username, password=password, confirm_password='')

        if password != confirm_password:
            app.logger.warning(f"Registration attempt failed for '{username}': Passwords do not match.")
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', username=username)

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            app.logger.warning(f"Registration attempt failed for '{username}': Username already exists.")
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html', username=username)

        try:
            new_user = User(username=username, role='client')
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            app.logger.info(f"New user registered: '{username}' with role 'client'.")
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during user registration for '{username}': {e}", exc_info=True)
            flash('An error occurred during registration. Please try again.', 'danger')
            return render_template('register.html', username=username)
        
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    user_username = current_user.username
    session.pop('_flashes', None)
    logout_user()
    app.logger.info(f"User '{user_username}' logged out successfully.")
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/client_dashboard')
@login_required
def client_dashboard():
    if current_user.role != 'client':
        flash('Access denied. You do not have client privileges.', 'danger')
        return redirect(url_for('home'))
    
    user_checks = URLCheck.query.filter_by(checker=current_user).order_by(URLCheck.timestamp.desc()).all()
    
    return render_template('index.html', user=current_user, user_checks=user_checks)

@app.route('/admin')
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied. You do not have admin privileges.', 'danger')
        return redirect(url_for('home'))
    
    return render_template('admin_dashboard.html', user=current_user)

@app.route('/admin/users')
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('Access denied. You do not have admin privileges.', 'danger')
        return redirect(url_for('home'))
    
    all_users = User.query.order_by(User.username).all()
    return render_template('manage_users.html', user=current_user, all_users=all_users)
    
@app.route('/admin/feedback')
@login_required
def manage_feedback():
    if current_user.role != 'admin':
        flash('Access denied. You do not have admin privileges.', 'danger')
        return redirect(url_for('home'))

    all_feedback = Feedback.query.order_by(Feedback.timestamp.desc()).all()
    return render_template('manage_feedback.html', user=current_user, all_feedback=all_feedback)

@app.route('/admin/checks')
@login_required
def manage_checks():
    if current_user.role != 'admin':
        flash('Access denied. You do not have admin privileges.', 'danger')
        return redirect(url_for('home'))
    
    all_checks = URLCheck.query.order_by(URLCheck.timestamp.desc()).all()
    return render_template('manage_checks.html', user=current_user, all_checks=all_checks)

@app.route('/add_user_by_admin', methods=['POST'])
@login_required
def add_user_by_admin():
    if current_user.role != 'admin':
        app.logger.warning(f"Non-admin user '{current_user.username}' attempted to add a user.")
        return jsonify({"error": "Access denied"}), 403

    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    username = data.get('username')
    role = data.get('role', 'client')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 409

    import secrets
    import string
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(12))

    try:
        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        app.logger.info(f"Admin '{current_user.username}' added new user '{username}' with role '{role}'.")
        return jsonify({
            "message": f"User {username} added successfully. Initial password: {password}",
            "username": username,
            "password": password
        }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding new user by admin: {e}", exc_info=True)
        return jsonify({"error": "Failed to add user"}), 500

@app.route('/remove_user', methods=['POST'])
@login_required
def remove_user():
    if current_user.role != 'admin':
        app.logger.warning(f"Non-admin user '{current_user.username}' attempted to remove a user.")
        return jsonify({"error": "Access denied"}), 403
    
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.get_json()
    user_id_to_remove = data.get('user_id')

    if not user_id_to_remove:
        return jsonify({"error": "User ID is required"}), 400
    
    user_to_remove = User.query.get(user_id_to_remove)

    if not user_to_remove:
        return jsonify({"error": "User not found"}), 404
    
    if user_to_remove.id == current_user.id:
        app.logger.warning(f"Admin '{current_user.username}' attempted to delete their own account.")
        return jsonify({"error": "Cannot delete your own account"}), 403

    try:
        db.session.delete(user_to_remove)
        db.session.commit()
        app.logger.info(f"Admin '{current_user.username}' successfully removed user '{user_to_remove.username}'.")
        return jsonify({"message": f"User {user_to_remove.username} removed successfully"}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error removing user '{user_to_remove.username}': {e}", exc_info=True)
        return jsonify({"error": "Failed to remove user"}), 500
        
@app.route('/admin/reply_feedback', methods=['POST'])
@login_required
def admin_reply_feedback():
    if current_user.role != 'admin':
        return jsonify({"error": "Access denied"}), 403
    
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.get_json()
    feedback_id = data.get('feedback_id')
    admin_reply = data.get('admin_reply')
    
    if not feedback_id or not admin_reply:
        return jsonify({"error": "Feedback ID and reply are required"}), 400
    
    feedback_entry = Feedback.query.get(feedback_id)
    if not feedback_entry:
        return jsonify({"error": "Feedback not found"}), 404
    
    try:
        feedback_entry.admin_reply = admin_reply
        feedback_entry.status = 'reviewed'
        db.session.commit()
        app.logger.info(f"Admin '{current_user.username}' replied to feedback ID {feedback_id}.")
        return jsonify({"message": "Reply submitted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error submitting admin reply for feedback ID {feedback_id}: {e}", exc_info=True)
        return jsonify({"error": "Failed to submit reply"}), 500

@app.route('/check_url', methods=['POST'])
@login_required
def check_url():
    if request.is_json:
        data = request.get_json()
        url = data.get('url')

        if not url:
            app.logger.warning(f"User '{current_user.username}' submitted empty URL check request.")
            return jsonify({"error": "URL is required"}), 400

        app.logger.info(f"User '{current_user.username}' submitted URL for check: '{url}'")

        result = analyze_url_heuristics(url)

        try:
            new_check = URLCheck(
                url=result['url'],
                status=result['status'],
                confidence=result['confidence'],
                score=result['score'],
                reason=result['reason'],
                user_id=current_user.id
            )
            db.session.add(new_check)
            db.session.commit()
            flash('URL check saved to history.', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error saving URL check for '{url}' by '{current_user.username}' to database: {e}")
            flash('Error saving URL check to history.', 'danger')

        return jsonify(result)
    app.logger.warning(f"Non-JSON request to /check_url by user '{current_user.username}' from IP: {request.remote_addr}")
    return jsonify({"error": "Request must be JSON"}), 400
# app.py

# ... (after the check_url route) ...

@app.route('/submit_feedback', methods=['POST'])
@login_required
def submit_feedback():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.get_json()
    feedback_text = data.get('feedbackText')
    url_submitted = data.get('urlSubmitted')

    if not feedback_text:
        app.logger.warning(f"User '{current_user.username}' tried to submit empty feedback.")
        return jsonify({"error": "Feedback text is required"}), 400
    
    app.logger.info(f"User '{current_user.username}' submitted feedback for URL: '{url_submitted}'")

    try:
        new_feedback = Feedback(
            user_id=current_user.id,
            url_submitted=url_submitted,
            feedback_text=feedback_text
        )
        db.session.add(new_feedback)
        db.session.commit()
        app.logger.info(f"Feedback submitted successfully by '{current_user.username}'. Feedback ID: {new_feedback.id}")
        return jsonify({"message": "Feedback submitted successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error submitting feedback by '{current_user.username}': {e}")
        return jsonify({"error": "Error submitting feedback."}), 500
    

# --- Run the App ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', role='admin')
            admin_user.set_password('adminpass')
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("Default admin user created.")

        if not User.query.filter_by(username='client').first():
            client_user = User(username='client', role='client')
            client_user.set_password('clientpass')
            db.session.add(client_user)
            db.session.commit()
            app.logger.info("Default client user created.")

    app.run(debug=True)