from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os

# Load environment variables from a .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///firewall.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Policy(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    application_name = db.Column(db.String(80), nullable=False)
    domains = db.Column(db.String(255), nullable=False)
    ip_addresses = db.Column(db.String(255), nullable=False)
    protocols = db.Column(db.String(255), nullable=False)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    source_ip = db.Column(db.String(50), nullable=False)
    destination_ip = db.Column(db.String(50), nullable=False)
    protocol = db.Column(db.String(10), nullable=False)
    application_name = db.Column(db.String(80), nullable=False)

# Create the database and tables
with app.app_context():
    db.create_all()

# Default admin credentials
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", 'admin')
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", generate_password_hash('adminpassword', method='sha256'))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['username'] = username
            return redirect(url_for('user_selection'))
        else:
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                session['username'] = username
                return redirect(url_for('console'))
            else:
                return 'Invalid credentials'
    
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    if 'username' not in session or session['username'] != ADMIN_USERNAME:
        return redirect(url_for('login'))

    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if not username or not password or not confirm_password:
        return render_template('admin_console.html', error_message="All fields are required", success_message="")

    if password != confirm_password:
        return render_template('admin_console.html', error_message="Passwords do not match", success_message="")

    # Check if user already exists
    if User.query.filter_by(username=username).first():
        return render_template('admin_console.html', error_message="Username already exists", success_message="")

    # Hash the password and save user to database
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return render_template('admin_console.html', success_message="User registered successfully", error_message="")



@app.route('/user_selection', methods=['GET', 'POST'])
def user_selection():
    if 'username' not in session or session['username'] != ADMIN_USERNAME:
        return redirect(url_for('login'))

    if request.method == 'POST':
        selected_user = request.form['user']
        
        if selected_user == ADMIN_USERNAME:
            return redirect(url_for('console', username=selected_user))
        else:
            # Redirect to the admin_user console with the selected user
            return redirect(url_for('admin_user_console', username=selected_user))
    
    users = User.query.with_entities(User.username).all()
    user_list = [user[0] for user in users]
    
    return render_template('user_selection.html', users=user_list)

@app.route('/admin_user_console')
def admin_user_console():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    selected_user = request.args.get('username')
    
    if selected_user != ADMIN_USERNAME:
        policies = Policy.query.all()
        logs = Log.query.all()
        return render_template('admin_user.html', policies=policies, logs=logs, admin=False)
    
    # Fallback to the general console if the user is somehow not recognized
    return redirect(url_for('console', username=selected_user))


@app.route('/console')
def console():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = request.args.get('username', session['username'])
    
    if user == ADMIN_USERNAME:
        policies = Policy.query.all()
        logs = Log.query.all()
        return render_template('admin_console.html', policies=policies, logs=logs, admin=True)
    else:
        policies = Policy.query.all()
        logs = Log.query.all()
        return render_template('user_console.html', policies=policies, logs=logs, admin=False)



@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/add_policy', methods=['POST'])
def add_policy():
    if 'username' not in session or session['username'] != ADMIN_USERNAME:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.form
    policy = Policy(
        application_name=data['application_name'],
        domains=data['domains'],
        ip_addresses=data['ip_addresses'],
        protocols=data['protocols']
    )
    db.session.add(policy)
    db.session.commit()
    return jsonify({"status": "Policy added"}), 201

@app.route('/policies', methods=['GET'])
def policies():
    policies = Policy.query.all()
    policies_list = [
        {"application_name": p.application_name, "domains": p.domains, "ip_addresses": p.ip_addresses, "protocols": p.protocols}
        for p in policies
    ]
    search_query = request.args.get('search')
    if search_query:
        policies_list = [p for p in policies_list if search_query.lower() in p['application_name'].lower()]
    return jsonify(policies_list)

@app.route('/logs', methods=['GET'])
def logs():
    logs = Log.query.all()
    logs_list = [
        {"source_ip": l.source_ip, "destination_ip": l.destination_ip, "protocol": l.protocol, "application_name": l.application_name}
        for l in logs
    ]
    return jsonify(logs_list)

@app.route('/anomalies', methods=['GET'])
def anomalies():
    # This is a placeholder for actual anomaly detection logic
    return jsonify({"anomalies": "No anomalies detected"})  # Modify according to your anomaly detection implementation

if __name__ == '__main__':
    app.run(debug=False)
