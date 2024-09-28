from werkzeug.security import generate_password_hash

# Replace 'your_admin_password' with the actual password you want to use
password_hash = generate_password_hash('admin1234', method='sha256')
print(password_hash)
