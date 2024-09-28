from flask_sqlalchemy import SQLAlchemy
from main import app, db

with app.app_context():
    # Drop all tables
    db.drop_all()
    # Recreate tables
    db.create_all()
    print("Database cleared and tables recreated.")
