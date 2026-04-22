from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from . import db

# 🧠 User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    # Relationship with ScanHistory
    scans = db.relationship('ScanHistory', backref='user', lazy=True)


# 📊 Scan History Model
class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    scan_type = db.Column(db.String(50))       # password / url / ai
    input_data = db.Column(db.String(300))
    result = db.Column(db.String(500))
    risk_score = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
