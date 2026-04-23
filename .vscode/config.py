import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-super-secret-key-change-in-production-2024'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///threatlens.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # Flask-Login
    SESSION_PERMANENT = False
    PERMANENT_SESSION_LIFETIME = 3600
    LOGIN_DISABLED = True
    
    # Rate limiting 
    RATELIMIT_ENABLED = True
    
    # OpenAI
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY') or None
