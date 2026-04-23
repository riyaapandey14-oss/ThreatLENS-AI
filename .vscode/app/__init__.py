import os
from dotenv import load_dotenv
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

load_dotenv()  # Load .env vars BEFORE creating app

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    global db, login_manager
    app = Flask(__name__, template_folder='../templates')

    # Debug API key (logs to terminal)
    api_key_len = len(os.environ.get('OPENAI_API_KEY', ''))
    status = 'LOADED (len=' + str(api_key_len) + ')' if api_key_len > 10 else 'MISSING - check .env'
    print(f"🚀 [ThreatLens] OpenAI API key status: {status}")

    app.config.from_object('config.Config')
    
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    
    @login_manager.user_loader
    def load_user(user_id):
        from .models import User
        return User.query.get(int(user_id))

    from .models import User, ScanHistory
    from .routes import main
    app.register_blueprint(main)
    
    print("ThreatLens FREE AI ready - Mistral HF + Rules!")
    
    @app.errorhandler(404)
    def not_found(error):
        return 'Page not found', 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return "Server error", 500

    return app
