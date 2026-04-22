from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    global db, login_manager
    app = Flask(__name__, template_folder='../templates')

    app.config.from_object("config.Config")
    
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
    
    @app.errorhandler(404)
    def not_found(error):
        return 'Page not found', 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return "Server error", 500

    return app
