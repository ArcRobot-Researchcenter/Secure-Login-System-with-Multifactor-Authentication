from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .config import Config

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Basic rate limiter
    limiter = Limiter(get_remote_address, app=app, default_limits=[])

    from .auth import auth_bp
    app.register_blueprint(auth_bp)

    with app.app_context():
        from . import models  # register models
        db.create_all()

    login_manager.login_view = "auth.login"
    return app
