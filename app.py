from flask import Flask, jsonify
from extensions import db, jwt
from auth import auth_bp
from users import user_bp
from models import User

def create_app():
    app = Flask(__name__)
    # Configuring .env
    app.config.from_prefixed_env()

    # Initializing extensions
    db.init_app(app)
    jwt.init_app(app)

    # Registering Blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(user_bp, url_prefix='/user')

    # load user
    @jwt.user_lookup_loader
    def user_lookup_loader(jwt_header, jwt_data):
        identity = jwt_data['sub']
        return User.query.filter_by(username=identity).one_or_none()

    # jwt error handler
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_data):
        return jsonify({
            "message": "Token Expired"
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            "message": "Token Signature Verification Failed"
        }), 401

    @jwt.unauthorized_loader
    def unauthorize_token_callback(error):
        return jsonify({
            "message": "No Valid Token Present"
        }), 401


    return app
