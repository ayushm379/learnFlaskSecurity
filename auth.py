from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt, current_user, get_jwt_identity
from models import User
from schemas import UserSchema

auth_bp = Blueprint('auth', __name__)

@auth_bp.post('/register')
def regsiter_user():
    data = request.get_json()
    existing_user = User.get_user_by_username(username=data.get('username'))

    if existing_user != None:
        return jsonify({
            'message': 'User Already Exists'
        }), 403
    
    new_user = User(
        username = data.get('username'),
        email = data.get('email')
    )

    new_user.encode_password(password=data.get('password'))
    new_user.save()

    return jsonify({
        'message': 'User Created'
    }), 201

@auth_bp.post('/login')
def login_user():
    data = request.get_json()

    user = User.get_user_by_username(username=data.get('username'))
    if user == None or not user.check_password(data.get('password')):
         return jsonify({
            'message': 'Incorrect Credentials'
        }), 400
    
    access_token = create_access_token(identity=user.username)
    refresh_token = create_refresh_token(identity=user.username)

    return jsonify({
        'message': 'logged in successfully',
        'tokens': {
            'access': access_token,
            'refresh': refresh_token
        }
    }), 200

@auth_bp.get('/self')
@jwt_required()
def who_am_i():
    userSchema = UserSchema().dump(current_user)
    return jsonify({
        "jwt_data": userSchema
    })


@auth_bp.get('/refresh')
@jwt_required(refresh=True)
def refresh_access_token():
    identity = get_jwt_identity()

    access_token = create_access_token(identity=identity)
    refresh_token = create_refresh_token(identity=identity)

    return jsonify({
        'message': "token refreshed successfully",
        'tokens': {
            'access': access_token,
            'refresh': refresh_token
        }
    })
