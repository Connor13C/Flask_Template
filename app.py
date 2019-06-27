import os

from dotenv import load_dotenv
from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager
from marshmallow import ValidationError

from resources.user import UserRegister, Users, UserLogin, UserLogout, TokenRefresh, UserUnregister
from blacklist import BLACKLIST
from resources.front_page import FrontPage


app = Flask(__name__)
load_dotenv(".env")
app.config.from_object("default_config")
app.config.from_envvar("APPLICATION_SETTINGS")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
api = Api(app)
jwt = JWTManager(app)


@app.errorhandler(ValidationError)
def handle_marshmallow_validation(err):
    return jsonify(err.messages), 400


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return decrypted_token["jti"] in BLACKLIST


api.add_resource(UserRegister, '/register')
api.add_resource(UserUnregister, '/unregister')
api.add_resource(Users, '/users')
api.add_resource(UserLogin, '/login')
api.add_resource(TokenRefresh, '/refresh')
api.add_resource(UserLogout, '/logout')
api.add_resource(FrontPage, '/')

if __name__ == "__main__":
    from db import db
    from ma import ma
    db.init_app(app)
    ma.init_app(app)
    db.create_all(app=app)
    app.run(port=5000, debug=True)
