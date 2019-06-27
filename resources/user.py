from flask_restful import Resource
from flask import request
from werkzeug.security import safe_str_cmp
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    get_raw_jwt,
    jwt_required,
    jwt_refresh_token_required
)
from libs.strings import gettext
from models.user import UserModel
from schemas.user import UserSchema
from blacklist import BLACKLIST

user_schema = UserSchema()


class UserRegister(Resource):
    @classmethod
    def post(cls):
        user_json = request.get_json()
        user = user_schema.load(user_json)

        if UserModel.find_by_username(user.username):
            return {"message": gettext("user_username_exists")}, 400

        user.save_to_db()

        return {"message": gettext("user_registered").format(user.username)}, 201


class UserUnregister(Resource):
    @classmethod
    @jwt_required
    def delete(cls):
        jwt_id = get_jwt_identity()
        user = UserModel.find_by_id(jwt_id)
        if not user:
            return {"message": gettext("user_not_found")}, 404
        jti = get_raw_jwt()['jti']
        BLACKLIST.add(jti)
        user.delete_from_db()
        return {"message": gettext("user_deleted").format(user.username)}, 200


class Users(Resource):
    """
    This resource can be useful when testing our Flask app. We may not want to expose it to public users, but for the
    sake of demonstration in this course, it can be useful when we are manipulating data regarding the users.
    """
    @classmethod
    @jwt_required
    def get(cls):
        users = UserModel.get_all_users()
        return [user_schema.dump(user) for user in users], 200


class UserLogin(Resource):
    @classmethod
    def post(cls):
        user_json = request.get_json()
        user_data = user_schema.load(user_json)

        user = UserModel.find_by_username(user_data.username)

        if user and safe_str_cmp(user.password, user_data.password):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {"access_token": access_token, "refresh_token": refresh_token}, 200

        return {"message": gettext("user_invalid_credentials")}, 401


class UserLogout(Resource):
    @classmethod
    @jwt_required
    def post(cls):
        jti = get_raw_jwt()['jti']
        BLACKLIST.add(jti)
        user = UserModel.find_by_id(get_jwt_identity())
        return {'message': gettext("user_logged_out").format(user.username)}, 200


class TokenRefresh(Resource):
    @classmethod
    @jwt_refresh_token_required
    def post(cls):
        jwt_id = get_jwt_identity()
        user = UserModel.find_by_id(jwt_id)
        if not user:
            return {"message": gettext("user_invalid_credentials")}, 401
        new_token = create_access_token(identity=jwt_id, fresh=False)
        return {'access_token': new_token}
