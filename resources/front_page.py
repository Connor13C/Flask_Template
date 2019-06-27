from flask_restful import Resource
from flask import render_template, make_response


class FrontPage(Resource):
    @classmethod
    def get(cls):
        return make_response(render_template('landing.html'))
