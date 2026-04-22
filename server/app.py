#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe, UserSchema, RecipeSchema

user_schema = UserSchema()
recipe_schema = RecipeSchema()
recipes_schema = RecipeSchema(many=True)

with app.app_context():
    db.create_all()


class Signup(Resource):
    def post(self):
        data = request.get_json()

        try:
            user = User(
                username=data.get("username"),
                image_url=data.get("image_url"),
                bio=data.get("bio"),
            )

            password = data.get("password")
            if not password:
                return {"errors": ["Password is required"]}, 422

            password_confirmation = data.get("password_confirmation")
            if password_confirmation is not None and password != password_confirmation:
                return {"errors": ["Password confirmation must match password"]}, 422

            user.password_hash = password

            db.session.add(user)
            db.session.commit()

            session["user_id"] = user.id

            return user_schema.dump(user), 201
        except (ValueError, IntegrityError) as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"errors": ["Unauthorized"]}, 401

        user = db.session.get(User, user_id)
        if not user:
            return {"errors": ["Unauthorized"]}, 401

        return user_schema.dump(user), 200

class Login(Resource):
    def post(self):
        data = request.get_json()

        user = User.query.filter(User.username == data.get("username")).first()

        if user and user.authenticate(data.get("password")):
            session["user_id"] = user.id
            return user_schema.dump(user), 200

        return {"errors": ["Invalid username or password"]}, 401

class Logout(Resource):
    def delete(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"errors": ["Unauthorized"]}, 401

        session.pop("user_id", None)
        return "", 204

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"errors": ["Unauthorized"]}, 401

        recipes = Recipe.query.filter(Recipe.user_id == user_id).all()
        return recipes_schema.dump(recipes), 200

    def post(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"errors": ["Unauthorized"]}, 401

        data = request.get_json()

        try:
            recipe = Recipe(
                title=data.get("title"),
                instructions=data.get("instructions"),
                minutes_to_complete=data.get("minutes_to_complete"),
                user_id=user_id,
            )

            db.session.add(recipe)
            db.session.commit()

            return recipe_schema.dump(recipe), 201
        except (ValueError, IntegrityError) as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
