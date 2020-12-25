import json

from flask import Flask, jsonify, request, Response
from flask_marshmallow import Marshmallow
from flask_rest_paginate import Pagination
from flask_sqlalchemy import SQLAlchemy

# from flask_paginate import Pagination, get_page_args

app = Flask(__name__)

####### CONFIGURING DATABASES #######

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://test1:Testing123!@#@localhost/trying'

db = SQLAlchemy(app)
ma = Marshmallow(app)
pagination = Pagination(app, db)


####### MODELS ##########

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    items = db.relationship('Item', backref='user', lazy='dynamic')

    def __init__(self, username, email, image_file, password):
        self.username = username
        self.email = email
        self.image_file = image_file
        self.password = password


class Item(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, name, description, user_id):
        self.name = name
        self.description = description
        self.user_id = user_id

    def to_json(self):
        return {
            "name": self.name,
            "description": self.description,
            "user_id": self.user_id
        }


##### MODELS SCHEMA ######
class userSchema(ma.Schema):
    class Meta:
        fields = ("username", "password")


class itemsSchema(ma.Schema):
    class Meta:
        fields = ("id", "name", "description", "user_id")


users_schema = userSchema()
items_schema = itemsSchema()

users_schema12 = userSchema(many=True)
items_schema12 = itemsSchema(many=True)


########## ROUTES ##########

@app.route('/Registration', methods=['POST'])
def register():
    user_name = request.json['username']
    email_address = request.json['email']
    image_file = request.json['image_file']
    passcode = request.json['password']
    existing_user = User.query.filter_by(username=user_name).first()
    if existing_user:
        return jsonify(message="user already exists!"), 409
    else:
        new_user = User(user_name, email_address, image_file, passcode)
        db.session.add(new_user)
        db.session.commit()
        return Response(status=200)


@app.route('/Login', methods=['POST'])
def login():
    uname = request.json['username']
    pswd = request.json['password']
    existing_user = User.query.filter_by(username=uname).first()
    if existing_user:
        if existing_user.password == pswd:
            return users_schema.jsonify(existing_user)
        else:
            return Response(status=401)
    else:
        return Response(status=404)


@app.route('/addItems', methods=["POST"])
def add_item():
    new_item = request.json['name']
    item_description = request.json['description']
    user_identity = request.json['user_id']
    new_item = Item(new_item, item_description, user_identity)
    db.session.add(new_item)
    db.session.commit()
    return jsonify("New item added")


@app.route('/remove_items/<id>', methods=['DELETE'])
def remove_item(id):
    item = Item.query.get(id)
    if item:
        db.session.delete(item)
        db.session.commit()
        return Response(status=200)
    else:
        return Response(status=404)


@app.route('/search', methods=['GET'])
def search():
    item_id = request.json["id"]
    search_id = "%{}%".format(item_id)
    name = request.json["name"]
    search_name = "%{}%".format(name)
    desc = request.json["description"]
    search_desc = "%{}%".format(desc)

    if item_id:
        new_result = []
        results = db.session.query(Item).filter(Item.id.like(search_id)).all()
        for i in results:
            new_result.append({
                "id": i.id,
                "name": i.name,
                "description": i.description
            })
        return jsonify(new_result)
    elif name:
        new_result = []
        results = db.session.query(Item).filter(Item.name.like(search_name)).all()
        for i in results:
            new_result.append({
                "id": i.id,
                "name": i.name,
                "description": i.description
            })
        return jsonify(new_result)
    elif desc:
        new_result = []
        results = db.session.query(Item).filter(Item.description.like(search_desc)).all()
        for i in results:
            new_result.append({
                "id": i.id,
                "name": i.name,
                "description": i.description
            })
        return jsonify(new_result)
    else:
        return jsonify(message="0 matching results...")

# @app.route('/claim', methods=['POST'])


############## MAIN ################

if __name__ == '__main__':
    app.run(debug=True)
