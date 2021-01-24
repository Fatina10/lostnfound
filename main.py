import json
from flask import Flask, jsonify, request, Response, session, g, abort
from flask_restful import Api
from flask_marshmallow import Marshmallow
from marshmallow import fields, validate
from flask_rest_paginate import Pagination
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_script import Manager
from flask_httpauth import HTTPBasicAuth
import jwt
from flask_migrate import Migrate, MigrateCommand
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'secret'

# CONFIGURING DATABASES
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://test1:Testing123!@#@localhost/trying'
app.config['DEBUG'] = True
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

# CONFIGURING FLASK MAIL
app.config['TESTING'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'zubizubidoo1122@gmail.com'
app.config['MAIL_PASSWORD'] = 'testinglostnfound1122'
app.config['MAIL_DEFAULT_SENDER'] = 'zubizubidoo1122@gmail.com'
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_ASCII_ATTACHMENTS'] = False

migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)
ma = Marshmallow(app)
pagination = Pagination(app, db)
mail = Mail(app)


# MODELS
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    items = db.relationship('Item', backref='user', lazy='dynamic')
    claims = db.relationship('Claims', backref='user', lazy='dynamic')

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def hash_password(self, password):
        self.password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)


class Item(db.Model):
    __tablename__ = 'items'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    questions = db.Column(db.JSON)
    claims = db.relationship('Claims', backref='item', lazy='dynamic')

    def __init__(self, name, description, user_id, questions):
        self.name = name
        self.description = description
        self.user_id = user_id
        self.questions = questions

    def to_json(self):
        return {
            "name": self.name,
            "description": self.description,
            "user_id": self.user_id,
            "questions": self.questions,
        }


class Claims(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    answers = db.Column(db.JSON)
    approval = db.Column(db.Boolean, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'), nullable=False)

    def __init__(self, answers, approval, user_id, item_id):
        self.answers = answers
        self.approval = approval
        self.user_id = user_id
        self.item_id = item_id


# MODELS SCHEMA
class UserSchema(ma.Schema):
    username = fields.Str(required=True, validate=[validate.Length(min=5, max=20)])
    email = fields.Email(required=True, validate=[validate.Length(min=15, max=120)])
    password = fields.Str(required=True, validate=[validate.Length(min=8, max=120)])

    class Meta:
        model = User


class ItemSchema(ma.Schema):
    name = fields.Str(required=True, validate=[validate.Length(min=3, max=120)])
    description = fields.Str(required=True, validate=[validate.Length(min=8, max=300)])

    class Meta:
        model = Item


class ClaimsSchema(ma.Schema):
    approval = fields.Boolean(required=False)

    class Meta:
        model = Claims


users_schema = UserSchema(many=True)
items_schema = ItemSchema(many=True)
claims_schema = ClaimsSchema(many=True)


# Routes
""" API for creating user account """


@app.route('/registration', methods=['POST'])
def register():
    user_name = request.json.get('username')
    email_address = request.json.get('email')
    password = request.json.get('password')

    # Ensuring that all the fields are being input by the user according to the schema's requirements
    if user_name is None or email_address is None or password is None:
        return jsonify("Missing fields!"), 400
    if len(user_name) < 5 or len(user_name) > 20:
        return jsonify("Username must be between 5 and 20 characters!"), 400
    if len(email_address) < 15 or len(email_address) > 120:
        return jsonify('email must be between 15 and 120 characters'), 400
    if len(password) < 8 or len(password) > 120:
        return jsonify('password must be between 8 and 120 characters'), 400

    # Ensuring that the user does not already exist
    user_name_check = User.query.filter_by(username=user_name).first()
    email_check = User.query.filter_by(email=email_address).first()
    if user_name_check or email_check:
        return jsonify("User already exists!"), 409

    # creating the user and saving to database
    user = User(username=user_name, email=email_address, password=password)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'This user was registered!': user.username}), 201


""" API for user login """


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    # Ensuring that username and password are both input
    if not (username and password):
        return jsonify("Please enter both username AND password!"), 400

    # checking if the user even exists
    existing_user = User.query.filter_by(username=username).first()
    if not existing_user:
        return jsonify("User does not exist!"), 404

    # checking if the password matches
    if not existing_user.verify_password(password):
        return jsonify("Wrong Password!"), 401
    session['user_id'] = existing_user.id
    session['logged_in'] = True
    return jsonify({"msg": "Login successful"})


"""API for adding items """


@app.route('/add_items', methods=["POST"])
def add_item():
    name = request.json['name']       # login required
    item_description = request.json['description']
    user_identity = session['user_id']
    json_questions = request.json.get("questions", {})
    if not user_identity:
        return jsonify("Login required!"), 401

    for key, val in json_questions.items():
        if not key.isnumeric():
            return jsonify("Each key should be an integer"), 400
        if not isinstance(val, str):
            return jsonify("Each value should be a string"), 400

    if json_questions and not isinstance(json_questions, dict):
        return jsonify("Please enter questions in the form of a dictionary!"), 400
    if name is None or item_description is None or json_questions is None:
        return jsonify("Please enter name, description AND questions!"), 400

    new_item = Item(name, item_description, user_identity, json_questions)
    db.session.add(new_item)
    db.session.commit()
    return jsonify("New item added"), 201


"""" API for removing items """""


@app.route('/remove_items/<int:item_id>', methods=['DELETE'])
def remove_item(item_id):
    user = session['user_id']
    item = Item.query.get(id)
    if item is None:
        return jsonify("Item does not exist"), 404
    item_by = db.session.query(Item.user_id).filter_by(id=id).first()
    if not user:
        return jsonify("login required"), 401
    user_id = item_by.user_id
    if user_id != user:
        return jsonify("Not Authorized"), 401
    db.session.delete(item)
    db.session.commit()
    return jsonify("Item Deleted!"), 200


""""" API for claiming an item """""


@app.route('/claims/<int:item_id>', methods=['POST'])
def claim_item(item_id):
    item = Item.query.get(item_id)
    if item is None:
        return jsonify("Item does not exist"), 404

    user = session['user_id']
    user_mail = db.session.query(User.email).filter_by(id=user).first()
    user_email = user_mail.email
    item_dude = item.user
    item_questions = item.questions.all()
    questions = item_questions.questions
    if item.user_id == user:
        return jsonify("Not Authorized"), 401
    msg = Message('You must answer these questions in the asked '
                  'order to claim this item', recipients=[user_email])
    msg.body = questions
    mail.send(msg)

    notification = Message('The item was claimed!', recipients=[item_dude.email])
    notification.body = f"The item '{item_id}' was claimed  by the user '{user}' " \
                        f"You will be notified when the user answers the questions for you to approve"

    mail.send(notification)
    return jsonify("Item was claimed!"), 200


"""""  API to add answers """""


@app.route('/add_answers/<int:item_id>', methods=["POST"])
def add_answers(item_id):
    item = Item.query.get(item_id)
    if item is None:
        return jsonify("This item does not exist"), 404
    session_user = session['user_id']
    if item.user_id == session_user:
        return jsonify("Not Authorized"), 401
    answers = request.json.get("answers")
    if answers is None:
        return jsonify("You must answer the questions"), 400
    if not isinstance(answers, dict):
        return jsonify("Value for key 'answers' should be a dictionary"), 400

    for key, val in answers.items():
        if not key.isnumeric():
            return jsonify("Each key should be an integer"), 400
        if not isinstance(val, str):
            return jsonify("Each value should be a string"), 400

    # check to ensure all questions are answered
    questions = item.questions
    if len(questions) > len(answers):
        return jsonify("You must answer all the questions!"),  400  # check status code
    if len(answers) > len(questions):
        return jsonify("Oops! The number of answers do not match the number of questions!"), 400

    answers = Claims(answers=answers, approval=None, item_id=item.id, user_id=session_user)
    db.session.add(answers)
    db.session.commit()
    questions = item.questions
    question_val = questions.values()
    claim = Claims.query.filter_by(id=item_id).first()
    answers = claim.answers
    answers_val = answers.values()
    result = {}
    for k, v in zip(question_val, answers_val):
        result[k] = v
    msg = Message('Answers added', recipients=[item.user.email])
    msg.body = f"The item '{item.name}' was claimed by user '{session_user}'." \
        f"The answers provided were '{result}'"
    mail.send(msg)

    user = User.query.filter_by(id=session_user).first()
    a_user = user.email
    notification = Message('Your answers were submitted!', recipients=[a_user])
    notification.body = f"Your answers for the item:  '{item.name}' have been submitted to  " \
                        f"'{item.user.email}'. Please wait for their response"
    mail.send(notification)

    return jsonify("Answers submitted!")


@app.route('/update_questions/<int:item_id>', methods=["POST"])
def update_questions(item_id):
    itm = Item.query.get(item_id)
    q = db.session.query(Item.questions).filter_by(id=item_id).first()
    item = db.session.query(Item).filter_by(id=item_id).first()
    if itm is None:
        return jsonify("This item does not exist"), 404
    session_user = session['user_id']
    if session_user is None:
        return jsonify("Login required"), 401
    if itm.user_id != session_user:
        return jsonify("Not Authorized"), 401
    qts = q.questions
    questions = request.json.get("questions")
    if questions is None:
        return jsonify("Missing data"), 400
    qts.update(questions)
    updated = Item(name=item.name, description=item.description, user_id=item.user_id, questions=qts)
    db.session.add(updated)
    db.session.commit()
    return jsonify("The questions have been updated!")


@app.route('/approval/<int:item_id>', methods=["POST"])
def approval(item_id):

    approval_status = request.json.get("approval")
    if not isinstance(approval_status, bool):
        return jsonify("approval can either be True or False"), 400
    if approval_status is None:
        return jsonify("Missing field!"), 400
    apr = db.session.query(Claims).filter_by(id=item_id).first()
    session_user = session['user_id']
    if apr.user_id == session_user:
        return jsonify("Not authorised"), 401
    approve = Claims(answers=apr.answers, approval=approval_status, item_id=item_id, user_id=apr.user_id)
    db.session.add(approve)
    db.session.commit()
    # send email to users
    return jsonify("Your response was submitted!")


# MAIN
if __name__ == '__main__':
    app.run(debug=True)
