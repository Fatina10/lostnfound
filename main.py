import re
import time
from flask import Flask, jsonify, request, Response, session, g, abort
from flask_restful import Api
from flask_marshmallow import Marshmallow
from marshmallow.validate import Length
from flask_rest_paginate import Pagination
from flask_sqlalchemy import SQLAlchemy
from flask_script import Manager
from flask_httpauth import HTTPBasicAuth
import jwt
from flask_migrate import Migrate, MigrateCommand
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_mail import Mail, Message
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import validates

app = Flask(__name__)
app.secret_key = 'secret'

# CONFIGURING DATABASES
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://test1:Testing123!@#@localhost/trying'
app.config['DEBUG'] = True
db = SQLAlchemy(app)
auth = HTTPBasicAuth()
api = Api(app)


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
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(128))
    items = db.relationship('Item', backref='user', lazy='dynamic')
    questions = db.relationship('Questions', backref='user', lazy='dynamic')
    answers = db.relationship('Answers', backref='user', lazy='dynamic')

    def __init__(self, username, email, image_file):
        self.username = username
        self.email = email
        self.image_file = image_file


    def hash_password(self, password):
        self.password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode(
            {'id': self.id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    def set_password(self, password):
        if not password:
            return jsonify('Password not provided'), 403
        if not re.match('\d.*[A-Z]|[A-Z].*\d', password):
            return jsonify('Password must contain 1 capital letter and 1 number'), 403
        if len(password) < 8 or len(password) > 50:
            return jsonify('Password must be between 8 and 120 characters'), 403
        self.password = generate_password_hash(password)


    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                              algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])

    @validates('username')
    def validate_username(self, key, username):
        if not username:
            return jsonify('No username provided'), 403
        if User.query.filter(User.username == username).first():
            return jsonify('Username is already in use'), 409
        if len(username) < 5 or len(username) > 20:
            return jsonify('Username must be between 5 and 20 characters'), 403
        return username

    @validates('email')
    def validate_email(self, key, email):
        if not email:
            return jsonify('No email provided'), 403
        if User.query.filter(User.email == email).first():
            return jsonify('email is already in use'), 409
        if len(email) < 5 or len(email) > 201:
            return jsonify('email must be between 5 and 120 characters'), 403
        if not re.match("[^@]+@[^@]+\.[^@]+", email):
            return jsonify('Provided email is not an email address'), 403
        return email


class Item(db.Model):
    __tablename__ = 'items'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    questions = db.relationship(
        'Questions', backref='item', lazy='dynamic', cascade="delete, merge, save-update")
    images = db.relationship('Img', backref='item', lazy='dynamic')

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


class Questions(db.Model):
    __tablename__ = 'questions'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    questions = db.Column(db.String(120), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'), nullable=False)
    answers = db.relationship('Answers', backref='question', lazy='dynamic', cascade="delete, merge, save-update")
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, questions, item_id, user_id):
        self.questions = questions
        self.item_id = item_id
        self.user_id = user_id

    def to_json(self):
        return {
            "questions": self.questions,
            "item_id": self.item_id
        }


class Answers(db.Model):
    __tablename__ = 'answers'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    answers = db.Column(db.String(120), nullable=False)
    approval = db.Column(db.Boolean)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, answers, question_id, approval, user_id):
        self.answers = answers
        self.question_id = question_id
        self.approval = approval
        self.user_id = user_id

    def to_json(self):
        return {
            "answers": self.answers,
            "question_id": self.question_id
        }


class Img(db.Model):
    __tablename__ = 'images'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    img = db.Column(db.LargeBinary(length=(2 ** 24) - 1), nullable=False)
    name = db.Column(db.Text, nullable=False)
    mimetype = db.Column(db.Text, nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('items.id', ondelete="CASCADE"), nullable=False)

    def __init__(self, img, name, mimetype, item_id):
        self.img = img
        self.name = name
        self.mimetype = mimetype
        self.item_id = item_id


# MODELS SCHEMA

class UserSchema(ma.Schema):
    class Meta:
        fields = ("username", "password")


class ItemSchema(ma.Schema):
    class Meta:
        fields = ("id", "name", "description", "questions", "user_id")


class QuestionSchema(ma.Schema):
    class Meta:
        fields = ("questions", "item_id")


class AnswerSchema(ma.Schema):
    class Meta:
        fields = ("answers", "approval", "question_id")


class ImageSchema(ma.Schema):
    class Meta:
        fields = ("id", "img", "name", "mimetype", "item_id")


users_schema = UserSchema()
items_schema = ItemSchema()
questions_schema = QuestionSchema()
answers_schema = AnswerSchema()
images_schema = ImageSchema()

users_schema12 = UserSchema(many=True)
items_schema12 = ItemSchema(many=True)
questions_schema12 = QuestionSchema(many=True)
answers_schema12 = AnswerSchema(many=True)
images_schema12 = ImageSchema(many=True)


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return jsonify("Login required. No active session"), 403
    return wrap


def prevent_login_signup(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get('user_id'):
            return jsonify("Please log out first ..."), 400
        return f(*args, **kwargs)
    return wrap


def ensure_correct_user(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        correct_id = kwargs.get('user_id')
        if correct_id != session.get('user_id'):
            return jsonify("Not Authorized"), 401
        return f(*args, **kwargs)
    return wrap


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


# ROUTES
@app.before_request
def current_user():
    if session.get('user_id'):
        g.current_user = User.query.get(session['user_id'])
    else:
        g.current_user = None


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


@app.route('/Registration', methods=['POST'])
def register():
    user_name = request.json.get('username')
    email_address = request.json.get('email')
    image_file = request.json.get('image_file')
    password = request.json.get('password')

    user = User(username=user_name, email=email_address, image_file=image_file)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'username': user.username}), 201


    # except AssertionError as exception_message:
    #     return jsonify(msg='Error: {}. '.format(exception_message)), 400


@app.route('/login', methods=['GET'])
@prevent_login_signup
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username and not password:
        return jsonify("Missing username and password"), 400

    if not username:
        return jsonify("missing username!"), 400

    if not password:
        return jsonify("missing password!"), 400

    existing_user = User.query.filter_by(username=username).first()

    if not existing_user:
        return jsonify("User does not exist!"), 404

    if not existing_user.verify_password(password):
        return jsonify( "Wrong Password!"), 401

    session['user_id'] = existing_user.id
    session['logged_in'] = True
    # app.permanent_session_lifetime = timedelta(minutes=5)
    return jsonify({"msg": "Login successful"})


@app.route('/addItems', methods=["POST"])
@login_required
def add_item():
    new_item = request.json['name']
    item_description = request.json['description']
    user_identity = session['user_id']
    if new_item is None or item_description is None or user_identity is None:
        abort(400)
    new_item = Item(new_item, item_description, user_identity)
    db.session.add(new_item)
    db.session.commit()
    return jsonify("New item added"), 201


@app.route('/remove_items/<int:id>/<int:user_id>', methods=['DELETE'])
@login_required
@ensure_correct_user
def remove_item(id, user_id):
    item = Item.query.get(id)
    user_id = db.session.query(Item.user_id).filter_by(id=id).first()
    user_id = user_id.user_id
    if item:
        db.session.delete(item)
        db.session.commit()
        return jsonify("Item Deleted ..."), 200
    else:
        return jsonify("No Item with this id ..."), 404


@app.route('/questions/<int:id>/<int:user_id>', methods=['POST'])
@login_required
@ensure_correct_user
def add_questions(id, user_id):
    item = Item.query.get(id)
    user_id = db.session.query(Item.user_id).filter_by(id=id).first()
    user = session['user_id']
    print(item)
    print(user_id)
    print(user)
    json_questions = request.json['questions']
    if not json_questions:
        return jsonify("no questions"), 400
    if user_id[0] != user:
        return jsonify("Not Authorized..."), 401
    for i in json_questions:
        db.session.add(Questions(questions=i, item_id=id, user_id=user_id))
    db.session.commit()
    return jsonify("Questions added ... "), 201


@app.route('/claim/<int:id>', methods=['POST'])
@login_required
def claim_item(id):
    user = session['user_id']
    i_id = Questions.query.filter_by(item_id=id).all()
    iu_id = db.session.query(Item.user_id).filter_by(id=id).first()
    temp = []
    if not i_id:
        return jsonify("Item does not exist"), 404
    if iu_id[0] == user:
        return jsonify("Not Authorized..."), 401
    for i in range(0, len(i_id)):
        temp.append(i_id[i].questions)
    return jsonify(temp)


@app.route('/add_answers/<int:id>', methods=["POST"])
@login_required
def add_answers(id):
    q = Questions.query.get(id)
    user = session['user_id']
    u_id = db.session.query(Questions.user_id).filter_by(id=id).first()
    user_email = db.session.query(User.email).filter_by(id=u_id).first()
    print(u_id)
    print(user_email)
    if q:
        json_answers = request.json['answers']
        if not json_answers:
            return jsonify("no answers"), 400
        if u_id[0] == user:
            return jsonify("Not Authorized..."), 401
        db.session.add(Answers(answers=json_answers, question_id=id, approval=None, user_id=user))
        db.session.commit()
        msg = Message('Answers added', recipients=[user_email[0]])
        msg.body = 'This is a test'
        mail.send(msg)
        return jsonify("Answers added ... "), 201
    else:
        return jsonify("Question id does not exist"), 400


@app.route('/approval/<int:id>/<int:user_id>', methods=['POST'])
@login_required
@ensure_correct_user
def approve(id, user_id):
    ans = Answers.query.get(id)
    u_id = db.session.query(Answers.user_id).filter_by(id=id).first()
    user_email = db.session.query(User.email).filter_by(id=u_id).first()
    q_id = db.session.query(Answers.question_id).filter_by(id=id).first()
    user_id = db.session.query(Questions.user_id).filter_by(id=q_id[0]).first()
    user_id = user_id.user_id
    print(user_id)
    if ans:
        approval = request.json['approval']
        if not approval:
            Answers.query.filter_by(id=id).update(dict(approval=approval))
            db.session.commit()
            approval = "Not Approved"
            msg = Message('Response against your answers', recipients=[user_email[0]])
            msg.body = 'Your request is ' + approval
            mail.send(msg)
            return jsonify("Response has been submitted...")

        Answers.query.filter_by(id=id).update(dict(approval=approval))
        db.session.commit()
        print(approval)
        approval = "Approved"
        msg = Message('Response against your answers', recipients=[user_email[0]])
        msg.body = 'Your request is ' + approval
        mail.send(msg)
        return jsonify("Response has been submitted..."), 200


@app.route('/upload/<id>', methods=['POST'])
@login_required
@ensure_correct_user
def upload(id):
    i_id = Item.query.get(id)
    pic = request.files['pic']
    print(pic)
    if not pic:
        return 'No picture uploaded', 400

    filename = secure_filename(pic.filename)
    mimetype = pic.mimetype
    image = Img(img=pic.read(), mimetype=mimetype, name=filename, item_id=i_id.id)
    print(image, mimetype, filename, i_id.id)
    db.session.add(image)
    db.session.commit()

    return 'Img has been uploaded!', 200


@app.route('/get_img/<int:id>')
def get_img(id):
    img = Img.query.filter_by(id=id).first()
    if not img:
        return 'No image with this id', 404

    return Response(img.img, mimetype=img.mimetype)


@app.route('/logout', methods=['DELETE'])
@login_required
def logout():
    """
    closes 'logged_in' session on call.
    removes user id from session.
    :return: logout response
    """
    session.pop('logged_in', None)
    session.pop('user_id', None)
    return jsonify("logged out. Session closed"), 200


# MAIN
if __name__ == '__main__':
    app.run()