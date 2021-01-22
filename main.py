import datetime
import uuid
from functools import wraps
import jwt
from flask import Flask, jsonify, request, Response, abort, make_response
from flask_mail import Mail, Message
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate, MigrateCommand
from flask_rest_paginate import Pagination
from flask_restful import Api
from flask_script import Manager
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'secret'

# CONFIGURING DATABASES
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://zubair:@Afzal262000@localhost/trying'
app.config['DEBUG'] = True
db = SQLAlchemy(app)
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
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(20), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    items = db.relationship('Item', backref='user', lazy='dynamic')
    questions = db.relationship('Questions', backref='user', lazy='dynamic')
    answers = db.relationship('Answers', backref='user', lazy='dynamic')

    def __init__(self, public_id, username, email, password):
        self.public_id = public_id
        self.username = username
        self.email = email
        self.password = password

    def hash_password(self, password):
        self.password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode(
            {'id': self.id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')


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
        self.id = Item.id
        self.name = name
        self.description = description
        self.user_id = user_id

    def to_json(self):
        return {
            "item_id": self.id,
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


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)

    return decorated

# ROUTES


@app.route('/search/item', methods=['GET'])
def search():
    name = request.args.get('name')
    search_name = "%{}%".format(name)
    desc = request.args.get('description')
    search_desc = "%{}%".format(desc)
    if name:
        new_result = []
        results = db.session.query(Item).filter(Item.name.like(search_name)).all()
        if not results:
            return jsonify("No matching results")
        for i in results:
            new_result.append(i.to_json())
        return jsonify(new_result)
    elif desc:
        new_result = []
        results = db.session.query(Item).filter(Item.description.like(search_desc)).all()
        if not results:
            return jsonify("No matching results")
        for i in results:
            new_result.append(i.to_json())
        return jsonify(new_result)
    else:
        return jsonify(message="write name or description to search the item")


@app.route('/registration', methods=['POST'])
def register():
    user_name = request.json.get('username')
    email_address = request.json.get('email')
    password = request.json.get('password')
    if user_name is None:
        return jsonify("empty Username is not allowed!"), 400
    if len(user_name) < 5 or len(user_name) > 20:
        return jsonify('Username must be between 5 and 20 characters'), 403
    if email_address is None:
        return jsonify("empty email address is not allowed!"), 400
    if len(email_address) < 5 or len(email_address) > 120:
        return jsonify('email must be between 5 and 120 characters'), 403
    if password is None:
        return jsonify("empty password is not allowed!"), 400
    hashed_password = generate_password_hash(password, method='sha256')
    user_name_check = User.query.filter_by(username=user_name).first()
    email_check = User.query.filter_by(email=email_address).first()
    if user_name_check or email_check is not None:
        return jsonify("User already exists!"), 409
    user = User(public_id=str(uuid.uuid4()), username=user_name, email=email_address, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'username': user.username}), 201


@app.route('/delete_user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})
    if user != current_user:
        return jsonify({'message': 'Cannot perform this action!'}), 401
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'user has been deleted!'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(
            minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/addItems', methods=["POST"])
@token_required
def add_item(current_user):
    new_item = request.json['name']
    item_description = request.json['description']
    if new_item is None or item_description is None or current_user is None:
        abort(400)
    new_item = Item(new_item, item_description, current_user.id)
    db.session.add(new_item)
    db.session.commit()
    return jsonify("New item added"), 201


@app.route('/remove_items/<int:id>', methods=['DELETE'])
@token_required
def remove_item(current_user, id):
    item = Item.query.get(id)
    user_item = db.session.query(Item.user_id).filter_by(id=id).first()
    if item is None:
        return jsonify("No Item with this id ..."), 404
    if user_item.user_id != current_user.id:
        return jsonify("Not Authorized ..."), 401
    db.session.delete(item)
    db.session.commit()
    return jsonify("Item Deleted ..."), 200


@app.route('/get_item/<item_id>', methods=['GET'])
@token_required
def get_item(current_user, item_id):
    i_id = Item.query.get(item_id)
    item = db.session.query(Item.user_id).filter_by(id=i_id.id).first()
    if item is None:
        return jsonify("No Item with this id ..."), 404
    ques = request.args.get('question')
    if ques:
        if ques == "True" or ques == "true" or ques == "1":
            question = db.session.query(Questions.questions).filter_by(item_id=i_id.id).first()
            user_item = db.session.query(Item.user_id).filter_by(id=i_id.id).first()
            if user_item.user_id == current_user.id:
                return jsonify("Not Authorized..."), 401
            if not question:
                return jsonify("test")
            return jsonify(question)
        else:
            return jsonify("No questions")
    else:
        return jsonify("question not found in query string"), 404


@app.route('/item/<item_id>/add_questions', methods=['POST'])
@token_required
def add_questions(current_user, item_id):
    json_questions = request.json.get("questions", {})
    if json_questions is None:
        return jsonify("no questions provided"), 400
    if json_questions and not isinstance(json_questions, dict):
        return jsonify("'questions' should be a dictionary"), 400
    for k, v in json_questions.items():
        if not k.isnumeric():
            return Response("Each key in dictionary 'json_questions' should be an int", status=400)
        if not isinstance(v, str):
            return Response("Each value in dictionary 'json_questions' should be a string", status=400)
    item = Item.query.get(item_id)
    user_item = db.session.query(Item.user_id).filter_by(id=item_id, user_id=current_user.id).first()
    if item is None:
        return jsonify("No Item with this id ..."), 404
    if user_item is None:
        return jsonify("Not Authorized..."), 401
    new_questions = Questions(json_questions, item.id, user_item.user_id)
    db.session.add(new_questions)
    db.session.commit()
    return jsonify("Questions added ... "), 201


@app.route('/add_answers/<question_id>', methods=["POST"])
@token_required
def add_answers(current_user, question_id):
    question = Questions.query.get(question_id)
    if question is None:
        return jsonify("question does not exist"), 404
    user_question = db.session.query(Questions).filter_by(id=question_id).first()
    questions = question.questions
    temp = {}
    question_dict = eval(questions)
    i_id = db.session.query(Questions).filter_by(id=question.id).first()
    item = db.session.query(Item).filter_by(id=i_id.item_id).first()
    user_id = user_question.user_id
    user = db.session.query(User.email).filter_by(id=user_id).first()
    user_email = user.email
    claim_user = User.query.get(current_user.id)
    if question:
        answers = request.json.get("answers", {})
        if answers is None:
            return Response("Key 'answers' missing in request data", status=400)
        if not isinstance(answers, dict):
            return Response("Value for key 'answers' should be a dictionary", status=400)
        for k, v in answers.items():
            if not k.isnumeric():
                return Response("Each key in dictionary 'answers' should be an int", status=400)
            if not isinstance(v, str):
                return Response("Each value in dictionary 'answers' should be a string", status=400)
        db_question_indices = set(question_dict.keys())
        answer_val = answers.values()
        question_val = question_dict.values()
        request_question_indices = set(answers.keys())
        if db_question_indices != request_question_indices:
            return Response("Question indices do not match".format(id), status=404)
        if user_id == current_user.id:
            return jsonify("Not Authorized..."), 401
        db_answers = Answers(answers=answers, approval=None, question_id=id, user_id=current_user.id)
        db.session.add(db_answers)
        db.session.commit()
        for k, v in zip(question_val, answer_val):
            temp[k] = v
        msg = Message('Answers added', recipients=[user_email])
        msg.body = f"The item '{item.name}' was claimed by user '{claim_user.email}'. The answers provided were: " \
                   f"'{temp}'"
        mail.send(msg)
    return jsonify("Answers added ... "), 201


@app.route('/approval/answer/<answer_id>', methods=['POST'])
@token_required
def approve(current_user, answer_id):
    ans_id = Answers.query.get(answer_id)
    answer = db.session.query(Answers.user_id).filter_by(id=answer_id).first()
    user_id_answer = answer.user_id
    user = db.session.query(User.email).filter_by(id=user_id_answer).first()
    user_email = user.email
    answer = db.session.query(Answers.question_id).filter_by(id=answer_id).first()
    question_id = answer.question_id
    question = db.session.query(Questions.user_id).filter_by(id=question_id).first()
    user_id_question = question.user_id
    if ans_id:
        if current_user.id == user_id_question:
            approval = request.json['approval']
            if not approval:
                Answers.query.filter_by(id=answer_id).update(dict(approval=approval))
                db.session.commit()
                approval = "Not Approved"
                msg = Message('Response against your answers', recipients=[user_email])
                msg.body = 'Your request is ' + approval
                mail.send(msg)
                return jsonify("Response has been submitted...")

            Answers.query.filter_by(id=answer_id).update(dict(approval=approval))
            db.session.commit()
            print(approval)
            approval = "Approved"
            msg = Message('Response against your answers', recipients=[user_email])
            msg.body = 'Your request is ' + approval
            mail.send(msg)
            return jsonify("Response has been submitted..."), 200
        else:
            return jsonify("Not Authorized..."), 401


@app.route('/upload/image/<item_id>', methods=['POST'])
def upload(item_id):
    pic = request.files['pic']
    if not pic:
        return 'No picture uploaded', 400
    i_id = Item.query.get(item_id)
    filename = secure_filename(pic.filename)
    mimetype = pic.mimetype
    image = Img(img=pic.read(), mimetype=mimetype, name=filename, item_id=i_id.id)
    print(image, mimetype, filename, i_id.id)
    db.session.add(image)
    db.session.commit()

    return 'Img has been uploaded!', 200


@app.route('/get_image/<image_id>')
def get_img(image_id):
    img = Img.query.filter_by(id=image_id).first()
    if not img:
        return 'No image with this id', 404

    return Response(img.img, mimetype=img.mimetype)


# MAIN
if __name__ == '__main__':
    app.run()
