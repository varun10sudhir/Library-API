from flask import Flask,request,jsonify,make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from pandas import json_normalize
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
import datetime
from functools import wraps
app=Flask(__name__)
app.config['SECRET_KEY']='thisisthesecretkey'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///library.db'
db=SQLAlchemy(app)
class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.String(50),unique=True)
    name=db.Column(db.String(50))
    password=db.Column(db.String(80))
    admin=db.Column(db.Boolean) 
class Books(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    book_name=db.Column(db.String(50))
    book_author=db.Column(db.String(50))
    book_id=db.Column(db.String(50),unique=True)
    book_available=db.Column(db.Boolean)
    userborrowedid=db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']
        if not token:
            return jsonify({'message':'Token is missing'}),401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user=User.query.filter_by(user_id=data['user_id']).first()
        except:
            return jsonify({"message":"Token is invalid"}),401
        return f(current_user,*args,**kwargs)
    return decorated

@app.route('/user',methods=['GET'])
@token_required
def get_all_user(current_user):
    if not current_user.admin:
        users=User.query.all()
        output=[]
        for user in users:
            if user==current_user:
                user_data={}
                user_data['Name']=user.name
                user_data['User_Id']=user.user_id
                user_data['Password']=user.password
                user_data['Admin']=user.admin
                output.append(user_data)
            else:
                user_data={}
                user_data['Name']=user.name
                output.append(user_data)
        return jsonify({"Users":output})
    users=User.query.all()
    output=[]
    for user in users:
        user_data={}
        user_data['Name']=user.name
        user_data['User_Id']=user.user_id
        user_data['Password']=user.password
        user_data['Admin']=user.admin
        output.append(user_data)
    return jsonify({"Users":output})


@app.route('/user/<user_id>',methods=['GET'])
@token_required
def get_one_userdetails(current_user,user_id):
    userone=User.query.filter_by(user_id=user_id).first()
    if not userone:
        return jsonify({"message":"User not found!"})
    output=[]
    user_data={}
    user_data['Name']=userone.name
    user_data['User_Id']=userone.user_id
    user_data['Password']=userone.password
    user_data['Admin']=userone.admin
    output.append(user_data)
    return jsonify({"User":output})



@app.route('/user',methods=['POST'])
def create_user():
    data=request.get_json()
    passwordhash = generate_password_hash(data['password'],method='sha256')
    new_user=User(user_id=str(uuid.uuid4()),name=data['name'],password=passwordhash,admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message":"New User created"})

@app.route('/user/<user_id>',methods=['PUT'])
@token_required
def promote_user(current_user,user_id):
    user=User.query.filter_by(user_id=user_id).first()
    data=request.get_json()
    if not user:
        return jsonify({"message:User not found"})
    if data["admin_code"]=='IAMADMIN':
        user.admin=True
        db.session.commit()
        return jsonify({"message":"User has been promoted!"})
    else:
        return jsonify({"message":"Wrong admin code, access denied"})



@app.route('/user/<user_id>',methods=['DELETE'])
@token_required
def delete_user(current_user,user_id):
    user=User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({"message:User not found"})
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message":"The user has been deleted"}) 

@app.route('/login')
def login():
    auth=request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response("Could not verify",401,{"WWW-Authenticate" :'Basic realm="Login required"'})
    user=User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response("Could not verify",401,{"WWW-Authenticate" :'Basic realm="Login required"'})
    if check_password_hash(user.password,auth.password):
        token=jwt.encode({"user_id":user.user_id,"exp":datetime.datetime.utcnow()+datetime.timedelta(minutes=20)},app.config['SECRET_KEY'])
        return jsonify({"token":token})
    return make_response("Could not verify",401,{"WWW-Authenticate" :'Basic realm="Login required"'})

@app.route('/books',methods=['GET'])
@token_required
def allbooks(current_user):
    book=Books.query.all()
    output=[]
    for eachbook in book:
        book_data={}
        book_data['Name']=eachbook.book_name
        book_data['Author']=eachbook.book_author
        book_data['Availablity Status']=eachbook.book_available
        book_data['Book_ID']=eachbook.book_id
        output.append(book_data)
    return jsonify({"All books":output})

@app.route('/books',methods=['POST'])
@token_required
def createborrowbook(current_user):
    if current_user.admin:
        data=request.get_json()
        book=Books(book_name=data['Name'],book_author=data['Author'],book_id=str(uuid.uuid4()),book_available=True)
        db.session.add(book)
        db.session.commit()
        return jsonify({"message":"New book added to database"})
    else:
        return jsonify({"message":"Access denied"})

@app.route("/books/<book_id>",methods=['DELETE'])
@token_required
def deletebook(current_user,book_id):
    if current_user.admin:
        book=Books.query.filter_by(book_id=book_id).first()
        if not book:
            return jsonify({"message":"Book doesn't exist in database"})
        db.session.delete(book)
        db.session.commit()
        return jsonify({"message":"Book deleted"})
    else:
        return jsonify({"message":"Access denied"})

@app.route('/<user_id>/books',methods=['PUT'])
@token_required
def returnorborrow(current_user,user_id):
    user=User.query.filter_by(user_id=user_id).first()
    data=request.get_json()
    book=Books.query.filter_by(book_name=data["Name"]).first()
    if not book:
        return jsonify({"message":"Enter a valid book"})
    if book.book_available:
        book.userborrowedid=current_user.id
        book.book_available=False
        db.session.commit()
        return jsonify({"message":"You have successfuly issued the book"})
    if not book.book_available:
        if book.userborrowedid==current_user.id:
            book.userborrowedid=None
            book.book_available=True
            db.session.commit()
            return jsonify({"message":"You have succesfully returned the book"})
        else:
            return jsonify({"message":"You have not issued the book"})

@app.route('/<user_id>/books',methods=['GET'])
@token_required
def viewuserbooks(current_user,user_id):
    user=User.query.filter_by(user_id=user_id)
    book=Books.query.filter_by(userborrowedid=current_user.id).all()
    if not book:
        return jsonify({"message":"You have not borrowed any books"})
    output=[]
    for eachbook in book:
        book_data={}
        book_data['Name']=eachbook.book_name
        book_data['Author']=eachbook.book_author
        book_data['Availablity Status']=eachbook.book_available
        book_data['Book_id']=eachbook.book_id
        output.append(book_data)
    return jsonify({"All books borrowed ":output})



if __name__=='__main__':
    app.run(debug=True)