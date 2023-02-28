from flask import Flask, request, jsonify, send_file,after_this_request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey
from PIL import Image
import base64
import io
import face_recognition as fr
import json
import numpy as np
import os
import tempfile
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import random
import string
import vonage
from functools import wraps
import logging
from flask_socketio import SocketIO, emit
from flask_cors import CORS, cross_origin
import time
import sys
import threading
import datetime
client = vonage.Client(key="5b0cdb35", secret="iw0KEHACp6UrTwla")
sms = vonage.Sms(client)

class Config(object):
    SECRET_KEY= 'you-will-never-guess'


approval_thread = threading.Event()
history_thread = threading.Event()
employee1_thread = threading.Event()
employee2_thread = threading.Event()
employee3_thread = threading.Event()
app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
db_path = os.path.join(os.path.dirname(__file__), 'app2.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
thread = None
thread1=None
thread2 = None
thread3 = None
thread_lock = threading.Lock()
app.config.from_object(Config)
db = SQLAlchemy(app)
db.init_app(app)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
logging.basicConfig(filename='record.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
socketio = SocketIO(app,cors_allowed_origins='*')

@socketio.on('connect')
def test_connect():
    """event listener when client connects to the server"""
    app.logger.info("client has connected")
    emit("connect",{"data":"id: is connected"})

@socketio.on('disconnect')
def disconnect():
    app.logger.info("client has diconnected")
    emit(
        'user disconnected',{"data":"id: is disconnected"},  
        broadcast=True)

class User(db.Model):
    __tablename__ = "User"
    username = db.Column(db.String(80),primary_key=True, unique=True)
    email = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String(128))
    admin=db.Column(db.Boolean, default=False, server_default="false")
    phonenumber=db.Column(db.String(80), unique=True)
    employees = relationship('Employees',backref="User", lazy=True)
    store = relationship('Store',backref="User", lazy=True)

    @property
    def password(self):
        raise AttributeError('password is not a readable property')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
   
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def validate_email(email):
        if User.query.filter_by(email = email).first() is not None:
            return False
        else:
            return True
   
    @staticmethod
    def validate_user_name(username):
        if User.query.filter_by(username = username).first() is not None:
            return False
        else:
            return True

    @staticmethod
    def validate_phonenumber(phonenumber):
        if User.query.filter_by(phonenumber = phonenumber).first() is not None:
            return False
        else:
            return True
       

    def __repr__(self):
        return '<User {}>'.format(self.email)  

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            app.logger.info('token present')
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            app.logger.info('token not present')
            return jsonify({'message' : 'logged out'})
 
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            app.logger.info('getting user data')
            app.logger.info(data)
            current_user = User.query\
                .filter_by(username = data['public_id'])\
                .first()
        except:
            app.logger.info('exception')
            return jsonify({
               'message' : 'logged out'})
        # returns the current logged in users contex to the routes
        app.logger.info('success')
        return  f(current_user, *args, **kwargs)
 
    return decorated

def sendsms(fromadd,to,text):
  try:
    responseData = sms.send_message(
        {
            "from": fromadd,
            "to": to,
            "text": text,
        }
    )
    print(responseData["messages"])
    if responseData["messages"][0]["status"] == "0":
      #app.logger.info('sms status sucess')
      return True
    else:
      #app.logger.error('sms status failed')
      return False
  except:
    #app.logger.error('sms api exception')
    return False

def parse(string):
    d = {'True': True, 'False': False}
    return d.get(string, string)
     
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login Form"""
    if request.method == 'POST':
        try:          
         user = User.query.filter_by(email=request.json['email']).first()
         if user is not None and user.check_password(request.json['password']):        
                token = jwt.encode({
                    'public_id': user.username,
                }, app.config['SECRET_KEY'])
                app.logger.info('login sucessful')
                return jsonify({'status':True,'token':token})
         else:  
              app.logger.error('email method user name already exists')
              return jsonify({'status':False})
        except:
            app.logger.error('Login function exception triggered')
            return jsonify({'status':False})
    else:
      return jsonify({'status':False})

@app.route('/register/', methods=['POST'])
def register():
    """Register Form"""
    random_string = str(''.join(random.choices(string.ascii_lowercase + string.digits, k=5)))
    try:
      if request.method == 'POST':
        value_email = User.validate_email(request.json['email'])
        value_phonenumber = User.validate_phonenumber(request.json['phonenumber'])
        value_user = User.validate_user_name(random_string)
        if value_email and value_phonenumber and value_user:
            new_user = User(
                email = request.json['email'],
                password = request.json['password'],
               username =  random_string,
               admin = parse(request.json['admin']),
               phonenumber = request.json['phonenumber']
               )
            db.session.add(new_user)
            db.session.commit()
            app.logger.info('registration success')
            return jsonify({'status':True,'username':random_string})
        else:
          app.logger.error('registration data already exists')
          return jsonify({'status':False})
      else:
        app.logger.error('registration wrong request')
        return jsonify({'status':False})
    except:
      app.logger.error('registration function exception triggered')
      return jsonify({'status':False})

@app.route("/currentuser", methods=['GET'])
@token_required
def Current_user(user):
        app.logger.info('Current user acessed')
        return jsonify({'email':user.email,'admin':user.admin,'phonenumber':user.phonenumber,'username':user.username})
   

@app.route('/getOTP', methods=('GET', 'POST'))
def get_otp():
    if request.method == "POST":
        if request.json['phonenumber']:
            user = User.query.filter_by(phonenumber=request.json['phonenumber']).first()
            if user is not None:
              to = str(request.json['phonenumber'])
              fromadd = 'Spades software solutions'
              code=random.randint(10000,99999)
              Text = f"Welcome to Spades Software Solutions Attendance application, Your OTP for login is {code}"                
              result = sendsms(fromadd,to,Text)
              if result:
                  session['otp_code'] = str(code)
                  app.logger.info('OTP sent successfully')
                  return jsonify({'status':True, "code":code})
              else:
                  app.logger.error('sms not sent')
                  return jsonify({'status':False, "code":''})  
            else:
                app.logger.error('phone verification user exists')      
                return jsonify({'status':False, "code":''})  
        else:
          app.logger.error('no phone number was sent from client')
          return jsonify({'status':False, "code":''})
    else:
      app.logger.error('wrong request send to funcion get_otp')
      return jsonify({'status':False, "code":''})

@app.route('/verifyOTP', methods=['POST'])
def verify_otp():
    if request.method == "POST":
        user = User.query.filter_by(phonenumber=request.json['phonenumber']).first()
        user_id = user.username
        user_isadmin = user.admin

        if request.json['verification-code']:
            code = request.json['verification-code']
            if code == session['otp_code']:
                token = jwt.encode({
                    'public_id': user.username,
                }, app.config['SECRET_KEY'])
                app.logger.info('otp verified successfully')
                return jsonify({'status' :True,'token' : token.decode('UTF-8')})
            else:
                app.logger.error('session otp was not pertinant')
                return jsonify({"status":False})
        else:
            app.logger.error('no verification code sent in request')
            return jsonify({"status":False})
    else:
        app.logger.error('wrong request sent to verify otp')
        return jsonify({"status":False})



class Employees(db.Model):
  __tablename__ = "Employees"
  userId=db.Column(db.String(128),primary_key=True,nullable=False,unique=True)
  imageId = db.Column(db.String(128))  
  firstName = db.Column(db.String(128), nullable=False)
  lastName = db.Column(db.String(128), nullable=False)
  emailId = db.Column(db.String(128), nullable=False)
  phoneNumber = db.Column(db.String(128), nullable=False)
  specialization = db.Column(db.String(128), nullable=False)
  aadharNumber = db.Column(db.String(128), nullable=False)
  address = db.Column(db.String(128), nullable=False)
  experience = db.Column(db.String(128), nullable=False)
  radius = db.Column(db.String(128), nullable=False)
  lat = db.Column(db.String(128), nullable=False)
  longi = db.Column(db.String(128), nullable=False)
  approval = relationship('Approval',backref="Employees", lazy=True)
  history = relationship('History',backref="Employees", lazy=True)
  attendance = relationship('Attendance',backref="Employees", lazy=True)
  storeid= db.Column(db.String,ForeignKey("Store.storeId"))
  admin = db.Column(db.String,ForeignKey("User.username"))

@token_required
@app.route('/employee/adddata', methods=['POST'])
def employee_adddata():
  if request.method == 'POST':
    try:
      emp = Employees.query.get(request.json['userId'])
      if emp is None:
        obj = Employees(
           userId = request.json['userId'],
          firstName = request.json['firstName'],
          lastName = request.json['lastName'],
          storeid = request.json['storeId'],
          imageId = request.json['imageId'],
          emailId = request.json['emailId'],
          phoneNumber = request.json['phoneNumber'],
          specialization = request.json['specialization'],
          aadharNumber = request.json['aadharNumber'],
          address = request.json['address'],
          experience = request.json['experience'],
          radius = request.json['radius'],
          longi = request.json['longi'],
          lat = request.json['lat'],  
          admin = request.json['admin']    
        )
        db.session.add(obj)
        db.session.commit()
        return jsonify({'status':True})
      else:
        return jsonify({'status':False})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/employee/delete/<string:id>', methods=['GET'])
def employee_deletedata(id):
  if request.method == 'GET':
    try:
      obj = Employees.query.filter_by(userId=id).delete()
      db.session.delete(obj)
      db.session.commit()
      return jsonify({'status':True})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/employee/getdata/<string:id>', methods=['GET'])
def employee_getdata(id):
  if request.method == 'GET':
    try:
      employees= {}  
      employee = Employees.query.filter_by(userId=id).first()
      employees= {'userId': employee.userId,'firstName' : employee.firstName, 'lastName' : employee.lastName,'emailId' : employee.emailId,'phoneNumber' : employee.phoneNumber,'specialization' : employee.specialization,
      'lat' : employee.lat,'longi' : employee.longi,'storeId' : employee.storeid,'imageId' : employee.imageId,'aadharNumber' : employee.aadharNumber,'address' : employee.address,'experience' : employee.experience,'radius' : employee.radius,}
      app.logger.info('successful')
      return jsonify({'status':True,'data':employees})
    except:
      app.logger.info('failed')
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@socketio.on('/employee2/stop_thread', namespace="/employee2-disconnect")
def employee2_threads():
        app.logger.info("your thread is stopped employee2")
        if employee2_thread.is_set():
            global thread1
            employee2_thread.clear()
            with thread_lock:
                app.logger.info('thread closing not locked')
                if thread1 is not None:
                   thread1 = None
        else:
            app.logger.info("Your socket is not open")

            

def backgroundemployee2_thread(id):
  while employee2_thread.is_set():
    try:
      all_employees= []  
      employees = Employees.query.filter_by(admin=id).all()
      if len(employees)>0:
        for employee in employees:
          employe= {'userId': employee.userId,'firstName' : employee.firstName, 'lastName' : employee.lastName,'emailId' : employee.emailId,'phoneNumber' : employee.phoneNumber,'specialization' : employee.specialization,
          'lat' : employee.lat,'longi' : employee.longi,'storeId' : employee.storeid,'imageId' : employee.imageId,'aadharNumber' : employee.aadharNumber,'address' : employee.address,'experience' : employee.experience,'radius' : employee.radius,'admin':employee.admin}
          all_employees.append(employe)
          employe={}
        app.logger.info(all_employees)
        emit("/employee2/data",{"data" :all_employees})
      else:
        app.logger.info('failure')  
        emit("/employee2/data",{"data" :[]})
    except:
      app.logger.info('exception')
      emit("/employee2/data",{"data" :[]})
    finally:
        time.sleep(2)


@socketio.on('/employee2/data', namespace="/employee2-data")
def employee_getadmindata(id):
    app.logger.info('connected employee')
    global thread1
    with thread_lock:
        app.logger.info('employee lock locked')
        if thread1 is None:
            employee2_thread.set()
            thread2 = socketio.start_background_task(backgroundemployee2_thread(id))
    emit("/employee2/data",{"data" :[]})


@socketio.on('/employee3/stop_thread', namespace="/employee3-disconnect")
def employee3_threads():
        app.logger.info("your thread is stopped employee3")
        if employee3_thread.is_set():
            global thread
            app.logger.info(employee3_thread)
            employee3_thread.clear()
            with thread_lock:
                app.logger.info('thread closing not locked')
                if thread is not None:
                   thread = None
        else:
            app.logger.info("Your socket is not open")

            

def backgroundemployee3_thread(id):
  while employee3_thread.is_set():
    try:
      employees = {}  
      employee = Employees.query.filter_by(userId=id).first()
      employees= {'userId': employee.userId,'firstName' : employee.firstName, 'lastName' : employee.lastName,'emailId' : employee.emailId,'phoneNumber' : employee.phoneNumber,'specialization' : employee.specialization,
      'lat' : employee.lat,'longi' : employee.longi,'storeId' : employee.storeid,'imageId' : employee.imageId,'aadharNumber' : employee.aadharNumber,'address' : employee.address,'experience' : employee.experience,'radius' : employee.radius,}
      app.logger.info(employees)
      emit("/employee3/data",{"data" :employees})
    except:
      app.logger.info('exception')
      emit("/employee3/data",{"data" :[]})
    finally:
        time.sleep(2)


@socketio.on('/employee3/data', namespace="/employee3-data")
def employee3_getdata(id):
    app.logger.info('connected employee')
    global thread
    with thread_lock:
        app.logger.info('employee lock locked')
        if thread is None:
            employee3_thread.set()
            thread2 = socketio.start_background_task(backgroundemployee3_thread(id))
    emit("/employee3/data",{"data" :{}})

@socketio.on('/employee1/stop_thread')
def employee1_threads():
    app.logger.info("your thread is stopped employee")
    global thread2
    employee1_thread.clear()
    with thread_lock:
      if thread2 is not None:
          thread2.join()
          thread2 = None

def backgroundemployee1_thread(data):
  while employee1_thread.is_set():
    try:
      all_employees= []
      employees = Employees.query.filter_by(admin=data['admin']).filter_by(storeid=data['store']).all()
      if len(employees)>0:
        for employee in employees:
          employe= {'userId': employee.userId,'firstName' : employee.firstName, 'lastName' : employee.lastName,'emailId' : employee.emailId,'phoneNumber' : employee.phoneNumber,'specialization' : employee.specialization,
          'lat' : employee.lat,'longi' : employee.longi,'storeId' : employee.storeid,'imageId' : employee.imageId,'aadharNumber' : employee.aadharNumber,'address' : employee.address,'experience' : employee.experience,'radius' : employee.radius,}
          all_employees.append(employe)
          employe={}
        emit("/employee/getadminstoredata",{"data" :all_employees})
      else:
        emit("/employee/getadminstoredata",{"data" :[]})
    except:
        emit("/employee/getadminstoredata",{"data" :[]})
    finally:
        time.sleep(2)


@socketio.on('/employee/getadminstoredata', namespace="/employee-getadminstoredata")
def employee_getadminstoredata(data):
  app.logger.info('connected')
  global thread2
  with thread_lock:
    if thread2 is None:
        employee1_thread.set()
        thread2 = socketio.start_background_task(backgroundemployee1_thread(data))
  emit("/employee/getadminstoredata",{"data" :[]})


@token_required
@app.route('/employee/update', methods=['POST'])
def update_employee():
     if request.method == 'POST':
        try:
            employee_to_update = Employees.query.filter_by(userId=request.json['empid']).first()
            if employee_to_update is not None:
              employee_to_update.imageId = str(request.json['imageId'])
              db.session.commit()
              app.logger.info('employee updated sucessfully')
              return jsonify({'status':True})
            else:
              app.logger.info('employee updation failed') 
              return jsonify({'status':False})
        except:
          app.logger.info('employee updation exception triggered')   
          return jsonify({'status':False})
     else:
      app.logger.info('employee updation request error')   
      return jsonify({'status':False})      


class Approval(db.Model):
  __tablename__ = "Approval"
  id = db.Column(db.Integer,primary_key=True)
  empname = db.Column(db.String(128), nullable=False)
  imageid = db.Column(db.String(128), nullable=False)
  empid = db.Column(db.String(128), ForeignKey("Employees.userId"))

@token_required
@app.route('/approval/adddata', methods=['POST'])
def approval_adddata():
  if request.method == 'POST':
    try:
      obj = Approval(
         empid = request.json['empId'],
         empname = request.json['empName'],
         imageid = request.json['imageId'],      
      )
      db.session.add(obj)
      db.session.commit()
      app.logger.info('approval added sucessfully')
      return jsonify({'status':True})
    except:
      app.logger.error('approval addata exception triggered')      
      return jsonify({'status':False})
  else:
    app.logger.error('approval addata wrong request')
    return jsonify({'status':False})

@token_required
@app.route('/approval/delete/<string:id>', methods=['GET'])
def approval_deletedata(id):
  if request.method == 'GET':
    try:
      obj = Approval.query.filter_by(empid=id).delete()
      db.session.commit()
      app.logger.info('approval deleted sucessfully')
      return jsonify({'status':True})
    except:
      app.logger.error('approval delete exception triggered')      
      return jsonify({'status':False})
  else:
    app.logger.error('approval delete wrong request')
    return jsonify({'status':False})

@socketio.on('/approval/stop_thread', namespace="/approval-stop")
def approvals_threads():
        app.logger.info("your thread is stopped approval")
        if approval_thread.is_set():
            global thread
            approval_thread.clear()
            with thread_lock:
              if thread is not None:
                  thread = None
        else:
            app.logger.info("Your socket is not open")


def backgroundapproval_thread(data):
  while approval_thread.is_set():
    try:
      all_approval= []  
      approvals = Approval.query.join(Employees).filter_by(admin=data).all()
      if len(approvals) > 0 :
        for approval in approvals:
          all_approval.append({'empId':approval.empid,'empName':approval.empname,'imageId':approval.imageid})
        app.logger.info(all_approval);
        emit("/approval/getdata",{"data" :all_approval})
      else:
        app.logger.info('no approval');  
        emit("/approval/getdata",{"data" :[]})
    except:
      app.logger.info('exception triggered');
      emit("/approval/getdata",{"data" :[]})
    finally:
      time.sleep(2)
  
   
@socketio.on('/approval/getdata', namespace="/approval-getdata")
def approval_getdata(id):
  app.logger.info('connected approval')
  app.logger.info('received message: ' + str(id))  
  global thread
  with thread_lock:
    app.logger.info('approval is locked')  
    if thread is None:
        approval_thread.set()
        thread3 = socketio.start_background_task( backgroundapproval_thread(id))
  emit("/approval/getdata",{"data" :[]})

class History(db.Model):
  __tablename__ = "History"
  id = db.Column(db.Integer,primary_key=True)
  checkin = db.Column(db.String(128))
  randomint = db.Column(db.String(128))
  checkout = db.Column(db.String(128))
  hrspent = db.Column(db.String(128))
  userid = db.Column(db.String(128), ForeignKey("Employees.userId"))

@token_required
@app.route('/history/updatedata', methods=['POST'])
def history_updatedata():
  if request.method == 'POST':
    try:        
      obj = {
         'userid' : request.json['userId'],
         'checkin' : request.json['checkIn'],
         'checkout' : request.json['checkOut'],
         'hrspent' : request.json['hrsSpent']        
      }
      history = History.query.filter_by(randomint=request.json['randomint']).first()
      for key, value in obj.items():
        setattr(history, key, value)

      db.session.commit()
      db.session.flush()
      app.logger.info('History, data updated sucessfully')
      return jsonify({'status':True})
    except:
      app.logger.error('hsitory updatedata exception triggered')
      return jsonify({'status':False})
  else:
    app.logger.error('hsitory updatedata wrong request')
    return jsonify({'status':False})

@token_required
@app.route('/history/adddata', methods=['POST'])
def history_adddata():
  if request.method == 'POST':
    try:
      history_id = str(random.randint(0,900))  
      history = History.query.filter_by(randomint=history_id).first()
      if history is None:
        obj = History(
           userid = request.json['userId'],
           checkin = request.json['checkIn'],
           checkout = request.json['checkOut'],
           hrspent = request.json['hrsSpent'],
           randomint = history_id,        
        )
        db.session.add(obj)
        db.session.commit()
        app.logger.info('hsitory adddata successfull')
        return jsonify({'status':True,'data':history_id})
      else:
        app.logger.error('hsitory adddata historyid already available')
        jsonify({'status':False})
    except:
      app.logger.error('hsitory adddata exception triggered')
      return jsonify({'status':False})
  else:
    app.logger.error('hsitory adddata wrong request')
    return jsonify({'status':False})


@socketio.on('/history/stop_thread', namespace="/history-stopthread")
def history_threads():
    app.logger.info("your history thread is stopped")
    if history_thread.is_set():
        app.logger.info("history_thread")
        global thread3
        history_thread.clear()
        with thread_lock:
          if thread3 is not None:
              thread3 = None
    else:
        app.logger.info('Your history thread is not locked')

def backgroundhistory_thread(id):
  while history_thread.is_set():  
    try:
      all_history = []  
      historys = History.query.filter_by(userid=id).all()
      if len(historys) > 0:
        for history in historys:
          all_history.append({'userId':history.userid,'checkIn':history.checkin,'checkOut':history.checkout,'hrsSpent':history.hrspent})
          app.logger.info(all_history)
          emit("/history/getdata",{"data" :all_history})
      else:
        app.logger.info('no history')
        emit("/history/getdata",{"data" :[]})
    except:
      app.logger.info('exception triggered');
      emit("/history/getdata",{"data" :[]})
    finally:
        time.sleep(2)  

    
  

@socketio.on('/history/getdata', namespace="/history-getdata")
def history_getdata(id):
  app.logger.info('connected')
  app.logger.info('received message: ' + str(id))  
  global thread3
  with thread_lock:
    if thread3 is None:
        history_thread.set()
        thread3 = socketio.start_background_task(backgroundhistory_thread(id))
  emit("/history/getdata",{"data" :[]})

@token_required
@app.route('/history/delete/<string:id>', methods=['GET'])
def history_deletedata(id):
  if request.method == 'GET':
    try:
      obj = History.query.filter_by(userId=id).delete()
      db.session.delete(obj)
      db.session.commit()
      app.logger.info('hsitory deletedata sucessful')      
      return jsonify({'status':True})
    except:
      app.logger.error('hsitory deletedata exception triggered')
      return jsonify({'status':False})
  else:
    app.logger.error('hsitory deletedata wrong request')
    return jsonify({'status':False})


class Store(db.Model):
  __tablename__ = "Store"
  storeId = db.Column(db.String(128),primary_key=True, nullable=False)
  radius = db.Column(db.String(128), nullable=False)
  storeName = db.Column(db.String(128), nullable=False)
  lat = db.Column(db.String(128), nullable=False)
  longi = db.Column(db.String(128), nullable=False)
  employee = relationship("Employees", backref='Store', lazy=True)
  admin = db.Column(db.String,ForeignKey("User.username"))

@token_required
@app.route('/store/adddata', methods=['POST'])
def Store_adddata():
  if request.method == 'POST':
    try:
      store = Store.query.get(request.json['storeId'])
      if store is None:
        obj = Store(
           storeId = request.json['storeId'],
           radius = request.json['radius'],
           storeName = request.json['storeName'],
           lat = request.json['lat'],
           admin = request.json['admin'],    
           longi = request.json['longi'],          
        )
        db.session.add(obj)
        db.session.commit()
        return jsonify({'status':True})
      else:
        return jsonify({'status':False})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/store/getdata/<string:store>', methods=['GET'])
def Store_getdata(store):
  if request.method == 'GET':
    try:
      all_stores = []  
      stores = Store.query.filter_by(admin=store).all()
      if len(stores)>0:
        for store in stores:
          all_stores.append({'storeId':store.storeId,'radius':store.radius,'storeName':store.storeName,'admin':store.admin,'lat':store.lat,'longi':store.longi})
        return jsonify({'status':True,'data':all_stores})
      else:
        return jsonify({'status':False})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/store/delete/<string:store>', methods=['GET'])
def Store_deletedata(store):
  if request.method == 'GET':
    try:
      obj = Store.query.filter_by(storeId=store).delete()
      db.session.delete(obj)
      db.session.commit()
      return jsonify({'status':True})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})


class Images(db.Model):
    __tablename__ = "Images"
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    img = db.Column(db.LargeBinary)

@token_required
@app.route('/deletefile/<string:name>', methods=['GET'])
def delete_file(name):
  if request.method == 'GET':
    try:  
      obj = Images.query.filter_by(name=name).delete()
      db.session.delete(obj)
      db.session.commit()
      return jsonify({'status':True})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/image/<string:filename>', methods=['GET'])
def download_image(filename):
  if request.method == 'GET':
    try:  
        images = Images.query.filter_by(name=filename).first()
        if not images.img:
            return jsonify({'status':False})

        return send_file(
            io.BytesIO(images.img),
            as_attachment=False,
            mimetype='image/png')
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/img-profile', methods=['POST'])
def upload_profile():
  if request.method == 'POST':
    try:
      file = request.files['file']
      data = file.read()
      newFile = Images(name=file.filename, img=data)
      db.session.add(newFile)
      db.session.commit()
      return jsonify({'status':True,"file_name": file.filename})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})



class Attendance(db.Model):
    __tablename__ = "Attendance"
    id = db.Column(db.Integer,primary_key=True)
    encoding = db.Column(db.String)
    employee_id = db.Column(db.String(128), ForeignKey("Employees.userId"))

@token_required
@app.route('/get_status/<string:name>' ,methods=['GET'])
def image(name):
  if request.method == 'GET':
    try:
      attendances = Attendance.query.filter_by(employee_id=name).all()
      if len(attendances)>0:
        for attendance in attendances:
          if attendance.encoding is not None:
            return jsonify({"Status": True})
        return jsonify({"Status": False})
      else:
        return jsonify({"Status": False})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})


@token_required
@app.route('/img-upload', methods=['POST'])
def upload_image():
  if request.method == 'POST':
    @after_this_request
    def remove_file(response):
      try:
        if tempimage_path is not None:
          os.remove(tempimage_path)
      except Exception as error:
        print("Error removing or closing downloaded file handle", error)
      return response  
    try:
      file = request.files['file']
      data = file.read()
      tempimage_path = os.path.join(os.path.dirname(os.path.abspath("__file__")), file.filename)
      with open(tempimage_path, 'wb') as fp:
         fp.write(data)
      target_img = fr.load_image_file(file.filename)
      target_encoding = fr.face_encodings(target_img)
      if len(target_encoding) > 0:
        target_encoding = json.dumps(list(target_encoding[0]))
        newFile = Attendance(employee_id = request.form['employee_id'] , encoding = target_encoding)
        db.session.add(newFile)
        db.session.commit()
        return jsonify({'status':False,"file_name": file.filename})
      else:
        newFile = Attendance( employee_id = request.form['employee_id'] )
        db.session.add(newFile)
        db.session.commit()
        return jsonify({'status':False,"file_name": ''})    
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})

@token_required
@app.route('/check_attendance', methods=['POST'])
def attendance():
  if request.method == 'POST':
    try:
      matches=[]
      file = request.files['file']
      data = file.read()
      tempimage_path = os.path.join(os.path.dirname(os.path.abspath("__file__")), file.filename)
      with open(tempimage_path, 'wb') as fp:
         fp.write(data)  
      known_image = fr.load_image_file(tempimage_path)
      encoding = fr.face_encodings(known_image)
      if len(encoding)>0:
        attendances = Attendance.query.filter_by(employee_id = request.form['employee_id']).all()
        for attendance in attendances:
          if attendance is not None and encoding is not None:
            known_encodings = np.array(json.loads(attendance.encoding))
            matches.append(fr.compare_faces([known_encodings], encoding[0]))
        for match in matches:
          if match[0] == True:
            return jsonify({"status": True})
          else:  
            return jsonify({"status": False})
      else:
        return jsonify({"status": False})      
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})    

@token_required
@app.route('/delete/<string:name>', methods=['GET'])
def delete_entry(name):
  if request.method == 'GET':
    try:  
      obj = Attendance.query.filter_by(employee_id=name).delete()
      db.session.delete(obj)
      db.session.commit()
      return jsonify({'status':True})
    except:
      return jsonify({'status':False})
  else:
    return jsonify({'status':False})


if __name__ == '__main__':
  with app.app_context():
   db.create_all()    
  socketio.run(app)
#else:
#    gunicorn_logger = logging.getLogger('gunicorn.error')
#    app.logger.handlers = gunicorn_logger.handlers
#    app.logger.setLevel(gunicorn_logger.level)
