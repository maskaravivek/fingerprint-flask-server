from flask import Flask, jsonify, request, g
import sqlite3
import argon2

import fingerprint_pro_server_api_sdk
from fingerprint_pro_server_api_sdk import EventResponse
from fingerprint_pro_server_api_sdk.rest import ApiException, KnownApiException
import time

app = Flask(__name__)
ph = argon2.PasswordHasher()

DATABASE = 'database.db'

# init variables and SDK after the import statements in the forms.py file
min_confidence = 0.5
max_request_lifespan = 60 * 5 # 5 minutes

# init the server API SDK
configuration = fingerprint_pro_server_api_sdk.Configuration(api_key="SUmn3f35FIfY10KKKaXo")
api_instance = fingerprint_pro_server_api_sdk.FingerprintApi(configuration)

@app.route('/')
def index():
    return 'Welcome to Fingerprint API'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cur = get_db().cursor()
        
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        
        user = cur.fetchone()
        
        if user:
            user_password = user[2]
            if ph.verify(user_password, password):
                full_name = user[3]
                return jsonify({'message': 'Login successful', 'full_name': full_name, 'status': 200})
        
        return jsonify({'message': 'Invalid credentials', 'status': 400})
    else:
        return jsonify({'message': 'Invalid request', 'status': 400})

@app.route('/register', methods=['POST'])  
def register():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            full_name = request.form['full_name']
            visitor_id = request.form['visitor_id']
            request_id = request.form['request_id']
            
            hashed_password = ph.hash(password)
            
            cur = get_db().cursor()
            
            # check if username already exists
            cur.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cur.fetchone()
            
            if  user:
                return jsonify({'message': 'Username already exists', 'status': 400})
            
            if validate_fingerprint(visitor_id=visitor_id, request_id=request_id):
                cur.execute('INSERT INTO users (username, password, full_name, visitor_id) VALUES (?, ?, ?, ?)', (username, hashed_password, full_name, visitor_id))
                get_db().commit()
                
                return jsonify({'message': 'User registered successfully', 'status': 200})
        else:
            return jsonify({'message': 'Invalid request', 'status': 400})
    except Exception as e:
        return jsonify({'message': str(e), 'status': 400})

def validate_fingerprint(visitor_id, request_id):
    if request_id:
        try:
            # Get the fingerprint from the request_id
            event = api_instance.get_event(request_id)

            event_json = event.to_dict()
            identification = event_json['products']['identification']['data']
            
            server_visitor_id = identification['visitor_id']
            identification_timestamp = identification['timestamp'] / 1000
            confidence = identification['confidence']['score']
            
            # Check if the fingerprint is valid
            time_now = int(time.time())

            if time_now - identification_timestamp > max_request_lifespan:
                raise Exception('Fingerprint request expired.')

            if server_visitor_id != visitor_id:
                raise Exception('Fingerprint forgery detected.')
            
            if confidence < min_confidence:
                raise Exception('Fingerprint confidence too low.')
        except ApiException as e:
            print("Exception when calling FingerprintApi->get_event: %s\n" % e)
            raise Exception('Invalid fingerprint.')
    
    if visitor_id:
        # Check if a user with the same fingerprint already exists
        
        cur = get_db().cursor()
        # check if visitor_id exists 
        cur.execute('SELECT * FROM users WHERE visitor_id = ?', (visitor_id,))
        user = cur.fetchone()
        
        if user:
            raise Exception('Another user with the same fingerprint already exists.')
    
    return True

if __name__ == '__main__':
    app.run()