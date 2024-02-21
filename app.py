from flask import Flask, jsonify, request, g
import sqlite3
import argon2

app = Flask(__name__)
ph = argon2.PasswordHasher()

DATABASE = 'database.db'

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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        visitor_id = request.form['visitor_id']
        
        hashed_password = ph.hash(password)
        
        cur = get_db().cursor()
        
        # check if username already exists
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        
        if  user:
            return jsonify({'message': 'Username already exists', 'status': 400})
        
        # check if visitor_id exists 
        cur.execute('SELECT * FROM users WHERE visitor_id = ?', (visitor_id,))
        user = cur.fetchone()
        
        if user:
            return jsonify({'message': 'Visitor already registered', 'status': 400})
    
        cur.execute('INSERT INTO users (username, password, full_name, visitor_id) VALUES (?, ?, ?, ?)', (username, hashed_password, full_name, visitor_id))
        
        get_db().commit()
        
        return jsonify({'message': 'User registered successfully'})
    else:
        return jsonify({'message': 'Invalid request', 'status': 400})

if __name__ == '__main__':
    app.run(debug=True)