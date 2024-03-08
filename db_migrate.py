import sqlite3

DATABASE = 'database.db'

con = sqlite3.connect(DATABASE)

cur = con.cursor()

# create users table

cur.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    full_name TEXT NOT NULL,
    visitor_id TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

con.commit()
con.close()