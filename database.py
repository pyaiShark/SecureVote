import sqlite3
from werkzeug.security import generate_password_hash

def get_db():
    db = sqlite3.connect('voting_system.db')
    db.row_factory = sqlite3.Row
    return db

def close_db(exception):
    pass  # Connection is closed by Flask automatically

def init_db():
    db = get_db()
    c = db.cursor()
    
    # Create tables
   # In database.py init_db() function
    c.execute('''
        CREATE TABLE IF NOT EXISTS voters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            voter_id TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            has_voted BOOLEAN DEFAULT 0,
            role TEXT DEFAULT 'voter',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    ''')

    c.execute('''
            CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            party TEXT NOT NULL,
            position TEXT NOT NULL,
            bio TEXT,
            photo TEXT,
            votes INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            voter_id INTEGER NOT NULL,
            candidate_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (voter_id) REFERENCES voters(id),
            FOREIGN KEY (candidate_id) REFERENCES candidates(id)
        )
    ''')
    
    # Create admin user if not exists
    c.execute("SELECT * FROM voters WHERE role = 'admin'")
    admin = c.fetchone()
    if not admin:
        hashed_password = generate_password_hash('admin123')
        c.execute("INSERT INTO voters (name, voter_id, password, role) VALUES (?, ?, ?, ?)",
                 ('Admin User', 'admin', hashed_password, 'admin'))
    
    # Add sample candidates if none exist
    c.execute("SELECT COUNT(*) FROM candidates")
    count = c.fetchone()[0]
    if count == 0:
        candidates = [
            ('Alex Morgan', 'Progressive Party', 'District 12 Representative', 
             '10+ years community leadership experience', 'uploads/candidate1.jpg'),
            ('Sarah Chen', 'Unity Alliance', 'District 12 Representative', 
             'Former city council member', 'uploads/candidate2.jpg'),
            ('James Wilson', 'Conservative Front', 'District 12 Representative', 
             'Business owner and philanthropist', 'uploads/candidate3.jpg')
        ]
        c.executemany("INSERT INTO candidates (name, party, position, bio, photo) VALUES (?, ?, ?, ?, ?)", candidates)
    
    db.commit()