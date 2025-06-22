import sqlite3
import os
from datetime import datetime

def migrate_database():
    db_path = 'voting_system.db'
    
    if not os.path.exists(db_path):
        print("Database doesn't exist. Run app.py to initialize it.")
        return
        
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    try:
        # Check if last_login column exists in voters table
        c.execute("PRAGMA table_info(voters)")
        columns = [col[1] for col in c.fetchall()]
        
        if 'last_login' not in columns:
            print("Adding last_login column to voters table...")
            c.execute("ALTER TABLE voters ADD COLUMN last_login DATETIME")
            print("Column added successfully.")
            
            # Set default value for existing users
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            c.execute("UPDATE voters SET last_login = ?", (now,))
            print("Default values set for existing users.")
            
        conn.commit()
        print("Migration completed successfully.")
    except Exception as e:
        print(f"Migration failed: {str(e)}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    migrate_database()