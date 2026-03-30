# view_db.py
import sqlite3
import os

db_path = os.path.join('instance', 'phishguard.db')
print(f"Database: {db_path}")
print(f"Exists: {os.path.exists(db_path)}")

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # List all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print("\n📊 Tables:", [t[0] for t in tables])
    
    # Show users
    cursor.execute("SELECT id, username, email FROM users;")
    users = cursor.fetchall()
    print("\n👤 Users:")
    for user in users:
        print(f"  - {user[1]} ({user[2]})")
    
    conn.close()