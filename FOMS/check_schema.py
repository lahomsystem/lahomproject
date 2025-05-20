import sqlite3
import os

# Connect to the database
conn = sqlite3.connect('furniture_orders.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Get all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
print("Tables in database:")
for table in tables:
    print(f"- {table['name']}")
    
# Check users table schema
print("\nUsers table schema:")
cursor.execute("PRAGMA table_info(users)")
columns = cursor.fetchall()
for col in columns:
    print(f"- {col['name']} ({col['type']})")
    
# List all users
print("\nUsers in database:")
cursor.execute("SELECT id, username, name, role, is_active FROM users")
users = cursor.fetchall()
for user in users:
    print(f"- ID: {user['id']}, Username: {user['username']}, Name: {user['name']}, Role: {user['role']}, Active: {user['is_active']}")

# Check for any non-active users
cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 0")
inactive_count = cursor.fetchone()[0]
if inactive_count > 0:
    print(f"\nWarning: {inactive_count} inactive user(s) found.")
    
print("\nVerification complete. Try logging in with username 'admin' and password 'Admin123'.")

conn.close() 