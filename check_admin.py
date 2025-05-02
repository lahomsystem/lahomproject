import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

# Connect to the database
conn = sqlite3.connect('furniture_orders.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Check if admin exists
cursor.execute("SELECT * FROM users WHERE username = 'admin'")
admin = cursor.fetchone()

if admin:
    print("Admin user exists:")
    print(f"Username: {admin['username']}")
    print(f"Password hash: {admin['password']}")
    print(f"Is active: {admin['is_active']}")
    
    # Test if 'admin123' works with the stored hash
    test_pwd = 'admin123'
    if check_password_hash(admin['password'], test_pwd):
        print(f"Password '{test_pwd}' matches the stored hash")
    else:
        print(f"Password '{test_pwd}' does NOT match the stored hash")
        
    # Create a new admin user with a simple password
    simple_pwd = 'Admin123'
    new_hash = generate_password_hash(simple_pwd)
    print(f"New password hash for '{simple_pwd}': {new_hash}")
    
    # Update the admin password (uncomment to apply)
    cursor.execute("UPDATE users SET password = ? WHERE username = 'admin'", (new_hash,))
    conn.commit()
    print("Admin password has been updated")
else:
    print("Admin user does not exist.")
    
    # Create admin user if it doesn't exist
    admin_pwd = generate_password_hash('Admin123')
    cursor.execute('''
    INSERT INTO users (username, password, name, email, role, is_active, email_verified)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', ('admin', admin_pwd, '관리자', 'admin@example.com', 'ADMIN', 1, 1))
    conn.commit()
    print("Admin user has been created")

conn.close() 