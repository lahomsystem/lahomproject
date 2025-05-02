import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

# Function to test login
def test_login(username, password):
    # Connect to database
    conn = sqlite3.connect('furniture_orders.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    print(f"Testing login with: {username} / {password}")
    
    # Get user by username
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        print("User not found")
        return False
    
    print(f"User found: {user['username']}, Role: {user['role']}")
    
    # Check if user is active
    if not user['is_active']:
        print("User is inactive")
        return False
    
    # Verify password
    if check_password_hash(user['password'], password):
        print("Password is correct ✓")
        return True
    else:
        print("Password is incorrect ✗")
        print(f"Stored hash: {user['password']}")
        # Generate hash for the password to compare
        new_hash = generate_password_hash(password)
        print(f"Generated hash for '{password}': {new_hash}")
        return False

# Test with the admin credentials
print("Testing admin login:")
admin_result = test_login('admin', 'Admin123')
print(f"Admin login result: {'Success' if admin_result else 'Failed'}")

print("\nTesting with old password:")
old_admin_result = test_login('admin', 'admin123')
print(f"Old admin login result: {'Success' if old_admin_result else 'Failed'}")

# If you want to test another user
if len(input("\nTest another user? (y/n): ").strip().lower()) > 0 and input("Test another user? (y/n): ").strip().lower()[0] == 'y':
    test_username = input("Enter username: ")
    test_password = input("Enter password: ")
    user_result = test_login(test_username, test_password)
    print(f"Login result: {'Success' if user_result else 'Failed'}") 