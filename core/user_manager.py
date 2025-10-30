import json
import os
import hashlib
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from core.logging import logger

class UserManager:
    """Simple user management system using JSON file storage."""
    
    def __init__(self):
        self.users_file = 'data/users.json'
        self.ensure_data_directory()
        self.ensure_users_file()
    
    def ensure_data_directory(self):
        """Create data directory if it doesn't exist."""
        if not os.path.exists('data'):
            os.makedirs('data')
    
    def ensure_users_file(self):
        """Create users file with default admin user if it doesn't exist."""
        if not os.path.exists(self.users_file):
            default_users = {
                'admin': {
                    'username': 'admin',
                    'password_hash': generate_password_hash('admin'),
                    'email': 'admin@vulscanner.local',
                    'role': 'admin',
                    'created_at': datetime.now().isoformat(),
                    'last_login': None,
                    'active': True
                }
            }
            with open(self.users_file, 'w') as f:
                json.dump(default_users, f, indent=2)
    
    def load_users(self):
        """Load users from JSON file."""
        try:
            with open(self.users_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.error("Could not load users file, creating new one")
            self.ensure_users_file()
            return self.load_users()
    
    def save_users(self, users):
        """Save users to JSON file."""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(users, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Could not save users file: {e}")
            return False
    
    def create_user(self, username, password, email, role='user'):
        """Create a new user."""
        users = self.load_users()
        
        # Check if user already exists
        if username in users:
            return False, "Username already exists"
        
        # Check if email already exists
        for user_data in users.values():
            if user_data.get('email') == email:
                return False, "Email already exists"
        
        # Validate input
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters"
        
        if '@' not in email or '.' not in email:
            return False, "Invalid email format"
        
        # Create user
        users[username] = {
            'username': username,
            'password_hash': generate_password_hash(password),
            'email': email,
            'role': role,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'active': True
        }
        
        if self.save_users(users):
            logger.info(f"User {username} created successfully")
            return True, "User created successfully"
        else:
            return False, "Failed to save user"
    
    def authenticate_user(self, username, password):
        """Authenticate a user."""
        users = self.load_users()
        
        if username not in users:
            return False
        
        user = users[username]
        if not user.get('active', True):
            return False
        
        if check_password_hash(user['password_hash'], password):
            # Update last login
            users[username]['last_login'] = datetime.now().isoformat()
            self.save_users(users)
            return True
        
        return False
    
    def get_user(self, username):
        """Get user information."""
        users = self.load_users()
        return users.get(username)
    
    def list_users(self):
        """List all users (without passwords)."""
        users = self.load_users()
        user_list = []
        for username, user_data in users.items():
            safe_user = {
                'username': user_data['username'],
                'email': user_data['email'],
                'role': user_data['role'],
                'created_at': user_data['created_at'],
                'last_login': user_data.get('last_login'),
                'active': user_data.get('active', True)
            }
            user_list.append(safe_user)
        return user_list
    
    def deactivate_user(self, username):
        """Deactivate a user."""
        users = self.load_users()
        if username in users and username != 'admin':  # Protect admin user
            users[username]['active'] = False
            return self.save_users(users)
        return False
    
    def activate_user(self, username):
        """Activate a user."""
        users = self.load_users()
        if username in users:
            users[username]['active'] = True
            return self.save_users(users)
        return False