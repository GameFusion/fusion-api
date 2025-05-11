#!/usr/bin/env python
import argparse
import os
import sys
import string
import random
import secrets
import psycopg2
from psycopg2 import sql
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
from pathlib import Path
if not Path.cwd().joinpath(".env").exists():
    print("⚠️  Warning: .env file not found in current directory:", Path.cwd())
load_dotenv(dotenv_path=Path.cwd() / ".env")


def generate_secure_password(length=16):
    """Generate a secure random password of specified length"""
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_api_key(expires_in_days=365 * 5, user_id=None, no_expiry=False, is_admin=False, auth_method=None):
    """Generate a JWT-based API key for use with the system"""
    # Use a secure token as the basis
    token_hex = secrets.token_hex(32)
    
    # Create a JWT with some standard claims
    payload = {
        'sub': token_hex,
        'iat': datetime.utcnow(),
        'jti': secrets.token_hex(16)
    }

    if user_id:
        payload['user_id'] = user_id

    if is_admin:
        payload['is_admin'] = True

    if auth_method:
        payload['auth_method'] = auth_method # auth_method=["api_key", "basic_auth"]
        
    if not no_expiry:
        payload['exp'] = datetime.utcnow() + timedelta(days=expires_in_days)
    
    # Sign with a secret key from environment variables
    jwt_secret = os.environ.get('JWT_SECRET_KEY')
    if not jwt_secret:
        print("Warning: JWT_SECRET_KEY not found in environment. Using default key (not secure for production).")
        jwt_secret = 'your_jwt_secret_key'
    
    encoded_jwt = jwt.encode(payload, jwt_secret, algorithm='HS256')
    
    # Return the JWT string
    return encoded_jwt

def get_db_connection():
    """Connect to the database using environment variables"""
    db_config = {
        'host': os.environ.get('DB_HOST', 'localhost'),
        'database': os.environ.get('DB_NAME', 'cbpapi'),
        'user': os.environ.get('DB_USER', 'postgres'),
        'password': os.environ.get('DB_PASSWORD')
    }
    
    # Check if required environment variables are set
    if not db_config['password']:
        print("Error: DB_PASSWORD environment variable is required")
        print("Please create a .env file with the required database credentials")
        return None
    
    try:
        return psycopg2.connect(**db_config)
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def find_user(identifier, id_type='username'):
    """Find a user by username, id, or email"""
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor()
    
    if id_type == 'username':
        cursor.execute("SELECT id, username, email, role FROM users WHERE username = %s", (identifier,))
    elif id_type == 'id':
        cursor.execute("SELECT id, username, email, role FROM users WHERE id = %s", (identifier,))
    elif id_type == 'email':
        cursor.execute("SELECT id, username, email, role FROM users WHERE email = %s", (identifier,))
    else:
        print(f"Invalid identifier type: {id_type}")
        conn.close()
        return None
    
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not user:
        return None
    
    return {
        'id': user[0],
        'username': user[1],
        'email': user[2],
        'role': user[3]
    }

def create_user(username, email, role, expires_in_days=365 * 5, no_expiry=False):
    """Create a new user in the database with random password and API key"""
    # Generate password and API key
    password = generate_secure_password()
    is_admin = role == "admin"
    api_key = generate_api_key(expires_in_days=expires_in_days, no_expiry=no_expiry, is_admin=is_admin)
    
    # Hash the password for storage
    password_hash = generate_password_hash(password)
    
    # Set default API quota based on role
    if role.lower() == 'admin':
        api_quota = 10000
    else:
        api_quota = 1000
    
    # Connect to the database
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor()
    
    try:
        # Check if user already exists
        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            print(f"Error: User '{username}' already exists")
            conn.close()
            return None
        
        # Insert the new user
        cursor.execute("""
            INSERT INTO users (username, password_hash, email, role, api_quota, api_key, active, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            username, 
            password_hash, 
            email, 
            role.lower(), 
            api_quota, 
            api_key, 
            True, 
            datetime.now()
        ))
        
        user_id = cursor.fetchone()[0]
        
        # Commit the transaction
        conn.commit()
        
        # Close the connection
        cursor.close()
        conn.close()
        
        return {
            'id': user_id,
            'username': username,
            'password': password,  # Only shown once during creation
            'email': email,
            'role': role.lower(),
            'api_key': api_key,
            'api_quota': api_quota
        }
        
    except Exception as e:
        print(f"Database error: {e}")
        conn.rollback()
        cursor.close()
        conn.close()
        return None

def regenerate_api_key(identifier, id_type='username'):
    """Regenerate API key for an existing user"""
    # Find the user first
    user = find_user(identifier, id_type)
    if not user:
        print(f"Error: User not found with {id_type} '{identifier}'")
        return None
    
    # Generate a new API key
    new_api_key = generate_api_key()
    
    # Connect to the database
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor()
    
    try:
        # Update the user's API key
        cursor.execute("""
            UPDATE users 
            SET api_key = %s, updated_at = %s
            WHERE id = %s
            RETURNING username, email, role, api_quota
        """, (
            new_api_key,
            datetime.now(),
            user['id']
        ))
        
        updated_user = cursor.fetchone()
        
        # Commit the transaction
        conn.commit()
        
        # Close the connection
        cursor.close()
        conn.close()
        
        if not updated_user:
            return None
        
        return {
            'id': user['id'],
            'username': updated_user[0],
            'email': updated_user[1],
            'role': updated_user[2],
            'api_key': new_api_key,
            'api_quota': updated_user[3]
        }
        
    except Exception as e:
        print(f"Database error: {e}")
        conn.rollback()
        cursor.close()
        conn.close()
        return None

def reset_password(identifier, id_type='username', new_password=None):
    """Reset password for an existing user"""
    # Find the user first
    user = find_user(identifier, id_type)
    if not user:
        print(f"Error: User not found with {id_type} '{identifier}'")
        return None
    
    # Generate a new password if not provided
    if new_password is None:
        new_password = generate_secure_password()
    
    # Hash the new password using Werkzeug
    password_hash = generate_password_hash(new_password)
    
    # Connect to the database
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor()
    
    try:
        # Update the user's password
        cursor.execute("""
            UPDATE users 
            SET password_hash = %s, updated_at = %s
            WHERE id = %s
            RETURNING username, email, role, api_quota, api_key
        """, (
            password_hash,
            datetime.now(),
            user['id']
        ))
        
        updated_user = cursor.fetchone()
        
        # Commit the transaction
        conn.commit()
        
        # Close the connection
        cursor.close()
        conn.close()
        
        if not updated_user:
            return None
        
        return {
            'id': user['id'],
            'username': updated_user[0],
            'email': updated_user[1],
            'role': updated_user[2],
            'password': new_password,  # Only returned once
            'api_quota': updated_user[3],
            'api_key': updated_user[4]
        }
        
    except Exception as e:
        print(f"Database error: {e}")
        conn.rollback()
        cursor.close()
        conn.close()
        return None

def save_credentials_to_file(user_info, file_path=None):
    """Save user credentials to a file"""
    if not file_path:
        # Use username for the file name
        file_path = f"{user_info['username']}_credentials.txt"
    
    try:
        with open(file_path, 'w') as f:
            f.write("========================================\n")
            f.write("   API USER CREDENTIALS\n")
            f.write("========================================\n\n")
            f.write(f"User ID:     {user_info['id']}\n")
            f.write(f"Username:    {user_info['username']}\n")
            f.write(f"Email:       {user_info['email']}\n")
            f.write(f"Role:        {user_info['role']}\n")
            f.write(f"API Quota:   {user_info.get('api_quota', 'N/A')} requests per day\n\n")
            f.write("--- IMPORTANT: SAVE THESE CREDENTIALS ---\n")
            if 'password' in user_info:
                f.write(f"Password:    {user_info['password']}\n")
            f.write(f"API Key:     {user_info['api_key']}\n")
            f.write("----------------------------------------\n\n")
            f.write("Documentation: https://cbpapi.com/docs\n")
            f.write("Support: support@cbpapi.com\n")
            
        print(f"Credentials saved to: {file_path}")
        return True
    except Exception as e:
        print(f"Error saving credentials to file: {e}")
        return False

def print_user_info(user_info, show_header=True):
    """Print user information to console"""
    if show_header:
        print("\n===== User Information =====")
    print(f"User ID:     {user_info['id']}")
    print(f"Username:    {user_info['username']}")
    print(f"Email:       {user_info['email']}")
    print(f"Role:        {user_info['role']}")
    if 'api_quota' in user_info:
        print(f"API Quota:   {user_info['api_quota']} requests per day")
    
    print("\n--- IMPORTANT: CREDENTIALS ---")
    if 'password' in user_info:
        print(f"Password:    {user_info['password']}")
        print("Note: The password will not be shown again.")
    print(f"API Key:     {user_info['api_key']}")
    print("---------------------------------------")

def main():
    """Main entry point for the script"""
    parser = argparse.ArgumentParser(description='CBP-API User Management Tool')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Create user command
    create_parser = subparsers.add_parser('create', help='Create a new user')
    create_parser.add_argument('username', help='Username for the new user')
    create_parser.add_argument('email', help='Email address for the new user')
    create_parser.add_argument('--role', default='user', choices=['user', 'admin'], help='User role (default: user)')
    create_parser.add_argument('--output-file', help='Save credentials to specified file')
    create_parser.add_argument('--expires-in-days', type=int, default=1825,
                           help='Number of days until API key expires (default: 1825, i.e. 5 years)')
    create_parser.add_argument('--no-expiry', action='store_true',
                           help='Generate a key with no expiration')

    # Regenerate API key command
    regen_parser = subparsers.add_parser('regenerate-key', help='Regenerate API key for a user')
    regen_parser.add_argument('identifier', help='Username, ID, or email of the user')
    regen_parser.add_argument('--id-type', default='username', choices=['username', 'id', 'email'], 
                              help='Type of identifier (default: username)')
    regen_parser.add_argument('--output-file', help='Save credentials to specified file')
    
    # Reset password command
    reset_parser = subparsers.add_parser('reset-password', help='Reset password for a user')
    reset_parser.add_argument('identifier', help='Username, ID, or email of the user')
    reset_parser.add_argument('--id-type', default='username', choices=['username', 'id', 'email'], 
                             help='Type of identifier (default: username)')
    reset_parser.add_argument('--password', help='New password (if not provided, a secure password will be generated)')
    reset_parser.add_argument('--output-file', help='Save credentials to specified file')
    

    args = parser.parse_args()
    
    # Check command
    if not args.command:
        parser.print_help()
        return 1
    
    # Execute command
    if args.command == 'create':
        user_info = create_user(
            args.username, 
            args.email, 
            args.role,
            expires_in_days=args.expires_in_days,
            no_expiry=args.no_expiry
        )
        if user_info:
            print_user_info(user_info)
            if args.output_file:
                save_credentials_to_file(user_info, args.output_file)
            else:
                save_credentials_to_file(user_info)
            return 0
        else:
            print("Failed to create user")
            return 1
            
    elif args.command == 'regenerate-key':
        user_info = regenerate_api_key(args.identifier, args.id_type)
        if user_info:
            print(f"API key regenerated for user: {user_info['username']}")
            print_user_info(user_info)
            if args.output_file:
                save_credentials_to_file(user_info, args.output_file)
            else:
                save_credentials_to_file(user_info)
            return 0
        else:
            print("Failed to regenerate API key")
            return 1
    
    elif args.command == 'reset-password':
        user_info = reset_password(args.identifier, args.id_type, args.password)
        if user_info:
            print(f"Password reset for user: {user_info['username']}")
            print_user_info(user_info)
            if args.output_file:
                save_credentials_to_file(user_info, args.output_file)
            else:
                save_credentials_to_file(user_info)
            return 0
        else:
            print("Failed to reset password")
            return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())