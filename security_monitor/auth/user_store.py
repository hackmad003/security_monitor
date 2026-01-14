"""
User Store Module
Manages user accounts for authentication
"""

import os
import json
from pathlib import Path
from typing import Optional, Dict, List
from datetime import datetime
import logging

from .jwt_handler import hash_password

logger = logging.getLogger(__name__)


class UserStore:
    """Simple file-based user store for authentication"""
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize user store
        
        Args:
            storage_path: Path to users.json file
                         Defaults to ~/.security_monitor/users.json
        """
        if storage_path is None:
            storage_path = Path.home() / ".security_monitor" / "users.json"
        
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize with default admin user if file doesn't exist
        if not self.storage_path.exists():
            self._create_default_admin()
    
    def _create_default_admin(self):
        """Create default admin user"""
        default_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "ChangeMe123!")
        
        logger.warning(
            "Creating default admin user. "
            "IMPORTANT: Change the password immediately!"
        )
        
        self.create_user(
            username="admin",
            password=default_password,
            full_name="Administrator",
            roles=["admin"]
        )
        
        print("\n" + "=" * 70)
        print("⚠️  DEFAULT ADMIN USER CREATED")
        print("=" * 70)
        print(f"\n  Username: admin")
        print(f"  Password: {default_password}")
        print("\n  ⚠️  SECURITY WARNING: Change this password immediately!")
        print(f"  Storage: {self.storage_path}")
        print("\n" + "=" * 70 + "\n")
    
    def _load_users(self) -> Dict:
        """Load users from storage file"""
        if not self.storage_path.exists():
            return {}
        
        try:
            with open(self.storage_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading users: {e}")
            return {}
    
    def _save_users(self, users: Dict):
        """Save users to storage file"""
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(users, f, indent=2)
            
            # Set restrictive permissions
            try:
                os.chmod(self.storage_path, 0o600)
            except Exception as e:
                logger.warning(f"Could not set file permissions: {e}")
                
        except Exception as e:
            logger.error(f"Error saving users: {e}")
            raise
    
    def create_user(
        self,
        username: str,
        password: str,
        full_name: str = "",
        email: str = "",
        roles: Optional[List[str]] = None
    ) -> bool:
        """
        Create a new user
        
        Args:
            username: Username (must be unique)
            password: Plain text password (will be hashed)
            full_name: User's full name
            email: User's email address
            roles: List of roles (e.g., ['admin', 'viewer'])
            
        Returns:
            True if user created, False if username already exists
        """
        users = self._load_users()
        
        if username in users:
            logger.warning(f"Cannot create user: Username already exists: {username}")
            return False
        
        if roles is None:
            roles = ['viewer']
        
        users[username] = {
            'username': username,
            'password_hash': hash_password(password),
            'full_name': full_name,
            'email': email,
            'roles': roles,
            'created_at': datetime.now().isoformat(),
            'enabled': True
        }
        
        self._save_users(users)
        logger.info(f"Created user: {username}")
        
        return True
    
    def get_user(self, username: str) -> Optional[Dict]:
        """
        Get user by username
        
        Args:
            username: Username to look up
            
        Returns:
            User dictionary or None if not found
        """
        users = self._load_users()
        user = users.get(username)
        
        if user and not user.get('enabled', True):
            logger.warning(f"User account disabled: {username}")
            return None
        
        return user
    
    def update_user(
        self,
        username: str,
        full_name: Optional[str] = None,
        email: Optional[str] = None,
        roles: Optional[List[str]] = None,
        enabled: Optional[bool] = None
    ) -> bool:
        """
        Update user information (not password)
        
        Args:
            username: Username to update
            full_name: New full name (optional)
            email: New email (optional)
            roles: New roles list (optional)
            enabled: Enable/disable account (optional)
            
        Returns:
            True if updated, False if user not found
        """
        users = self._load_users()
        
        if username not in users:
            logger.warning(f"Cannot update: User not found: {username}")
            return False
        
        if full_name is not None:
            users[username]['full_name'] = full_name
        if email is not None:
            users[username]['email'] = email
        if roles is not None:
            users[username]['roles'] = roles
        if enabled is not None:
            users[username]['enabled'] = enabled
        
        self._save_users(users)
        logger.info(f"Updated user: {username}")
        
        return True
    
    def change_password(self, username: str, new_password: str) -> bool:
        """
        Change user password
        
        Args:
            username: Username
            new_password: New plain text password (will be hashed)
            
        Returns:
            True if changed, False if user not found
        """
        users = self._load_users()
        
        if username not in users:
            logger.warning(f"Cannot change password: User not found: {username}")
            return False
        
        users[username]['password_hash'] = hash_password(new_password)
        self._save_users(users)
        logger.info(f"Changed password for user: {username}")
        
        return True
    
    def delete_user(self, username: str) -> bool:
        """
        Delete a user
        
        Args:
            username: Username to delete
            
        Returns:
            True if deleted, False if not found
        """
        users = self._load_users()
        
        if username not in users:
            logger.warning(f"Cannot delete: User not found: {username}")
            return False
        
        # Prevent deleting the last admin
        if 'admin' in users[username].get('roles', []):
            admin_count = sum(1 for u in users.values() if 'admin' in u.get('roles', []))
            if admin_count <= 1:
                logger.error("Cannot delete the last admin user")
                return False
        
        del users[username]
        self._save_users(users)
        logger.info(f"Deleted user: {username}")
        
        return True
    
    def list_users(self) -> List[Dict]:
        """
        Get list of all users (without password hashes)
        
        Returns:
            List of user dictionaries
        """
        users = self._load_users()
        
        # Return without password hashes
        return [
            {k: v for k, v in user.items() if k != 'password_hash'}
            for user in users.values()
        ]
    
    def has_role(self, username: str, role: str) -> bool:
        """
        Check if user has a specific role
        
        Args:
            username: Username to check
            role: Role name to check for
            
        Returns:
            True if user has the role, False otherwise
        """
        user = self.get_user(username)
        if not user:
            return False
        
        return role in user.get('roles', [])
