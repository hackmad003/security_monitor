"""
Secure Credential Storage Module
Provides encrypted storage for sensitive credentials
"""

import os
from pathlib import Path
from cryptography.fernet import Fernet
from typing import Dict, Optional
import json
import logging

logger = logging.getLogger(__name__)


class SecureCredentialStore:
    """Secure credential storage using encryption"""
    
    def __init__(self, storage_dir: Optional[Path] = None):
        """
        Initialize secure credential store
        
        Args:
            storage_dir: Directory for storing encrypted credentials
                        Defaults to user home directory
        """
        if storage_dir is None:
            storage_dir = Path.home() / ".security_monitor"
        
        self.storage_dir = Path(storage_dir)
        self.key_file = self.storage_dir / "key.bin"
        self.creds_file = self.storage_dir / "credentials.enc"
        self._ensure_key_exists()
    
    def _ensure_key_exists(self):
        """Create encryption key if it doesn't exist"""
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        if not self.key_file.exists():
            logger.info("Creating new encryption key")
            key = Fernet.generate_key()
            self.key_file.write_bytes(key)
            
            # Set restrictive permissions
            try:
                os.chmod(self.key_file, 0o600)
            except Exception as e:
                logger.warning(f"Could not set file permissions: {e}")
    
    def _get_cipher(self) -> Fernet:
        """Get Fernet cipher instance"""
        key = self.key_file.read_bytes()
        return Fernet(key)
    
    def store_credentials(self, target_name: str, username: str, password: str):
        """
        Store encrypted credentials for a target
        
        Args:
            target_name: Name of the target system
            username: Username for authentication
            password: Password for authentication
        """
        cipher = self._get_cipher()
        
        # Load existing credentials
        creds = self._load_all_credentials()
        
        # Add/update credentials
        creds[target_name] = {
            'username': username,
            'password': password
        }
        
        # Encrypt and save
        encrypted = cipher.encrypt(json.dumps(creds).encode())
        self.creds_file.write_bytes(encrypted)
        
        # Set restrictive permissions
        try:
            os.chmod(self.creds_file, 0o600)
        except Exception as e:
            logger.warning(f"Could not set file permissions: {e}")
        
        logger.info(f"Stored credentials for target: {target_name}")
    
    def get_credentials(self, target_name: str) -> Optional[Dict[str, str]]:
        """
        Retrieve decrypted credentials for a target
        
        Args:
            target_name: Name of the target system
            
        Returns:
            Dictionary with 'username' and 'password' keys, or None if not found
        """
        creds = self._load_all_credentials()
        return creds.get(target_name)
    
    def delete_credentials(self, target_name: str) -> bool:
        """
        Delete credentials for a target
        
        Args:
            target_name: Name of the target system
            
        Returns:
            True if credentials were deleted, False if not found
        """
        creds = self._load_all_credentials()
        
        if target_name not in creds:
            return False
        
        del creds[target_name]
        
        # Re-encrypt and save
        cipher = self._get_cipher()
        encrypted = cipher.encrypt(json.dumps(creds).encode())
        self.creds_file.write_bytes(encrypted)
        
        logger.info(f"Deleted credentials for target: {target_name}")
        return True
    
    def list_targets(self) -> list:
        """
        Get list of targets with stored credentials
        
        Returns:
            List of target names
        """
        creds = self._load_all_credentials()
        return list(creds.keys())
    
    def _load_all_credentials(self) -> Dict:
        """
        Load and decrypt all credentials
        
        Returns:
            Dictionary of all stored credentials
        """
        if not self.creds_file.exists():
            return {}
        
        try:
            cipher = self._get_cipher()
            encrypted = self.creds_file.read_bytes()
            decrypted = cipher.decrypt(encrypted)
            return json.loads(decrypted)
        except Exception as e:
            logger.error(f"Error loading credentials: {e}")
            return {}


class CredentialValidator:
    """Validates credential inputs to prevent injection attacks"""
    
    @staticmethod
    def validate_credential_input(value: str, field_name: str, max_length: int = 256) -> None:
        """
        Validate credential inputs to prevent injection
        
        Args:
            value: The credential value to validate
            field_name: Name of the field (for error messages)
            max_length: Maximum allowed length
            
        Raises:
            ValueError: If validation fails
        """
        if not value:
            raise ValueError(f"{field_name} cannot be empty")
        
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string")
        
        # Check for suspicious characters that could be used in injection attacks
        dangerous_chars = [';', '&', '|', '$', '`', '\n', '\r', '<', '>', '"']
        for char in dangerous_chars:
            if char in value:
                raise ValueError(
                    f"{field_name} contains potentially dangerous character: {char}"
                )
        
        # Length limits
        if len(value) > max_length:
            raise ValueError(f"{field_name} exceeds maximum length of {max_length}")
        
        # Check for null bytes
        if '\x00' in value:
            raise ValueError(f"{field_name} contains null bytes")
    
    @staticmethod
    def validate_hostname(hostname: str) -> None:
        """
        Validate hostname/server name
        
        Args:
            hostname: The hostname to validate
            
        Raises:
            ValueError: If validation fails
        """
        if not hostname:
            raise ValueError("Hostname cannot be empty")
        
        # Basic hostname validation
        import re
        # Allow alphanumeric, dots, hyphens, and underscores
        if not re.match(r'^[a-zA-Z0-9._-]+$', hostname):
            raise ValueError(
                "Hostname can only contain alphanumeric characters, dots, hyphens, and underscores"
            )
        
        if len(hostname) > 253:
            raise ValueError("Hostname exceeds maximum length")
    
    @staticmethod
    def sanitize_for_powershell(value: str) -> str:
        """
        Sanitize a value for use in PowerShell commands
        
        Args:
            value: The value to sanitize
            
        Returns:
            Sanitized value safe for PowerShell
        """
        # Escape single quotes by doubling them
        return value.replace("'", "''")
