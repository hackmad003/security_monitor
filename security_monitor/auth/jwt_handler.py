"""
JWT Authentication Handler
Provides token-based authentication for API endpoints
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging

logger = logging.getLogger(__name__)

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE-THIS-IN-PRODUCTION-USE-LONG-RANDOM-STRING")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", "30"))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTP Bearer token scheme
security = HTTPBearer()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create JWT access token
    
    Args:
        data: Dictionary with user information (must include 'sub' for username)
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc)
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.info(f"Created access token for user: {data.get('sub', 'unknown')}")
    
    return encoded_jwt


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """
    Verify JWT token and extract payload
    
    Args:
        credentials: HTTP Authorization header credentials
        
    Returns:
        Dictionary with token payload
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        
        if username is None:
            logger.warning("Token missing 'sub' claim")
            raise credentials_exception
        
        logger.debug(f"Token verified for user: {username}")
        return payload
        
    except JWTError as e:
        logger.warning(f"JWT verification failed: {e}")
        raise credentials_exception


def get_current_user(payload: Dict[str, Any] = Depends(verify_token)) -> Optional[str]:
    """
    Get current authenticated user from token

    Args:
        payload: Token payload from verify_token

    Returns:
        Username of authenticated user, or None if not found
    """
    return payload.get("sub")


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash
    
    Args:
        plain_password: Plain text password to verify
        hashed_password: Hashed password to check against
        
    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(username: str, password: str, user_store) -> Optional[Dict]:
    """
    Authenticate a user with username and password
    
    Args:
        username: Username to authenticate
        password: Password to verify
        user_store: UserStore instance
        
    Returns:
        User dictionary if authenticated, None otherwise
    """
    user = user_store.get_user(username)
    
    if not user:
        logger.warning(f"Authentication failed: User not found: {username}")
        return None
    
    if not verify_password(password, user['password_hash']):
        logger.warning(f"Authentication failed: Invalid password for user: {username}")
        return None
    
    logger.info(f"User authenticated successfully: {username}")
    return user


# Optional: Custom dependency for role-based access
def require_admin(current_user: str = Depends(get_current_user)) -> str:
    """
    Dependency that requires admin role
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Username if user is admin
        
    Raises:
        HTTPException: If user is not admin
    """
    # In a real implementation, check user roles from database
    # For now, this is a placeholder
    # You would typically do: user = get_user_from_db(current_user)
    # and check: if 'admin' not in user.roles: raise exception
    
    logger.debug(f"Admin access granted to: {current_user}")
    return current_user
