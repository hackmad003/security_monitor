"""
Rate Limiting Module
Provides rate limiting functionality for API endpoints
"""

import time
from collections import defaultdict, deque
from typing import Dict, Tuple, Optional
import threading
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Simple in-memory rate limiter using token bucket algorithm
    """
    
    def __init__(self, requests_per_minute: int = 60, burst_size: int = 10):
        """
        Initialize rate limiter
        
        Args:
            requests_per_minute: Maximum requests allowed per minute
            burst_size: Maximum burst size (tokens refilled instantly)
        """
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.window_size = 60  # seconds
        
        # Storage for request timestamps by identifier (IP or user)
        self._requests: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()
    
    def is_allowed(self, identifier: str) -> Tuple[bool, Optional[int]]:
        """
        Check if request is allowed for identifier
        
        Args:
            identifier: Unique identifier (IP address, user ID, etc.)
            
        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        with self._lock:
            current_time = time.time()
            
            # Get request queue for this identifier
            request_queue = self._requests[identifier]
            
            # Remove old requests outside the window
            while request_queue and request_queue[0] < current_time - self.window_size:
                request_queue.popleft()
            
            # Check if under limit
            if len(request_queue) < self.requests_per_minute:
                request_queue.append(current_time)
                return True, None
            
            # Rate limited - calculate retry after
            oldest_request = request_queue[0]
            retry_after = int(oldest_request + self.window_size - current_time) + 1
            
            logger.warning(f"Rate limit exceeded for {identifier}")
            return False, retry_after
    
    def get_remaining(self, identifier: str) -> int:
        """
        Get remaining requests for identifier
        
        Args:
            identifier: Unique identifier
            
        Returns:
            Number of remaining requests
        """
        with self._lock:
            current_time = time.time()
            request_queue = self._requests[identifier]
            
            # Remove old requests
            while request_queue and request_queue[0] < current_time - self.window_size:
                request_queue.popleft()
            
            return max(0, self.requests_per_minute - len(request_queue))
    
    def reset(self, identifier: str) -> None:
        """
        Reset rate limit for identifier
        
        Args:
            identifier: Unique identifier
        """
        with self._lock:
            if identifier in self._requests:
                del self._requests[identifier]
    
    def cleanup_old_entries(self, max_age_minutes: int = 60) -> None:
        """
        Cleanup old entries to prevent memory bloat
        
        Args:
            max_age_minutes: Maximum age of entries to keep
        """
        with self._lock:
            current_time = time.time()
            cutoff_time = current_time - (max_age_minutes * 60)
            
            # Find identifiers with no recent requests
            to_remove = []
            for identifier, request_queue in self._requests.items():
                if not request_queue or request_queue[-1] < cutoff_time:
                    to_remove.append(identifier)
            
            # Remove old entries
            for identifier in to_remove:
                del self._requests[identifier]
            
            if to_remove:
                logger.info(f"Cleaned up {len(to_remove)} old rate limit entries")


class EndpointRateLimiter:
    """
    Rate limiter with different limits per endpoint
    """
    
    def __init__(self):
        """Initialize endpoint rate limiter with default limits"""
        self.limiters = {
            'login': RateLimiter(requests_per_minute=5, burst_size=3),      # Strict for login
            'api_write': RateLimiter(requests_per_minute=30, burst_size=10), # Moderate for writes
            'api_read': RateLimiter(requests_per_minute=100, burst_size=20), # Generous for reads
            'default': RateLimiter(requests_per_minute=60, burst_size=10)    # Default
        }
    
    def is_allowed(self, identifier: str, endpoint_type: str = 'default') -> Tuple[bool, Optional[int]]:
        """
        Check if request is allowed
        
        Args:
            identifier: Unique identifier
            endpoint_type: Type of endpoint (login, api_write, api_read, default)
            
        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        limiter = self.limiters.get(endpoint_type, self.limiters['default'])
        return limiter.is_allowed(identifier)
    
    def get_remaining(self, identifier: str, endpoint_type: str = 'default') -> int:
        """Get remaining requests for identifier and endpoint type"""
        limiter = self.limiters.get(endpoint_type, self.limiters['default'])
        return limiter.get_remaining(identifier)
    
    def reset(self, identifier: str, endpoint_type: Optional[str] = None) -> None:
        """Reset rate limit for identifier"""
        if endpoint_type:
            limiter = self.limiters.get(endpoint_type)
            if limiter:
                limiter.reset(identifier)
        else:
            # Reset for all endpoint types
            for limiter in self.limiters.values():
                limiter.reset(identifier)
    
    def cleanup_old_entries(self) -> None:
        """Cleanup old entries from all limiters"""
        for limiter in self.limiters.values():
            limiter.cleanup_old_entries()


# Global rate limiter instance
_global_rate_limiter = EndpointRateLimiter()


def get_rate_limiter() -> EndpointRateLimiter:
    """Get global rate limiter instance"""
    return _global_rate_limiter


# FastAPI dependency for rate limiting
async def rate_limit_dependency(
    identifier: str,
    endpoint_type: str = 'default'
) -> None:
    """
    FastAPI dependency for rate limiting
    
    Usage:
        @app.get("/api/endpoint", dependencies=[Depends(rate_limit_dependency)])
        async def my_endpoint():
            ...
    """
    from fastapi import HTTPException, status
    
    limiter = get_rate_limiter()
    allowed, retry_after = limiter.is_allowed(identifier, endpoint_type)
    
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )
