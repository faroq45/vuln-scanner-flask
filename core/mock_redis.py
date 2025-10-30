"""
Mock Redis implementation for testing without a Redis server
"""
import json
import time
from typing import Any, Optional, Dict


class MockRedis:
    """Simple in-memory mock of Redis for testing purposes."""
    
    def __init__(self):
        self.data: Dict[str, Any] = {}
        self.expires: Dict[str, float] = {}
    
    def set(self, key: str, value: Any, ex: Optional[int] = None) -> bool:
        """Set a key-value pair with optional expiry."""
        self.data[key] = value
        if ex:
            self.expires[key] = time.time() + ex
        return True
    
    def get(self, key) -> Optional[Any]:
        """Get value by key."""
        # Convert bytes to string if needed
        if isinstance(key, bytes):
            key = key.decode('utf-8')
        
        # Check if key has expired
        if key in self.expires and time.time() > self.expires[key]:
            del self.data[key]
            del self.expires[key]
            return None
        
        return self.data.get(key)
    
    def delete(self, key) -> bool:
        """Delete a key."""
        # Convert bytes to string if needed
        if isinstance(key, bytes):
            key = key.decode('utf-8')
            
        if key in self.data:
            del self.data[key]
        if key in self.expires:
            del self.expires[key]
        return True
    
    def exists(self, key) -> bool:
        """Check if key exists."""
        return self.get(key) is not None
    
    def incr(self, key: str) -> int:
        """Increment counter."""
        current = self.data.get(key, 0)
        if isinstance(current, (int, str)):
            try:
                new_value = int(current) + 1
                self.data[key] = new_value
                return new_value
            except ValueError:
                pass
        self.data[key] = 1
        return 1
    
    def scan_iter(self, match: str = '*'):
        """Iterate over keys matching pattern."""
        import fnmatch
        for key in list(self.data.keys()):
            # Check if key has expired
            if key in self.expires and time.time() > self.expires[key]:
                del self.data[key]
                del self.expires[key]
                continue
            if fnmatch.fnmatch(key, match):
                yield key.encode('utf-8')
    
    def sadd(self, key: str, value: Any):
        """Add to set."""
        if key not in self.data:
            self.data[key] = set()
        if isinstance(self.data[key], set):
            self.data[key].add(value)
        return True
    
    def smembers(self, key: str):
        """Get set members."""
        return self.data.get(key, set())
    
    def dbsize(self) -> int:
        """Get database size."""
        # Clean expired keys first
        expired_keys = []
        current_time = time.time()
        for key in self.data.keys():
            if key in self.expires and current_time > self.expires[key]:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.data[key]
            del self.expires[key]
            
        return len(self.data)
    
    def flushdb(self):
        """Clear database."""
        self.data.clear()
        self.expires.clear()
    
    def ping(self):
        """Ping the Redis server (mock always succeeds)."""
        return True


# Simple wrapper to provide the same interface as the existing RedisManager
class MockRedisManager:
    """Mock version of RedisManager for testing."""
    
    def __init__(self):
        self.r = MockRedis()
        from core.utils import Utils
        self.utils = Utils()
    
    def store(self, key, value):
        return self.r.set(key, value)
    
    def get(self, key):
        return self.r.get(key)
    
    def set(self, key, value, ex=None):
        return self.r.set(key, value, ex=ex)
    
    def delete(self, key):
        return self.r.delete(key)
    
    def exists(self, key):
        return self.r.exists(key)
    
    def get_scan_progress(self):
        return 0  # No active scans in mock
    
    def get_session_state(self):
        return self.r.get('sess_state')
    
    def get_vuln_data(self):
        return {}  # No vulnerabilities in mock
    
    def initialize(self):
        self.r.set('p_scan-count', 0)
        self.r.set('p_last-scan', 'N/A')