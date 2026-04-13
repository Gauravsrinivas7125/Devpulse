"""
DevPulse - Redis Client with Development Fallback
Real Redis connection with in-memory fallback for development
"""

import os
import logging
import json
from typing import Any, Optional, Dict
from datetime import timedelta

logger = logging.getLogger(__name__)

# Try to import redis
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("Redis not installed. Using in-memory fallback.")


class RedisClient:
    """Redis client with development fallback"""
    
    def __init__(self):
        self.redis_url = os.getenv("REDIS_URL")
        self.use_redis = REDIS_AVAILABLE and bool(self.redis_url)
        
        if self.use_redis:
            try:
                self.client = redis.from_url(self.redis_url, decode_responses=True)
                # Test connection
                self.client.ping()
                logger.info("Connected to Redis")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {str(e)}. Using in-memory fallback.")
                self.use_redis = False
                self.client = None
        else:
            logger.info("Using in-memory cache (development mode)")
            self.client = None
        
        # In-memory fallback
        self._memory_store: Dict[str, Any] = {}

    def get(self, key: str) -> Optional[str]:
        """Get value from cache"""
        try:
            if self.use_redis and self.client:
                return self.client.get(key)
            else:
                return self._memory_store.get(key)
        except Exception as e:
            logger.error(f"Redis GET error: {str(e)}")
            return self._memory_store.get(key)

    def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        """Set value in cache with optional expiration (seconds)"""
        try:
            if self.use_redis and self.client:
                if ex:
                    self.client.setex(key, ex, value)
                else:
                    self.client.set(key, value)
                return True
            else:
                self._memory_store[key] = value
                # Note: In-memory doesn't support expiration
                return True
        except Exception as e:
            logger.error(f"Redis SET error: {str(e)}")
            self._memory_store[key] = value
            return False

    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            if self.use_redis and self.client:
                self.client.delete(key)
                return True
            else:
                self._memory_store.pop(key, None)
                return True
        except Exception as e:
            logger.error(f"Redis DELETE error: {str(e)}")
            return False

    def exists(self, key: str) -> bool:
        """Check if key exists"""
        try:
            if self.use_redis and self.client:
                return bool(self.client.exists(key))
            else:
                return key in self._memory_store
        except Exception as e:
            logger.error(f"Redis EXISTS error: {str(e)}")
            return False

    def incr(self, key: str, amount: int = 1) -> int:
        """Increment counter"""
        try:
            if self.use_redis and self.client:
                return self.client.incrby(key, amount)
            else:
                current = int(self._memory_store.get(key, 0))
                new_value = current + amount
                self._memory_store[key] = str(new_value)
                return new_value
        except Exception as e:
            logger.error(f"Redis INCR error: {str(e)}")
            return 0

    def decr(self, key: str, amount: int = 1) -> int:
        """Decrement counter"""
        try:
            if self.use_redis and self.client:
                return self.client.decrby(key, amount)
            else:
                current = int(self._memory_store.get(key, 0))
                new_value = current - amount
                self._memory_store[key] = str(new_value)
                return new_value
        except Exception as e:
            logger.error(f"Redis DECR error: {str(e)}")
            return 0

    def lpush(self, key: str, *values) -> int:
        """Push values to list (left)"""
        try:
            if self.use_redis and self.client:
                return self.client.lpush(key, *values)
            else:
                if key not in self._memory_store:
                    self._memory_store[key] = []
                if not isinstance(self._memory_store[key], list):
                    self._memory_store[key] = []
                for value in reversed(values):
                    self._memory_store[key].insert(0, value)
                return len(self._memory_store[key])
        except Exception as e:
            logger.error(f"Redis LPUSH error: {str(e)}")
            return 0

    def rpush(self, key: str, *values) -> int:
        """Push values to list (right)"""
        try:
            if self.use_redis and self.client:
                return self.client.rpush(key, *values)
            else:
                if key not in self._memory_store:
                    self._memory_store[key] = []
                if not isinstance(self._memory_store[key], list):
                    self._memory_store[key] = []
                self._memory_store[key].extend(values)
                return len(self._memory_store[key])
        except Exception as e:
            logger.error(f"Redis RPUSH error: {str(e)}")
            return 0

    def lrange(self, key: str, start: int, stop: int) -> list:
        """Get range from list"""
        try:
            if self.use_redis and self.client:
                return self.client.lrange(key, start, stop)
            else:
                if key not in self._memory_store:
                    return []
                items = self._memory_store[key]
                if not isinstance(items, list):
                    return []
                return items[start:stop + 1]
        except Exception as e:
            logger.error(f"Redis LRANGE error: {str(e)}")
            return []

    def hset(self, key: str, mapping: Dict[str, Any]) -> int:
        """Set hash fields"""
        try:
            if self.use_redis and self.client:
                return self.client.hset(key, mapping=mapping)
            else:
                if key not in self._memory_store:
                    self._memory_store[key] = {}
                self._memory_store[key].update(mapping)
                return len(mapping)
        except Exception as e:
            logger.error(f"Redis HSET error: {str(e)}")
            return 0

    def hget(self, key: str, field: str) -> Optional[str]:
        """Get hash field"""
        try:
            if self.use_redis and self.client:
                return self.client.hget(key, field)
            else:
                if key not in self._memory_store:
                    return None
                return self._memory_store[key].get(field)
        except Exception as e:
            logger.error(f"Redis HGET error: {str(e)}")
            return None

    def hgetall(self, key: str) -> Dict[str, Any]:
        """Get all hash fields"""
        try:
            if self.use_redis and self.client:
                return self.client.hgetall(key)
            else:
                if key not in self._memory_store:
                    return {}
                return self._memory_store.get(key, {})
        except Exception as e:
            logger.error(f"Redis HGETALL error: {str(e)}")
            return {}

    def setjson(self, key: str, obj: Any, ex: Optional[int] = None) -> bool:
        """Set JSON object"""
        try:
            json_str = json.dumps(obj)
            return self.set(key, json_str, ex=ex)
        except Exception as e:
            logger.error(f"Redis SETJSON error: {str(e)}")
            return False

    def getjson(self, key: str) -> Optional[Any]:
        """Get JSON object"""
        try:
            value = self.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error(f"Redis GETJSON error: {str(e)}")
            return None

    def flush(self) -> bool:
        """Flush all cache"""
        try:
            if self.use_redis and self.client:
                self.client.flushdb()
            else:
                self._memory_store.clear()
            return True
        except Exception as e:
            logger.error(f"Redis FLUSH error: {str(e)}")
            return False

    def info(self) -> Dict[str, Any]:
        """Get cache info"""
        if self.use_redis and self.client:
            try:
                return self.client.info()
            except Exception as e:
                logger.error(f"Redis INFO error: {str(e)}")
                return {}
        else:
            return {
                "mode": "in-memory",
                "keys": len(self._memory_store),
                "memory_usage": "N/A (development)"
            }


    def getfloat(self, key: str) -> Optional[float]:
        """Get a float value from Redis"""
        value = self.get(key)
        if value is None:
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None

    def setfloat(self, key: str, value: float, ex: Optional[int] = None) -> bool:
        """Store a float value in Redis"""
        return self.set(key, str(value), ex=ex)


# Global instance
redis_client = RedisClient()
