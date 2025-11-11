# test_redis.py
import sys
try:
    import config, redis
except Exception as e:
    print("Import error:", e)
    sys.exit(1)

host = getattr(config, "RDS_HOST", "127.0.0.1")
port = getattr(config, "RDS_PORT", 6379)
passwd = getattr(config, "RDS_PASS", None) or None
print("Using Redis:", host, port, "password_set:", bool(passwd))

r = redis.Redis(host=host, port=int(port), password=passwd, socket_timeout=3)
try:
    print("PING ->", r.ping())
    print("redis_version:", r.info().get("redis_version"))
    print("Sample url_* keys:", r.keys("url_*")[:10])
except Exception as e:
    print("Redis connection failed:", repr(e))
