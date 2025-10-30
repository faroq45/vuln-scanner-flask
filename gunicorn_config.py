"""
Gunicorn Configuration for Production Deployment (Linux/Unix)
"""

import multiprocessing
import os

# Server socket
bind = "0.0.0.0:8080"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'sync'  # Use 'gevent' or 'eventlet' for async
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 60
keepalive = 5

# Process naming
proc_name = 'vuln-scanner-flask'

# Logging
accesslog = 'logs/gunicorn-access.log'
errorlog = 'logs/gunicorn-error.log'
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process management
daemon = False  # Set to True to run as daemon
pidfile = 'gunicorn.pid'
user = None  # Set to run as specific user
group = None  # Set to run as specific group
umask = 0
tmp_upload_dir = None

# Server mechanics
preload_app = True  # Load app before forking workers
reload = False  # Auto-reload on code changes (disable in production)
check_config = False

# SSL (uncomment and configure for HTTPS)
# keyfile = '/path/to/keyfile'
# certfile = '/path/to/certfile'
# ca_certs = '/path/to/ca_certs'
# cert_reqs = 0
# do_handshake_on_connect = False
# ciphers = 'TLSv1'

# Server hooks
def on_starting(server):
    """Called just before the master process is initialized."""
    print("Starting Gunicorn server...")

def on_reload(server):
    """Called to recycle workers during a reload via SIGHUP."""
    pass

def when_ready(server):
    """Called just after the server is started."""
    print(f"Server is ready. Spawning {workers} workers.")

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    pass

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    pass

def post_worker_init(worker):
    """Called just after a worker has initialized the application."""
    pass

def worker_int(worker):
    """Called when a worker receives the INT or QUIT signal."""
    pass

def worker_abort(worker):
    """Called when a worker receives the SIGABRT signal."""
    pass

def pre_exec(server):
    """Called just before a new master process is forked."""
    pass

def pre_request(worker, req):
    """Called just before a worker processes the request."""
    pass

def post_request(worker, req, environ, resp):
    """Called after a worker processes the request."""
    pass

def child_exit(server, worker):
    """Called just after a worker has been exited."""
    pass

def worker_exit(server, worker):
    """Called just after a worker has been exited."""
    pass

def nworkers_changed(server, new_value, old_value):
    """Called just after num_workers has been changed."""
    pass

def on_exit(server):
    """Called just before exiting Gunicorn."""
    print("Shutting down Gunicorn server...")
