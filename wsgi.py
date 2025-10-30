#!/usr/bin/env python3
"""
WSGI Entry Point for Vulnerability Scanner Flask Application
Use this file for production deployment with Gunicorn, uWSGI, or Waitress
"""

import sys
import os

# Add the application directory to the Python path
sys.path.insert(0, os.path.dirname(__file__))

# Import the Flask application
from main import app

# Initialize background workers
from core.redis import rds
from core.workers import start_workers

# Initialize Redis and start worker threads
rds.initialize()
start_workers()

# WSGI application object
application = app

if __name__ == "__main__":
    # For testing the WSGI app directly
    from werkzeug.serving import run_simple
    run_simple('0.0.0.0', 8080, application, use_reloader=False, use_debugger=False)
