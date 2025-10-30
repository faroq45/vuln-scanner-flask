#!/usr/bin/env python3
"""
Waitress WSGI Server for Windows Production Deployment
Waitress is a pure-Python WSGI server that works well on Windows
"""

import sys
import os
from waitress import serve

# Add the application directory to the Python path
sys.path.insert(0, os.path.dirname(__file__))

# Import configuration
import config

# Import the WSGI application
from wsgi import application

def main():
    """Start the Waitress WSGI server"""
    
    print("=" * 70)
    print("Starting Vulnerability Scanner - Production Mode (Waitress)")
    print("=" * 70)
    print(f"Host: {config.WEB_HOST}")
    print(f"Port: {config.WEB_PORT}")
    print(f"Threads: 10")
    print("=" * 70)
    print("\nPress CTRL+C to stop the server\n")
    
    # Start Waitress server
    # Waitress is production-ready and works great on Windows
    serve(
        application,
        host=config.WEB_HOST,
        port=config.WEB_PORT,
        threads=10,  # Number of worker threads
        channel_timeout=60,  # Channel timeout in seconds
        cleanup_interval=10,  # Cleanup interval in seconds
        url_scheme='http',  # Use 'https' if you have SSL configured
        ident='VulnScanner/1.0'  # Server identification
    )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nShutting down server...")
        sys.exit(0)
    except Exception as e:
        print(f"\nError starting server: {e}")
        sys.exit(1)
