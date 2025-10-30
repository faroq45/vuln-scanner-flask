#!/bin/bash
# Advanced Vulnerability Scanner - Start Script
# GitHub: https://github.com/faroq45/vuln-scanner-flask

echo "🛡️  Starting Advanced Vulnerability Scanner..."

# Start Redis in background
echo "Starting Redis..."
redis-server --bind 127.0.0.1 --daemonize yes

# Wait a moment for Redis to start
sleep 2

# Check if Redis is running
if redis-cli ping > /dev/null 2>&1; then
    echo "✅ Redis is running"
else
    echo "⚠️  Warning: Redis may not be running. Start it manually if needed."
fi

# Start the Flask application
echo "Starting Flask application..."
python3 main.py

echo "🚀 Application started on http://localhost:8080"
