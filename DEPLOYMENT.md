# Production Deployment Guide

This guide covers deploying the Vulnerability Scanner Flask application to production using WSGI servers.

## Table of Contents
- [Windows Deployment (Waitress)](#windows-deployment-waitress)
- [Linux/Unix Deployment (Gunicorn)](#linuxunix-deployment-gunicorn)
- [Docker Deployment](#docker-deployment)
- [Nginx Reverse Proxy](#nginx-reverse-proxy)
- [Security Recommendations](#security-recommendations)

---

## Windows Deployment (Waitress)

**Waitress** is the recommended WSGI server for Windows. It's pure Python and production-ready.

### Installation

```bash
pip install waitress
```

### Running with Waitress

**Option 1: Using the run script**
```bash
python run_waitress.py
```

**Option 2: Direct command**
```bash
waitress-serve --host=0.0.0.0 --port=8080 --threads=10 wsgi:application
```

**Option 3: With more options**
```bash
waitress-serve --host=0.0.0.0 --port=8080 --threads=10 --channel-timeout=60 --cleanup-interval=10 --ident=VulnScanner wsgi:application
```

### Running as Windows Service

1. Install `pywin32`:
   ```bash
   pip install pywin32
   ```

2. Create a Windows Service script or use NSSM (Non-Sucking Service Manager):
   ```bash
   # Download NSSM from https://nssm.cc/download
   nssm install VulnScanner "C:\path\to\python.exe" "C:\path\to\run_waitress.py"
   nssm start VulnScanner
   ```

---

## Linux/Unix Deployment (Gunicorn)

**Gunicorn** is the recommended WSGI server for Linux/Unix systems.

### Installation

```bash
pip install gunicorn
```

### Running with Gunicorn

**Option 1: Using configuration file**
```bash
gunicorn -c gunicorn_config.py wsgi:application
```

**Option 2: Command line options**
```bash
gunicorn --bind 0.0.0.0:8080 --workers 4 --timeout 60 --log-level info wsgi:application
```

**Option 3: With gevent workers (async)**
```bash
pip install gevent
gunicorn --bind 0.0.0.0:8080 --workers 4 --worker-class gevent --worker-connections 1000 wsgi:application
```

### Running as Systemd Service

1. Create service file: `/etc/systemd/system/vuln-scanner.service`

```ini
[Unit]
Description=Vulnerability Scanner Flask Application
After=network.target redis.target

[Service]
Type=notify
User=vulnscan
Group=vulnscan
WorkingDirectory=/opt/vuln-scanner-flask
Environment="PATH=/opt/vuln-scanner-flask/venv/bin"
ExecStart=/opt/vuln-scanner-flask/venv/bin/gunicorn -c gunicorn_config.py wsgi:application
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=always

[Install]
WantedBy=multi-user.target
```

2. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable vuln-scanner
sudo systemctl start vuln-scanner
sudo systemctl status vuln-scanner
```

---

## Docker Deployment

### Dockerfile

```dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    redis-server \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir gunicorn gevent

# Copy application
COPY . .

# Create logs directory
RUN mkdir -p logs

# Expose port
EXPOSE 8080

# Start Redis and application
CMD redis-server --daemonize yes && \
    gunicorn -c gunicorn_config.py wsgi:application
```

### Docker Compose

```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    restart: always
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

  vuln-scanner:
    build: .
    restart: always
    ports:
      - "8080:8080"
    depends_on:
      - redis
    environment:
      - RDS_HOST=redis
      - RDS_PORT=6379
      - WEB_HOST=0.0.0.0
      - WEB_PORT=8080
    volumes:
      - ./logs:/app/logs
      - ./data:/app/data

volumes:
  redis-data:
```

### Build and Run

```bash
# Build image
docker build -t vuln-scanner:latest .

# Run with docker-compose
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## Nginx Reverse Proxy

### Configuration

Create `/etc/nginx/sites-available/vuln-scanner`:

```nginx
upstream vuln_scanner {
    server 127.0.0.1:8080;
    keepalive 64;
}

server {
    listen 80;
    server_name vuln-scanner.example.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name vuln-scanner.example.com;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/vuln-scanner.crt;
    ssl_certificate_key /etc/ssl/private/vuln-scanner.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Logging
    access_log /var/log/nginx/vuln-scanner-access.log;
    error_log /var/log/nginx/vuln-scanner-error.log;

    # Max upload size
    client_max_body_size 50M;

    # Proxy settings
    location / {
        proxy_pass http://vuln_scanner;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        proxy_buffering off;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Static files (if needed)
    location /static {
        alias /opt/vuln-scanner-flask/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/vuln-scanner /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## Security Recommendations

### 1. Environment Variables

Store sensitive data in environment variables:

```bash
export SECRET_KEY="your-secret-key-here"
export RDS_PASSW="redis-password"
export DB_PASSWORD="database-password"
```

### 2. Firewall Configuration

```bash
# Ubuntu/Debian
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# CentOS/RHEL
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

### 3. SSL/TLS Certificate

**Using Let's Encrypt (Certbot):**
```bash
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d vuln-scanner.example.com
```

### 4. Redis Security

Edit `/etc/redis/redis.conf`:
```conf
bind 127.0.0.1
requirepass your-strong-password
maxmemory 256mb
maxmemory-policy allkeys-lru
```

### 5. Application Security

Update `config.py`:
```python
# Production settings
WEB_DEBUG = False
WEB_SECURITY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
```

### 6. User Permissions

```bash
# Create dedicated user
sudo useradd -r -s /bin/false vulnscan

# Set permissions
sudo chown -R vulnscan:vulnscan /opt/vuln-scanner-flask
sudo chmod 750 /opt/vuln-scanner-flask
```

### 7. Log Rotation

Create `/etc/logrotate.d/vuln-scanner`:
```
/opt/vuln-scanner-flask/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 vulnscan vulnscan
    sharedscripts
    postrotate
        systemctl reload vuln-scanner
    endscript
}
```

---

## Performance Tuning

### Gunicorn Workers

Formula: `(2 x $num_cores) + 1`

```bash
# Check CPU cores
nproc

# Set workers accordingly
gunicorn --workers 5 --worker-class gevent --worker-connections 1000 wsgi:application
```

### Redis Optimization

```conf
# /etc/redis/redis.conf
maxmemory 1gb
maxmemory-policy allkeys-lru
tcp-backlog 511
timeout 300
```

### Database Connection Pooling

Update `core/database.py` to use connection pooling for better performance.

---

## Monitoring

### Health Check Endpoint

The application provides `/health` endpoint for monitoring:

```bash
curl http://localhost:8080/health
```

### Prometheus Integration

Add metrics to your application for Prometheus monitoring.

### Log Monitoring

Use tools like:
- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Graylog**
- **Splunk**

---

## Troubleshooting

### Check Application Status

```bash
# Systemd
sudo systemctl status vuln-scanner

# Logs
sudo journalctl -u vuln-scanner -f
```

### Check Port Binding

```bash
sudo netstat -tulpn | grep 8080
# or
sudo ss -tulpn | grep 8080
```

### Test WSGI Application

```bash
python wsgi.py
```

### Redis Connection Test

```bash
redis-cli ping
redis-cli INFO
```

---

## Backup and Recovery

### Database Backup

```bash
# SQLite
cp vuln_scanner.db vuln_scanner.db.backup

# PostgreSQL
pg_dump vuln_scanner > backup.sql
```

### Redis Backup

```bash
redis-cli SAVE
cp /var/lib/redis/dump.rdb /backup/redis-backup.rdb
```

---

## Support

For issues and questions:
- Check application logs in `logs/` directory
- Review Redis logs: `/var/log/redis/redis-server.log`
- Check system logs: `sudo journalctl -xe`

---

**Last Updated:** 2025-10-29
