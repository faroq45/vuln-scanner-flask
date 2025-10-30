# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Repository Overview

This is a Flask-based web application for vulnerability scanning, network exploitation, and reconnaissance. The application provides both web-based and REST API interfaces for conducting security assessments.

**Key Features:**
- Vulnerability scanning using custom rules and OWASP Top 10 checks
- Network port scanning with nmap integration
- Scheduled assessments and notifications
- Real-time scan progress tracking via Redis
- Multi-threaded scanning and attack modules

## Development Commands

### Setup and Installation
```bash
# Create virtual environment
python3 -m venv env

# Activate virtual environment (Linux/macOS)
source env/bin/activate
# On Windows PowerShell:
env\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Install and start Redis (required)
# Linux: sudo apt-get install redis-server
# macOS: brew install redis
# Windows: Install Redis from official source

# Start the application
bash start.sh
# Or manually:
# nohup redis-server --bind 127.0.0.1 &> /dev/null
# python3 main.py
```

### Testing
```bash
# Test OWASP scanner integration
python test_owasp_scanner.py

# Run the application in debug mode (modify config.py)
# Set WEB_DEBUG = True in config.py
python main.py
```

### Development Server
```bash
# Access the web application
# Default: http://0.0.0.0:8080
# Default credentials: admin/admin
```

## Architecture Overview

### Core Application Structure

**Main Application (`main.py`)**
- Flask app with blueprints for different views
- REST API endpoints using Flask-RESTful
- Redis-backed session management and progress tracking
- Multi-threaded worker system for scanning operations

**Configuration (`config.py`)**
- Web server settings (host, port, debug mode)
- Redis configuration for session storage
- Security headers and authentication settings
- Default scan configuration template

### Key Components

**Views Architecture (`views/`)**
- Blueprint-based routing with session authentication
- Separated views for different functionalities:
  - Dashboard and reports (`view_dashboard.py`, `view_reports.py`)
  - Assessment configuration (`view_assessment.py`)
  - Quick scan interface (`view_qs.py`)
  - Real-time console output (`view_console.py`)
  - OWASP scanner integration (`view_owasp_scan.py`)

**Core Modules (`core/`)**
- **Redis Manager (`redis.py`)**: Centralized data store with fallback to mock implementation
- **Security (`security.py`)**: Session-based authentication and IP blocking
- **Workers (`workers.py`)**: Background thread management for scanners
- **Port Scanner (`port_scanner.py`)**: Network discovery using nmap
- **Parser (`parser.py`)**: Scan configuration validation
- **Reports (`reports.py`)**: Result generation and export functionality

**Scanning Engine (`bin/`)**
- **Scanner (`scanner.py`)**: Port discovery and asset inventory
- **Attacker (`attacker.py`)**: Vulnerability assessment using rule-based checks
- **Scheduler (`scheduler.py`)**: Manages periodic and scheduled scans

**OWASP Scanner Module (`scanner/`)**
- Modern async-based OWASP Top 10 vulscanner
- HTTP client with rate limiting and crawling capabilities
- Modular security checks system
- Integration with main Flask application

### Data Flow

1. **Scan Initialization**: User configures scan via web UI → validation → Redis storage
2. **Background Processing**: 
   - Scanner process discovers hosts/ports → stores in Redis
   - Attacker process retrieves scan data → runs vulnerability checks
   - Results stored back to Redis with unique identifiers
3. **Real-time Updates**: Web UI polls Redis for progress and results
4. **Reporting**: Completed scans generate reports and trigger notifications

### Key Design Patterns

**Redis-Centric Architecture**
- All scan state, progress, and results stored in Redis
- Fallback to mock Redis implementation when server unavailable
- Key prefixes organize different data types (`vuln_`, `sca_`, `sch_`, `inv_`)

**Multi-Process Worker Model**
- Separate processes for scanning and attacking
- Thread-based rule execution within attacker process
- Configurable parallelism limits to prevent resource exhaustion

**Blueprint-Based Web Architecture**
- Modular view organization with consistent authentication
- Session-based security with IP blocking for brute force protection
- REST API alongside traditional web views

## Development Notes

### Adding New Vulnerability Checks
- Implement in `core/manager.py` rule system
- Follow existing pattern for rule intensity levels and exclusions
- Store findings using `rds.store_vuln()` with consistent schema

### Extending OWASP Scanner
- Add new checks in `scanner/scanner/checks/` directory
- Implement base check interface from `checks/base.py`
- Register in `get_available_checks()` function

### Database Schema (Redis Keys)
- `sess_*`: Session state and configuration
- `vuln_*`: Vulnerability findings (SHA1 hashed keys)
- `sca_*`: Scan data for processing
- `inv_*`: Asset inventory
- `sch_*`: Scheduled scan queue
- `p_*`: Persistent settings and statistics

### Security Considerations
- Default credentials should be changed in production
- Web security headers configured in `config.py`
- Session-based authentication with configurable login attempt limits
- Network scanning limited by IP deny-list to prevent abuse

### Integration Points
- Slack webhook integration for notifications (`core/utils.py`)
- Email notifications via SMTP
- Generic webhook support for external integrations
- PDF report generation using ReportLab

## Environment Configuration

- **WEB_HOST/WEB_PORT**: Server binding configuration
- **RDS_HOST/RDS_PORT**: Redis connection settings
- **WEB_USER/WEB_PASSW**: Authentication credentials via environment variables
- **WEB_SECURITY**: Enable/disable security headers

Access web application at configured host:port (default: http://0.0.0.0:8080)