# Database & User Activity Tracking Features

## Overview
The vulnerability scanner now includes comprehensive database integration for storing users and tracking all user actions on the website.

## Features Added

### 1. **Database Integration**
- **SQLite Database**: Lightweight, serverless database stored locally
- **Location**: `vulnscanner.db` in the project root directory
- **ORM**: SQLAlchemy for database operations

### 2. **Database Tables**

#### User Activity (`user_activity`)
Tracks all user actions in the system:
- `id`: Unique activity ID
- `username`: User who performed the action
- `action`: Type of action (LOGIN, LOGOUT, SCAN_INITIATED, etc.)
- `details`: JSON field with additional information
- `ip_address`: IP address of the user
- `user_agent`: Browser/client information
- `timestamp`: When the action occurred

#### Scan Sessions (`scan_sessions`)
Stores information about vulnerability scans:
- Session ID, status, start/end times
- Scan configuration and parameters
- Engineer name and description

#### Vulnerabilities (`vulnerabilities`)
Records discovered vulnerabilities:
- Vulnerability details (rule, severity, description)
- Target information (IP, port, service)
- Evidence and proof of concept
- OWASP/CVE classifications

#### Targets (`targets`)
Stores scan target information:
- Target type (IP, domain, URL, network)
- Discovery details
- Open ports and services

#### Scan Statistics (`scan_statistics`)
Aggregated statistics for scans:
- Vulnerability counts by severity
- Target statistics
- Scan duration

### 3. **User Activity Tracking**

The system automatically logs the following activities:

#### Authentication Events
- `LOGIN_SUCCESS`: Successful login
- `LOGIN_FAILED`: Failed login attempt
- `LOGIN_BLOCKED`: Login blocked due to multiple failures
- `LOGOUT`: User logout

#### Page Access
- Automatic tracking of page views for authenticated users
- Tracks GET and POST requests with parameters
- Example: `GET_DASHBOARD`, `POST_SCAN`, etc.

#### Scan Operations
- `SCAN_INITIATED`: When a user starts a scan
- `SCAN_INITIATION_FAILED`: When scan initiation fails
- Includes scan type and target information

### 4. **Activity Dashboard**

**Access**: Navigate to `/activity` after logging in

**Features**:
- View all your activity (regular users)
- View all users' activities (admin users only)
- Filter by username and action type
- Pagination support
- Real-time statistics:
  - Total activities
  - Unique users (admin only)
  - Recent logins (last 24 hours)
  - Top 10 actions

**Permissions**:
- Regular users: Can only see their own activities
- Admin users: Can see all activities across all users

## API Endpoints

### Get User Activities
```
GET /api/activity?limit=50&offset=0&username=admin&action=LOGIN
```

**Parameters**:
- `limit`: Number of records to return (default: 100)
- `offset`: Pagination offset (default: 0)
- `username`: Filter by username (admin only)
- `action`: Filter by action type

**Response**:
```json
{
  "activities": [
    {
      "id": 1,
      "username": "admin",
      "action": "LOGIN_SUCCESS",
      "details": {"method": "user_database"},
      "ip_address": "127.0.0.1",
      "user_agent": "Mozilla/5.0...",
      "timestamp": "2025-10-28T12:00:00"
    }
  ],
  "total": 150,
  "limit": 50,
  "offset": 0
}
```

### Get Activity Statistics
```
GET /api/activity/stats
```

**Response**:
```json
{
  "total_activities": 250,
  "unique_users": 5,
  "recent_logins_24h": 12,
  "top_actions": [
    {"action": "LOGIN_SUCCESS", "count": 45},
    {"action": "GET_DASHBOARD", "count": 38}
  ]
}
```

## User Management

### Default Users
The system comes with a default admin user:
- **Username**: `admin`
- **Password**: `admin`
- **Role**: `admin`

### User Storage
Users are stored in JSON format in `data/users.json` with:
- Username and hashed password
- Email address
- Role (admin/user)
- Account status (active/inactive)
- Creation date and last login

### Creating New Users
Navigate to `/signup` to create new user accounts.

### Admin Features
Admin users can:
- View all user activities
- Access user management endpoints
- Deactivate/activate user accounts
- View system-wide statistics

## Database Setup

### Initial Setup
```bash
python setup_database.py
```

This will:
1. Create the SQLite database
2. Create all required tables
3. Verify user accounts
4. Display current statistics

### Checking Database Status
```bash
python setup_database.py
```

Shows:
- Database connection status
- List of tables
- User accounts
- Activity count

## Configuration

### Database Settings (config.py)
```python
USE_DATABASE = True
DB_ECHO = False  # Set to True for SQL query logging
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_URL = f"sqlite:///{os.path.join(BASE_DIR, 'vulnscanner.db')}"
```

### Switching to PostgreSQL (Optional)
To use PostgreSQL instead of SQLite:

1. Update `config.py`:
```python
DB_URL = "postgresql://user:password@localhost:5432/vulnscanner"
```

2. Install PostgreSQL driver:
```bash
pip install psycopg2-binary
```

3. Run setup:
```bash
python init_database.py
```

## Security Considerations

### Data Protection
- Passwords are hashed using Werkzeug's security functions
- User activity logs include IP addresses for security auditing
- Failed login attempts are tracked
- IP blocking after multiple failed attempts

### Access Control
- Activity logs are session-protected
- Regular users can only access their own logs
- Admin features require admin role verification
- All API endpoints require authentication

### Privacy
- User agent strings are logged for security purposes
- IP addresses are stored for audit trails
- Activity details are stored in JSON format
- Sensitive data should not be logged in activity details

## Monitoring & Auditing

### What Gets Logged
- All login/logout events
- Page access (except static files)
- Scan initiations and results
- Failed operations
- Admin actions

### What Doesn't Get Logged
- Static file requests (CSS, JS, images)
- Health check endpoints
- Unauthenticated page access

### Log Retention
- SQLite database grows with activity
- Consider implementing log rotation for production
- Archive old activity logs periodically
- Current implementation: No automatic cleanup

## Troubleshooting

### Database Not Connected
Check:
1. `USE_DATABASE = True` in config.py
2. Database file path is accessible
3. SQLAlchemy is installed: `pip install sqlalchemy`

### No Activities Showing
Check:
1. You are logged in
2. Database setup was completed
3. Activity middleware is enabled
4. Browser console for JavaScript errors

### Permission Denied
- Ensure user account has correct role
- Admin features require `role='admin'`
- Check session is valid

## Performance

### Database Size
- Each activity record: ~500 bytes
- 10,000 activities ≈ 5 MB
- SQLite handles millions of records efficiently

### Optimization Tips
- Set `DB_ECHO = False` in production
- Index important columns (already done)
- Use pagination for large result sets
- Consider archiving old data

## Development

### Adding New Activity Types
1. Log activity using `db_manager.log_user_activity()`:
```python
from core.database import db_manager

db_manager.log_user_activity(
    username=session.get('session'),
    action='CUSTOM_ACTION',
    details={'key': 'value'},
    ip_address=request.remote_addr,
    user_agent=request.headers.get('User-Agent')
)
```

2. Update activity badge colors in `activity.html` if needed

### Custom Queries
```python
from core.database import db_manager, UserActivity

with db_manager.get_session() as session:
    # Your custom SQLAlchemy queries
    activities = session.query(UserActivity).filter_by(
        username='admin'
    ).all()
```

## Backup & Recovery

### Backing Up
```bash
# Simple file copy
copy vulnscanner.db vulnscanner.db.backup

# Or use SQLite backup
sqlite3 vulnscanner.db ".backup vulnscanner_backup.db"
```

### Restoring
```bash
copy vulnscanner_backup.db vulnscanner.db
```

## Future Enhancements

Potential improvements:
- [ ] Export activity logs to CSV/JSON
- [ ] Activity log retention policies
- [ ] Real-time activity monitoring dashboard
- [ ] Email notifications for specific activities
- [ ] Integration with SIEM systems
- [ ] Advanced filtering and search
- [ ] Activity reports and analytics

## Support

For issues or questions:
1. Check database setup: `python setup_database.py`
2. Verify configuration in `config.py`
3. Check application logs in `vulscanner.log`
4. Review the database tables and schemas
