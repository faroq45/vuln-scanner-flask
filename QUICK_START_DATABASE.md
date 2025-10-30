# Quick Start: Database & Activity Tracking

## What Was Added

✅ **SQLite Database** for storing users and tracking activities
✅ **User Activity Logging** - Every action is automatically tracked
✅ **Activity Dashboard** - View all user activities at `/activity`
✅ **API Endpoints** for querying activities and statistics
✅ **Admin Features** - Admins can see all users' activities

## Getting Started

### 1. Database is Already Set Up!
The database was automatically initialized when you ran `setup_database.py`

### 2. Start the Application
```bash
# Make sure Redis is running
Start-Process -FilePath "C:\Program Files\Redis\redis-server.exe" -WindowStyle Hidden

# Start the app
python main.py
```

### 3. Login
- **URL**: http://127.0.0.1:8080/login
- **Username**: `admin`
- **Password**: `admin`

### 4. View Activity Logs
- Navigate to: http://127.0.0.1:8080/activity
- You'll see all your actions being tracked in real-time!

## What Gets Tracked?

### Automatically Logged:
- ✅ Login/Logout events
- ✅ Page views (dashboard, reports, scans, etc.)
- ✅ Scan initiations
- ✅ Failed operations
- ✅ Every action you take on the website

### Information Stored:
- Username
- Action type
- IP address
- Browser/device info
- Timestamp
- Additional details (scan config, errors, etc.)

## Features at a Glance

### For Regular Users:
- View your own activity history
- Filter by action type
- See when you last logged in
- Track your scan history

### For Admin Users:
- View ALL users' activities
- Filter by username
- System-wide statistics
- User management

## Database Location
```
C:\Users\ASUS\.vscode\vuln-scanner-flask\vulnscanner.db
```

## Useful Commands

### Check Database Status
```bash
python setup_database.py
```

### View Activity via API
```bash
# Get your activities (while logged in)
curl http://127.0.0.1:8080/api/activity

# Get statistics
curl http://127.0.0.1:8080/api/activity/stats
```

## Example: What You'll See

After logging in and navigating around, your activity log will show:
```
2025-10-28 12:00:00 | LOGIN_SUCCESS     | 127.0.0.1
2025-10-28 12:00:05 | GET_DASHBOARD     | 127.0.0.1
2025-10-28 12:00:10 | GET_SCAN          | 127.0.0.1
2025-10-28 12:01:00 | SCAN_INITIATED    | 127.0.0.1
2025-10-28 12:05:00 | GET_REPORTS       | 127.0.0.1
2025-10-28 12:10:00 | GET_ACTIVITY      | 127.0.0.1
2025-10-28 12:15:00 | LOGOUT            | 127.0.0.1
```

## Security Features

✅ Passwords are hashed (never stored in plain text)
✅ Failed login attempts are tracked
✅ IP blocking after 5 failed attempts
✅ Session-based authentication
✅ Activity logs for audit trails

## Next Steps

1. **Create more users**: Go to http://127.0.0.1:8080/signup
2. **Run some scans**: Track how scan activities are logged
3. **Check the activity dashboard**: See everything being tracked
4. **Read full docs**: Check `DATABASE_FEATURES.md` for details

## Troubleshooting

### No activities showing?
- Make sure you're logged in
- Check that database was set up: `python setup_database.py`
- Look for errors in the console

### Database errors?
```bash
# Recreate the database
rm vulnscanner.db
python setup_database.py
```

### Can't access /activity page?
- You must be logged in
- Check your session is valid
- Try logging out and back in

## That's It!

Your vulnerability scanner now has full database integration with comprehensive activity tracking. Every action is logged automatically for security and auditing purposes.

**Happy Scanning! 🔒**
