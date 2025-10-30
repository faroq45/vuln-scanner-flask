import os

# SQLite Database Configuration (Easier Alternative to PostgreSQL)

# Database settings
USE_DATABASE = True
DB_TYPE = 'sqlite'
DB_URL = f'sqlite:///{os.path.join(os.getcwd(), "vulnscanner.db")}'
DB_ECHO = False  # Set to True for SQL debug output

# This creates a local SQLite database file that doesn't require a server
# Much simpler than PostgreSQL but still provides persistent storage

print(f"SQLite Database will be created at: {DB_URL}")