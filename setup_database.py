#!/usr/bin/env python3
"""
Initialize the SQLite database for user activity tracking
"""
import os
import sys

# Make sure we're in the right directory
if __name__ == "__main__":
    print("🗄️  Initializing VulnScanner Database")
    print("=" * 50)
    
    try:
        # Import database manager
        from core.database import db_manager, Base
        from core.user_manager import UserManager
        
        if db_manager.connected:
            print("✅ Database connection: OK")
            print(f"📍 Database location: {os.path.abspath('vulnscanner.db')}")
            
            # Tables are already created by database.py initialization
            print("✅ Database tables created/verified")
            
            # List tables
            from sqlalchemy import inspect
            inspector = inspect(db_manager.engine)
            tables = inspector.get_table_names()
            
            print(f"\n📋 Database tables ({len(tables)}):")
            for table in tables:
                print(f"   - {table}")
            
            # Check if default users exist
            print("\n👥 Checking user accounts...")
            user_manager = UserManager()
            users = user_manager.list_users()
            print(f"   Found {len(users)} user(s):")
            for user in users:
                print(f"   - {user['username']} ({user['role']})")
            
            # Get activity count
            with db_manager.get_session() as session:
                from core.database import UserActivity
                activity_count = session.query(UserActivity).count()
                print(f"\n📊 User activities logged: {activity_count}")
            
            print("\n" + "=" * 50)
            print("🎉 Database setup completed successfully!")
            print("\nYou can now run the application with: python main.py")
            
        else:
            print("❌ Database connection failed!")
            print("   Check your database configuration in config.py")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Error during database setup: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
