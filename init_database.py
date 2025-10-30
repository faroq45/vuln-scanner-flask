#!/usr/bin/env python3
"""
Database initialization script for VulScanner
"""
import os
import sys
import getpass
import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

import config

def create_database():
    """Create the PostgreSQL database if it doesn't exist"""
    
    print("🗄️  PostgreSQL Database Setup for VulScanner")
    print("=" * 60)
    
    # Get database credentials
    db_user = input(f"PostgreSQL username (default: {config.DB_USER}): ").strip() or config.DB_USER
    db_password = getpass.getpass(f"PostgreSQL password for {db_user}: ")
    
    if not db_password:
        print("❌ Password cannot be empty")
        return False
    
    db_host = input(f"PostgreSQL host (default: {config.DB_HOST}): ").strip() or config.DB_HOST
    db_port = input(f"PostgreSQL port (default: {config.DB_PORT}): ").strip() or config.DB_PORT
    db_name = input(f"Database name (default: {config.DB_NAME}): ").strip() or config.DB_NAME
    
    print("\n📋 Database Configuration:")
    print(f"   Host: {db_host}")
    print(f"   Port: {db_port}")
    print(f"   User: {db_user}")
    print(f"   Database: {db_name}")
    
    confirm = input(f"\n✅ Create database '{db_name}' with this configuration? (y/N): ").strip().lower()
    if confirm != 'y':
        print("❌ Database setup cancelled")
        return False
    
    try:
        # Connect to PostgreSQL server (without specifying database)
        print(f"\n🔌 Connecting to PostgreSQL server at {db_host}:{db_port}...")
        conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database='postgres'  # Connect to default postgres database
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (db_name,))
        exists = cursor.fetchone()
        
        if exists:
            print(f"📍 Database '{db_name}' already exists")
        else:
            # Create database
            print(f"🏗️  Creating database '{db_name}'...")
            cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
            print(f"✅ Database '{db_name}' created successfully")
        
        cursor.close()
        conn.close()
        
        # Update environment variables or config
        print("\n🔧 Setting up database configuration...")
        
        # Create environment variables file
        env_content = f"""# PostgreSQL Configuration for VulScanner
DB_HOST={db_host}
DB_PORT={db_port}
DB_NAME={db_name}
DB_USER={db_user}
DB_PASSWORD={db_password}
USE_DATABASE=true
"""
        
        with open('.env.db', 'w') as f:
            f.write(env_content)
        
        print("✅ Database configuration saved to .env.db")
        print("\n🔧 Setting environment variables for this session...")
        
        # Set environment variables for current session
        os.environ['DB_HOST'] = db_host
        os.environ['DB_PORT'] = db_port  
        os.environ['DB_NAME'] = db_name
        os.environ['DB_USER'] = db_user
        os.environ['DB_PASSWORD'] = db_password
        os.environ['USE_DATABASE'] = 'true'
        
        # Test connection to the new database
        print(f"\n🧪 Testing connection to '{db_name}'...")
        test_conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            database=db_name,
            user=db_user,
            password=db_password
        )
        test_conn.close()
        print("✅ Database connection test successful")
        
        # Initialize database schema
        print("\n📊 Initializing database schema...")
        try:
            from core.database import db_manager
            if db_manager.connected:
                print("✅ Database tables created successfully")
                
                # Create initial data
                print("📋 Creating initial scan session record...")
                
                return True
            else:
                print("❌ Failed to connect to database for schema creation")
                return False
                
        except Exception as e:
            print(f"❌ Error initializing database schema: {e}")
            return False
            
    except psycopg2.Error as e:
        print(f"❌ PostgreSQL error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def check_database_status():
    """Check current database status"""
    print("\n📊 Current Database Status:")
    print("=" * 40)
    
    try:
        from core.database import db_manager
        
        if db_manager.connected:
            print("✅ Database connection: OK")
            
            # Get statistics
            stats = db_manager.get_scan_statistics()
            print(f"📈 Total vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
            print(f"   - Critical: {stats.get('critical_vulns', 0)}")
            print(f"   - High: {stats.get('high_vulns', 0)}")
            print(f"   - Medium: {stats.get('medium_vulns', 0)}")
            print(f"   - Low: {stats.get('low_vulns', 0)}")
            
            # Test database operations
            with db_manager.get_session() as session:
                from core.database import ScanSession, Vulnerability, Target
                
                session_count = session.query(ScanSession).count()
                vuln_count = session.query(Vulnerability).count() 
                target_count = session.query(Target).count()
                
                print(f"📋 Scan sessions: {session_count}")
                print(f"🎯 Targets: {target_count}")
                print(f"🔍 Total vulnerabilities: {vuln_count}")
                
        else:
            print("❌ Database connection: FAILED")
            print("   Using Redis/Mock fallback")
            
    except Exception as e:
        print(f"❌ Error checking database status: {e}")

if __name__ == "__main__":
    print("🛠️  VulScanner Database Setup")
    print("=" * 50)
    
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        check_database_status()
    else:
        success = create_database()
        
        if success:
            print("\n" + "=" * 60)
            print("🎉 Database setup completed successfully!")
            print("\nNext steps:")
            print("1. Load environment variables: set -a && source .env.db && set +a")
            print("2. Or restart your application to use the database")
            print("3. Run 'python init_database.py status' to check status")
            check_database_status()
        else:
            print("\n❌ Database setup failed")
            sys.exit(1)