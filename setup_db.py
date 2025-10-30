#!/usr/bin/env python3
"""
Simple PostgreSQL database setup for VulScanner
"""
import os
import sys

print("🗄️  Setting up PostgreSQL for VulScanner")
print("=" * 60)

# Check if environment variables are set
db_user = os.environ.get('DB_USER', 'postgres')
db_password = os.environ.get('DB_PASSWORD', '')
db_host = os.environ.get('DB_HOST', 'localhost')
db_port = os.environ.get('DB_PORT', '5432')
db_name = os.environ.get('DB_NAME', 'vulnscanner')

if not db_password:
    print("❌ DB_PASSWORD environment variable not set!")
    print("\nPlease set the PostgreSQL password first:")
    print("PowerShell: $env:DB_PASSWORD = 'your_password'")
    print("CMD: set DB_PASSWORD=your_password")
    print("Then run this script again.")
    sys.exit(1)

print(f"📋 Database Configuration:")
print(f"   Host: {db_host}")
print(f"   Port: {db_port}")
print(f"   User: {db_user}")
print(f"   Database: {db_name}")

try:
    # Test if we can import the required modules
    import psycopg2
    print("\n✅ psycopg2 module available")
    
    # Try to connect and create database
    print(f"\n🔌 Testing connection to PostgreSQL...")
    
    try:
        # Connect to default postgres database first
        conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database='postgres'
        )
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Check if our database exists
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (db_name,))
        exists = cursor.fetchone()
        
        if not exists:
            print(f"🏗️  Creating database '{db_name}'...")
            cursor.execute(f'CREATE DATABASE "{db_name}"')
            print(f"✅ Database '{db_name}' created successfully")
        else:
            print(f"📍 Database '{db_name}' already exists")
        
        cursor.close()
        conn.close()
        
        # Now test connection to our database
        print(f"🧪 Testing connection to '{db_name}'...")
        test_conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            database=db_name,
            user=db_user,
            password=db_password
        )
        test_conn.close()
        print("✅ Database connection test successful")
        
    except psycopg2.Error as e:
        print(f"❌ PostgreSQL connection failed: {e}")
        print("\nPlease check:")
        print("1. PostgreSQL is running")
        print("2. Username and password are correct")
        print("3. Host and port are accessible")
        sys.exit(1)
    
    # Initialize database schema
    print("\n📊 Initializing database schema...")
    try:
        from core.database import db_manager
        
        if db_manager.connected:
            print("✅ Database connection established")
            print("✅ Database tables created/verified")
            
            # Test basic operations
            with db_manager.get_session() as session:
                from core.database import ScanSession, Vulnerability, Target
                
                session_count = session.query(ScanSession).count()
                vuln_count = session.query(Vulnerability).count()
                target_count = session.query(Target).count()
                
                print(f"📈 Database Status:")
                print(f"   Scan Sessions: {session_count}")
                print(f"   Vulnerabilities: {vuln_count}")
                print(f"   Targets: {target_count}")
                
            print("\n🎉 Database setup completed successfully!")
            print("\nThe vulscanner will now use PostgreSQL for data storage.")
            
        else:
            print("❌ Failed to initialize database schema")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
        
except ImportError:
    print("❌ psycopg2 not installed. Please install it first:")
    print("pip install psycopg2-binary")
    sys.exit(1)
except Exception as e:
    print(f"❌ Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 60)
print("✅ PostgreSQL Database Integration Complete!")
print("\nYour vulscanner now has:")
print("• Persistent data storage in PostgreSQL")
print("• Enhanced vulnerability tracking")
print("• Scan session management")
print("• Advanced reporting capabilities")
print("\nStart your application with 'python main.py' to use the database!")