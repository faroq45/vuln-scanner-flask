#!/usr/bin/env python3
"""
Simple setup for VulScanner (works with or without PostgreSQL)
"""
import os
import sys

print("🗄️  Setting up VulScanner")
print("=" * 60)

def test_redis():
    """Test Redis connection"""
    try:
        from core.redis import RedisManager
        redis_manager = RedisManager()
        if redis_manager.is_mock:
            print("✅ Redis fallback working (using mock Redis)")
        else:
            print("✅ Redis connection working (using external Redis or Memurai)")
        return True
    except Exception as e:
        print(f"❌ Redis setup failed: {e}")
        return False

def test_database():
    """Test PostgreSQL connection"""
    print("\n🗃️  Testing PostgreSQL connection...")
    
    # Check if environment variables are set
    db_user = os.environ.get('DB_USER', 'postgres')
    db_password = os.environ.get('DB_PASSWORD', '')
    db_host = os.environ.get('DB_HOST', 'localhost')
    db_port = os.environ.get('DB_PORT', '5432')
    db_name = os.environ.get('DB_NAME', 'vulnscanner')

    if not db_password:
        print("⚠️  DB_PASSWORD not set - PostgreSQL will be disabled")
        return False
    
    try:
        import psycopg2
        
        # Try to connect
        conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database='postgres',
            connect_timeout=5
        )
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (db_name,))
        exists = cursor.fetchone()
        
        if not exists:
            print(f"🏗️  Creating database '{db_name}'...")
            cursor.execute(f'CREATE DATABASE "{db_name}"')
            print(f"✅ Database '{db_name}' created")
        else:
            print(f"✅ Database '{db_name}' exists")
        
        cursor.close()
        conn.close()
        
        # Initialize schema
        try:
            from core.database import db_manager
            if db_manager.connected:
                print("✅ PostgreSQL connection successful - advanced features enabled")
                return True
            else:
                print("⚠️  PostgreSQL schema initialization failed - falling back to Redis-only mode")
                return False
        except Exception as e:
            print(f"⚠️  PostgreSQL schema error: {e}")
            return False
            
    except ImportError:
        print("⚠️  psycopg2 not installed - PostgreSQL disabled")
        return False
    except Exception as e:
        print(f"⚠️  PostgreSQL connection failed: {e}")
        print("    Scanner will work in Redis-only mode")
        return False

def test_scanner_components():
    """Test core scanner components"""
    print("\n🔧 Testing scanner components...")
    
    try:
        from core.port_scanner import Scanner
        print("✅ Core port scanner module loaded")
    except Exception as e:
        print(f"❌ Scanner module error: {e}")
        return False
    
    try:
        from core.url_scanner import URLScanner
        print("✅ URL scanner module loaded")
    except Exception as e:
        print(f"⚠️  URL scanner issue: {e}")
    
    try:
        import nmap
        print("✅ Nmap module available")
    except Exception as e:
        print(f"⚠️  Nmap not available: {e}")
    
    return True

def main():
    """Main setup function"""
    
    # Test Redis
    print("\n🔴 Testing Redis/Cache Layer...")
    redis_ok = test_redis()
    
    if not redis_ok:
        print("❌ Redis setup failed - scanner may not work properly")
        return False
    
    # Test Database (optional)
    db_ok = test_database()
    
    # Test scanner components
    scanner_ok = test_scanner_components()
    
    if not scanner_ok:
        print("❌ Core scanner components failed")
        return False
    
    # Summary
    print("\n" + "=" * 60)
    print("🎉 VulScanner Setup Complete!")
    print("\nFeatures Available:")
    print(f"• Redis/Caching: {'✅ Working' if redis_ok else '❌ Failed'}")
    print(f"• PostgreSQL Database: {'✅ Working' if db_ok else '⚠️  Disabled (Redis-only mode)'}")
    print(f"• Core Scanning: {'✅ Working' if scanner_ok else '❌ Failed'}")
    
    if not db_ok:
        print("\n📋 PostgreSQL Notes:")
        print("• Scanner will work in Redis-only mode")
        print("• Scan results will be temporary (lost on restart)")
        print("• To enable PostgreSQL:")
        print("  1. Set DB_PASSWORD environment variable")
        print("  2. Ensure PostgreSQL is running and accessible")
        print("  3. Run this setup again")
    
    print(f"\n🚀 Ready to start: python main.py")
    
    return redis_ok and scanner_ok

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⏹️  Setup cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)