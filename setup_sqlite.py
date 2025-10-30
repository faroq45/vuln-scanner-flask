#!/usr/bin/env python3
"""
SQLite Database Setup for VulScanner
Easier alternative to PostgreSQL - no server required!
"""
import os
import sys

def setup_sqlite_database():
    """Setup SQLite database for the vulscanner"""
    print("🗄️  Setting up SQLite Database for VulScanner")
    print("=" * 60)
    
    # Import config to set SQLite settings temporarily
    print("📋 Configuring SQLite database...")
    
    # Update config.py to use SQLite
    config_path = "config.py"
    
    try:
        # Read current config
        with open(config_path, 'r') as f:
            config_content = f.read()
        
        # Check if database settings exist and update them
        new_config_lines = []
        in_db_section = False
        db_settings_found = False
        
        for line in config_content.split('\n'):
            if 'USE_DATABASE' in line:
                new_config_lines.append("USE_DATABASE = True")
                db_settings_found = True
            elif 'DB_URL' in line or 'DB_HOST' in line or 'DB_USER' in line:
                if 'DB_URL' in line:
                    # Replace with SQLite URL
                    db_path = os.path.join(os.getcwd(), "vulnscanner.db").replace("\\", "/")
                    new_config_lines.append(f'DB_URL = "sqlite:///{db_path}"')
                # Skip other DB settings for SQLite
            elif 'DB_ECHO' in line:
                new_config_lines.append("DB_ECHO = False")
            else:
                new_config_lines.append(line)
        
        # Add SQLite settings if not found
        if not db_settings_found:
            new_config_lines.extend([
                "",
                "# SQLite Database Configuration",
                "USE_DATABASE = True",
                f'DB_URL = "sqlite:///{os.path.join(os.getcwd(), "vulnscanner.db").replace(chr(92), "/")}"',
                "DB_ECHO = False"
            ])
        
        # Write updated config
        with open(config_path, 'w') as f:
            f.write('\n'.join(new_config_lines))
        
        print("✅ Config updated for SQLite")
        
    except Exception as e:
        print(f"⚠️  Could not update config.py: {e}")
        print("Will use default SQLite settings")
    
    # Test database creation
    try:
        from core.database import db_manager
        
        if db_manager.connected:
            print("✅ SQLite database initialized successfully")
            
            # Test basic operations
            with db_manager.get_session() as session:
                from core.database import ScanSession, Vulnerability, Target
                
                session_count = session.query(ScanSession).count()
                vuln_count = session.query(Vulnerability).count()
                target_count = session.query(Target).count()
                
                print(f"📊 Database Status:")
                print(f"   Scan Sessions: {session_count}")
                print(f"   Vulnerabilities: {vuln_count}")
                print(f"   Targets: {target_count}")
            
            db_file = os.path.join(os.getcwd(), "vulnscanner.db")
            if os.path.exists(db_file):
                size_mb = os.path.getsize(db_file) / (1024*1024)
                print(f"📁 Database file: {db_file} ({size_mb:.2f} MB)")
            
            print("\n🎉 SQLite Database Setup Complete!")
            return True
            
        else:
            print("❌ Failed to initialize SQLite database")
            return False
            
    except Exception as e:
        print(f"❌ Error setting up SQLite database: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main setup function"""
    success = setup_sqlite_database()
    
    if success:
        print("\n" + "=" * 60)
        print("✅ SQLite Database Integration Complete!")
        print("\nAdvantages of SQLite:")
        print("• No server setup required")
        print("• Single file database")
        print("• Full SQL support")
        print("• Perfect for development and small deployments")
        print("• Persistent data storage")
        print("\n🚀 Ready to start: python main.py")
        return True
    else:
        print("\n❌ SQLite setup failed")
        return False

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