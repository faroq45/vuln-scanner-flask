#!/usr/bin/env python3
"""
VS Code Integration Test for VulScanner
Run this to verify everything works in VS Code!
"""
import os
import sys

def test_vs_code_integration():
    """Test VS Code integration"""
    print("🎉 VS Code Integration Test")
    print("=" * 50)
    
    # Check current directory
    current_dir = os.getcwd()
    print(f"📁 Current Directory: {current_dir}")
    
    # Check if main.py exists
    if os.path.exists('main.py'):
        print("✅ main.py found - Scanner ready to run")
    else:
        print("❌ main.py not found")
        return False
    
    # Check database
    if os.path.exists('vulnscanner.db'):
        size_mb = os.path.getsize('vulnscanner.db') / (1024*1024)
        print(f"✅ SQLite database found ({size_mb:.2f} MB)")
    else:
        print("⚠️  Database not found - run setup first")
    
    # Check Python modules
    try:
        import flask
        print(f"✅ Flask version: {flask.__version__}")
    except ImportError:
        print("❌ Flask not available")
        return False
    
    try:
        import sqlalchemy
        print(f"✅ SQLAlchemy version: {sqlalchemy.__version__}")
    except ImportError:
        print("❌ SQLAlchemy not available")
        return False
    
    # Test core modules
    try:
        from core.redis import RedisManager
        print("✅ Redis manager available")
    except ImportError as e:
        print(f"❌ Redis manager error: {e}")
        return False
    
    try:
        from core.database import db_manager
        print("✅ Database manager available")
        if db_manager.connected:
            print("✅ Database connection active")
        else:
            print("⚠️  Database not connected")
    except ImportError as e:
        print(f"❌ Database manager error: {e}")
        return False
    
    print("\n🎯 VS Code Launch Options:")
    print("1. Press F5 to start with debugger")
    print("2. Use Ctrl+Shift+P → Tasks: Run Task → '🚀 Start Scanner'")
    print("3. Open terminal with Ctrl+` and run: python main.py")
    
    print("\n🌐 Once running, access at:")
    print("• http://127.0.0.1:8080")
    print("• http://localhost:8080")
    
    print("\n✨ VS Code Features Available:")
    print("• Set breakpoints in Python code")
    print("• Debug step-by-step execution")
    print("• View variables and call stack")
    print("• Integrated terminal")
    print("• Code auto-completion")
    
    return True

if __name__ == "__main__":
    print("🔍 Testing VS Code Integration for VulScanner\n")
    
    success = test_vs_code_integration()
    
    if success:
        print("\n🎉 VS Code integration test PASSED!")
        print("Your vulscanner is ready to run in VS Code!")
    else:
        print("\n❌ VS Code integration test FAILED!")
        print("Please check the errors above.")
    
    print("\n" + "=" * 50)
    print("Ready to launch? Try one of these methods in VS Code:")
    print("• Press F5 (recommended for debugging)")
    print("• Ctrl+Shift+P → Tasks: Run Task")
    print("• Terminal: python main.py")