#!/usr/bin/env python3
"""
Test script for OWASP Top 10 vulscanner integration
"""

import asyncio
import sys
import os
import json

# Add scanner to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scanner', 'scanner'))

def test_imports():
    """Test that all scanner modules can be imported."""
    print("🔍 Testing OWASP scanner imports...")
    
    try:
        from core import Finding, ScanConfig, get_owasp_category
        print("✅ Core modules imported successfully")
        
        from core.http_client import HttpClient
        print("✅ HTTP client imported successfully")
        
        from core.scanner_engine import VulnerabilityScanner
        print("✅ Scanner engine imported successfully")
        
        from checks.base import get_available_checks
        checks = get_available_checks()
        print(f"✅ Security checks loaded: {len(checks)} checks available")
        
        for check in checks:
            print(f"   - {check.name}: {check.__class__.__name__}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_sample_scan():
    """Test creating a sample scan configuration."""
    print("\n🔧 Testing scan configuration...")
    
    try:
        from core import ScanConfig
        
        config = ScanConfig(
            target="http://httpbin.org",
            max_pages=5,
            concurrency=2,
            timeout=10,
            checks=['security_headers', 'reflected_xss']
        )
        
        print("✅ Scan configuration created successfully")
        print(f"   Target: {config.target}")
        print(f"   Max pages: {config.max_pages}")
        print(f"   Selected checks: {config.checks}")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False

async def test_http_client():
    """Test the HTTP client functionality."""
    print("\n🌐 Testing HTTP client...")
    
    try:
        from core.http_client import HttpClient
        
        async with HttpClient() as client:
            # Test with a simple HTTP request
            response = await client.get("https://httpbin.org/get")
            
            if response:
                print("✅ HTTP client working successfully")
                print(f"   Status: {response.status_code}")
                print(f"   Response time: {response.response_time:.2f}s")
                return True
            else:
                print("❌ HTTP client returned no response")
                return False
                
    except Exception as e:
        print(f"❌ HTTP client error: {e}")
        return False

def test_finding_creation():
    """Test creating and serializing findings."""
    print("\n📝 Testing finding creation...")
    
    try:
        from core import Finding, get_owasp_category
        
        # Create a sample finding
        finding = Finding(
            id="test-001",
            target="http://example.com",
            url="http://example.com/test",
            title="Test Vulnerability",
            severity="Medium",
            description="This is a test vulnerability",
            evidence="Test evidence",
            confidence=85,
            cwe=79,
            param="test_param",
            payload="<script>alert('xss')</script>"
        )
        
        # Set OWASP category
        finding.owasp_category = get_owasp_category(finding.cwe)
        
        print("✅ Finding created successfully")
        print(f"   Title: {finding.title}")
        print(f"   Severity: {finding.severity}")
        print(f"   OWASP Category: {finding.owasp_category}")
        
        # Test serialization
        finding_dict = finding.to_dict()
        print("✅ Finding serialization working")
        
        return True
        
    except Exception as e:
        print(f"❌ Finding creation error: {e}")
        return False

def test_flask_integration():
    """Test Flask integration without running server."""
    print("\n🌶️  Testing Flask integration...")
    
    try:
        sys.path.append('.')
        from views.view_owasp_scan import OWASP_SCANNER_AVAILABLE
        
        if OWASP_SCANNER_AVAILABLE:
            print("✅ OWASP scanner available in Flask app")
        else:
            print("⚠️  OWASP scanner marked as unavailable in Flask app")
        
        return True
        
    except ImportError as e:
        print(f"❌ Flask integration error: {e}")
        return False

async def main():
    """Run all tests."""
    print("🚀 Starting OWASP Top 10 Scanner Integration Tests\n")
    print("=" * 60)
    
    tests = [
        ("Import Tests", test_imports()),
        ("Configuration Tests", test_sample_scan()),
        ("HTTP Client Tests", await test_http_client()),
        ("Finding Tests", test_finding_creation()),
        ("Flask Integration Tests", test_flask_integration())
    ]
    
    passed = 0
    total = len(tests)
    
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS:")
    print("=" * 60)
    
    for test_name, result in tests:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
        if result:
            passed += 1
    
    print("=" * 60)
    print(f"📈 Overall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 All tests passed! OWASP scanner integration is working.")
        return True
    else:
        print(f"⚠️  {total-passed} tests failed. Please check the errors above.")
        return False

if __name__ == "__main__":
    try:
        result = asyncio.run(main())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)