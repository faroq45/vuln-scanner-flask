#!/usr/bin/env python3
"""
Final verification that all branding is correctly set to VulScanner
"""
import os
import re

def main():
    """Verify VulScanner branding"""
    print("🔍 Final VulScanner Branding Verification")
    print("=" * 50)
    
    # Check key files
    key_checks = [
        {
            'file': 'templates/login.html',
            'should_contain': ['VulScanner', 'vulscanner_logo_black.png'],
            'should_not_contain': ['Nerve', 'nerve', 'Obaid Bashir', 'websitescanner']
        },
        {
            'file': 'templates/sidebar.html', 
            'should_contain': ['vulscanner_logo.png', 'obaidlone/website-scanner'],
            'should_not_contain': ['Nerve', 'nerve', 'websitescanner']
        },
        {
            'file': 'config.py',
            'should_contain': ['vulscanner.log', 'vulscanner'],
            'should_not_contain': ['nerve', 'websitescanner', 'vulnscannerflask']
        }
    ]
    
    print("📋 Checking key files...")
    all_good = True
    
    for check in key_checks:
        file_path = check['file']
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                print(f"\n📄 {file_path}:")
                
                # Check should contain
                for item in check['should_contain']:
                    if item in content:
                        print(f"  ✅ Contains: {item}")
                    else:
                        print(f"  ❌ Missing: {item}")
                        all_good = False
                
                # Check should not contain
                for item in check['should_not_contain']:
                    if item in content:
                        print(f"  ⚠️  Still contains: {item}")
                        all_good = False
                    else:
                        print(f"  ✅ Clean of: {item}")
                        
            except Exception as e:
                print(f"  ❌ Error reading {file_path}: {e}")
                all_good = False
        else:
            print(f"  ❌ File not found: {file_path}")
            all_good = False
    
    # Check assets
    print(f"\n🎨 Checking assets...")
    required_assets = [
        'static/img/vulscanner_logo.png',
        'static/img/vulscanner_logo_black.png',
        'static/css/vulscanner.css'
    ]
    
    for asset in required_assets:
        if os.path.exists(asset):
            size = os.path.getsize(asset)
            print(f"  ✅ {asset} ({size} bytes)")
        else:
            print(f"  ❌ Missing: {asset}")
            all_good = False
    
    # Check for any remaining old branding
    print(f"\n🔍 Scanning for old branding...")
    old_terms = ['nerve', 'Nerve', 'NERVE', 'websitescanner', 'vulnscannerflask']
    found_issues = []
    
    # Only check main application files, not our update scripts
    for root, dirs, files in os.walk('.'):
        # Skip certain directories
        if any(skip in root for skip in ['.git', '__pycache__', '.vscode', 'reports']):
            continue
            
        for file in files:
            if file.endswith(('.py', '.html', '.css', '.js')):
                file_path = os.path.join(root, file)
                
                # Skip our update scripts
                if any(skip in file for skip in ['verify_', 'update_', 'remove_nerve_', 'BRANDING_']):
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    for term in old_terms:
                        if re.search(rf'\\b{re.escape(term)}\\b', content):
                            found_issues.append(f"{file_path}: contains '{term}'")
                except:
                    pass
    
    if found_issues:
        print("  ⚠️  Found old branding:")
        for issue in found_issues[:5]:  # Show first 5
            print(f"    • {issue}")
        if len(found_issues) > 5:
            print(f"    ... and {len(found_issues) - 5} more issues")
        all_good = False
    else:
        print("  ✅ No old branding found!")
    
    # Final result
    print(f"\n" + "=" * 50)
    if all_good:
        print("🎉 VulScanner Branding Verification PASSED!")
        print("✨ Your scanner is perfectly branded as VulScanner")
        print("🔗 GitHub link: https://github.com/obaidlone/website-scanner")
        print("🎯 Clean login page without developer attribution")
        print("🚀 Ready to use at: http://127.0.0.1:8080")
    else:
        print("⚠️  VulScanner Branding Verification found issues")
        print("Please review the items marked with ❌ above")
    
    print(f"\n📊 Summary:")
    print(f"  • Project Name: VulScanner")
    print(f"  • Technical Name: vulscanner")
    print(f"  • GitHub Repo: obaidlone/website-scanner")
    print(f"  • Login Attribution: None (clean)")
    print(f"  • Assets: vulscanner_logo.png, vulscanner.css")

if __name__ == "__main__":
    main()