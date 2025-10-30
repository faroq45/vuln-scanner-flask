#!/usr/bin/env python3
"""
Verify that all branding has been updated correctly
"""
import os
import re

def check_file_for_old_branding(file_path):
    """Check a file for old branding that should have been updated"""
    old_patterns = [
        r'krishpranav',
        r'vulnscannerflask',
        r'vuln-scanner-flask', 
        r'vulnerability scanner',
        r'Vulnerability Scanner'
    ]
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        
        issues = []
        for pattern in old_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                matches = re.findall(pattern, content, re.IGNORECASE)
                issues.append(f"Found '{pattern}': {len(matches)} occurrences")
        
        return issues
    except Exception:
        return []

def main():
    """Main verification function"""
    print("🔍 Verifying Website Scanner Branding Updates")
    print("=" * 50)
    
    # Check key files
    key_files = [
        'templates/login.html',
        'templates/sidebar.html', 
        'templates/dashboard.html',
        'config.py',
        'README.md'
    ]
    
    total_issues = 0
    
    for file_path in key_files:
        if os.path.exists(file_path):
            issues = check_file_for_old_branding(file_path)
            if issues:
                print(f"\n⚠️  {file_path}:")
                for issue in issues:
                    print(f"    {issue}")
                total_issues += len(issues)
            else:
                print(f"✅ {file_path}: Clean")
    
    # Check if new assets exist
    print(f"\n📁 Checking Static Assets:")
    
    new_assets = [
        'static/img/websitescanner_logo.png',
        'static/img/websitescanner_logo_black.png',
        'static/css/websitescanner.css'
    ]
    
    for asset in new_assets:
        if os.path.exists(asset):
            print(f"✅ {asset}: Exists")
        else:
            print(f"❌ {asset}: Missing")
            total_issues += 1
    
    # Summary
    print(f"\n" + "=" * 50)
    if total_issues == 0:
        print("🎉 All branding updates completed successfully!")
        print("✨ Your Website Scanner is ready with:")
        print("  • Updated GitHub link: https://github.com/obaidlone/website-scanner")
        print("  • New branding: Website Scanner") 
        print("  • Attribution: Obaid Bashir")
    else:
        print(f"⚠️  Found {total_issues} potential issues to review")
    
    print(f"\n🚀 Ready to launch your rebranded Website Scanner!")

if __name__ == "__main__":
    main()