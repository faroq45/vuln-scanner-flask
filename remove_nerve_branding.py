#!/usr/bin/env python3
"""
Remove any remaining VulScanner branding and replace with vulscanner
"""
import os
import re

def update_file_content(file_path):
    """Update a single file to remove VulScanner references"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        
        original_content = content
        
        # Replace all variations of VulScanner with vulscanner
        content = re.sub(r'\bNerve\b', 'VulScanner', content)
        content = re.sub(r'\bnerve\b', 'vulscanner', content)
        content = re.sub(r'\bNERVE\b', 'VULSCANNER', content)
        
        # Replace in titles and headers
        content = re.sub(r'<title>VulScanner</title>', '<title>VulScanner</title>', content)
        content = re.sub(r'<title>vulscanner</title>', '<title>VulScanner</title>', content)
        
        # Replace in comments and documentation
        content = re.sub(r'# VulScanner', '# VulScanner', content)
        content = re.sub(r'## VulScanner', '## VulScanner', content)
        content = re.sub(r'### VulScanner', '### VulScanner', content)
        
        # Replace in configuration values
        content = re.sub(r'"vulscanner"', '"vulscanner"', content)
        content = re.sub(r"'vulscanner'", "'vulscanner'", content)
        
        # Only write if content changed
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(content)
            return True
        return False
        
    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        return False

def main():
    """Main function to remove VulScanner branding"""
    print("🔄 Removing VulScanner Branding - Updating to VulScanner")
    print("=" * 60)
    
    # Directories to check
    directories = [
        'templates',
        'core',
        'rules',
        'views',
        'bin',
        'static',
        'data',
        '.'  # Root directory
    ]
    
    # File extensions to update
    extensions = ['.py', '.html', '.css', '.js', '.md', '.txt', '.json', '.yml', '.yaml', '.sh']
    
    updated_files = []
    total_files_checked = 0
    
    for directory in directories:
        if os.path.exists(directory):
            print(f"\n📁 Checking {directory}/")
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if any(file.endswith(ext) for ext in extensions):
                        file_path = os.path.join(root, file)
                        total_files_checked += 1
                        
                        # Skip certain files
                        skip_files = ['.git', '__pycache__', 'node_modules', '.vscode', 'vulnscanner.db']
                        if any(skip in file_path for skip in skip_files):
                            continue
                        
                        if update_file_content(file_path):
                            updated_files.append(file_path)
                            print(f"  ✅ Updated: {file_path}")
    
    print(f"\n" + "=" * 60)
    print("🎉 VulScanner Branding Removal Complete!")
    print(f"📊 Statistics:")
    print(f"  • Files checked: {total_files_checked}")
    print(f"  • Files updated: {len(updated_files)}")
    
    if updated_files:
        print(f"\n📋 Updated files:")
        for file_path in updated_files[:10]:  # Show first 10
            print(f"  • {file_path}")
        if len(updated_files) > 10:
            print(f"  ... and {len(updated_files) - 10} more files")
    else:
        print("\n✅ No VulScanner references found - all clean!")
    
    # Check for remaining VulScanner references
    print(f"\n🔍 Verifying removal...")
    remaining_found = False
    
    for directory in directories:
        if os.path.exists(directory):
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if any(file.endswith(ext) for ext in ['.py', '.html', '.css', '.js']):
                        file_path = os.path.join(root, file)
                        
                        # Skip update scripts
                        if 'remove_nerve_branding' in file_path or 'update_' in file:
                            continue
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if re.search(r'\bNerve\b|\bnerve\b|\bNERVE\b', content):
                                    print(f"⚠️  Found remaining VulScanner reference in: {file_path}")
                                    remaining_found = True
                        except:
                            pass
    
    if not remaining_found:
        print("✅ Verification passed - No remaining VulScanner references found!")
    
    print(f"\n🚀 Your scanner is now fully branded as 'VulScanner'!")
    print(f"🌟 Ready to use at: http://127.0.0.1:8080")

if __name__ == "__main__":
    main()