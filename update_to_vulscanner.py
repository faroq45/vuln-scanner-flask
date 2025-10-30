#!/usr/bin/env python3
"""
Update branding from websitescanner to vulscanner and remove vulscanner references
"""
import os
import re

def update_file_content(file_path):
    """Update a single file with vulscanner branding"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        
        original_content = content
        
        # Replace websitescanner with vulscanner
        content = re.sub(r'websitescanner', 'vulscanner', content)
        content = re.sub(r'Website Scanner', 'VulScanner', content)
        content = re.sub(r'website scanner', 'vulscanner', content)
        
        # Replace vulscanner references
        content = re.sub(r'nerve_logo', 'vulscanner_logo', content)
        content = re.sub(r'vulscanner\.css', 'vulscanner.css', content)
        
        # Update CSS references to use vulscanner
        content = re.sub(r'websitescanner\.css', 'vulscanner.css', content)
        
        # Remove Obaid Bashir attribution if present
        content = re.sub(r'<span[^>]*>.*?Obaid Bashir.*?</span>', '', content, flags=re.DOTALL)
        content = re.sub(r'Developed by.*?Obaid Bashir.*?</a>', '', content)
        
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
    """Main update function"""
    print("🔄 Updating to VulScanner Branding")
    print("=" * 50)
    
    # Directories to update
    directories = [
        'templates',
        'core', 
        'views',
        '.'  # Root directory
    ]
    
    # File extensions to update
    extensions = ['.py', '.html', '.css', '.js', '.md']
    
    updated_files = []
    
    for directory in directories:
        if os.path.exists(directory):
            print(f"\n📁 Processing {directory}/")
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if any(file.endswith(ext) for ext in extensions):
                        file_path = os.path.join(root, file)
                        
                        # Skip certain files
                        if any(skip in file_path for skip in ['.git', '__pycache__', '.vscode', 'vulnscanner.db', 'update_', 'verify_', 'BRANDING_']):
                            continue
                        
                        if update_file_content(file_path):
                            updated_files.append(file_path)
                            print(f"  ✅ Updated: {file_path}")
    
    print(f"\n🎉 VulScanner Branding Update Complete!")
    print(f"📋 Updated {len(updated_files)} files")
    
    print(f"\n✨ Your scanner is now branded as 'VulScanner'")
    print(f"🔗 GitHub link still points to: https://github.com/obaidlone/website-scanner")
    print(f"🎯 Login page: Clean without developer attribution")

if __name__ == "__main__":
    main()