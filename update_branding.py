#!/usr/bin/env python3
"""
Batch update script to rebrand from website-scanner to Website Scanner
and update GitHub references to obaidlone
"""
import os
import re
from pathlib import Path

def update_file_content(file_path):
    """Update a single file with new branding"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        
        original_content = content
        
        # Replace GitHub references
        content = re.sub(r'https://github\.com/obaidlone[^"\s]*', 'https://github.com/obaidlone/website-scanner', content)
        content = re.sub(r'obaidlone/website-scanner', 'obaidlone/website-scanner', content)
        content = re.sub(r'obaidlone', 'obaidlone', content, flags=re.IGNORECASE)
        
        # Replace branding
        content = re.sub(r'websitescanner', 'websitescanner', content)
        content = re.sub(r'website-scanner', 'website-scanner', content)
        content = re.sub(r'Website Scanner', 'Website Scanner', content)
        content = re.sub(r'website scanner', 'website scanner', content)
        
        # Replace titles
        content = re.sub(r'<title>websitescanner</title>', '<title>Website Scanner</title>', content)
        content = re.sub(r'<title>Website Scanner</title>', '<title>Website Scanner</title>', content)
        
        # Replace image references
        content = re.sub(r'websitescanner_logo', 'websitescanner_logo', content)
        
        # Replace CSS references
        content = re.sub(r'websitescanner\.css', 'websitescanner.css', content)
        
        # Replace powered by references
        content = re.sub(r'Powered\s+by.*obaidlone', 'Developed by <a href="https://github.com/obaidlone" target="_blank">Obaid Bashir</a>', content)
        
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
    print("🔄 Updating Website Scanner Branding")
    print("=" * 50)
    
    # Directories to update
    directories = [
        'templates',
        'core',
        'rules',
        'views',
        'bin',
        '.'  # Root directory
    ]
    
    # File extensions to update
    extensions = ['.py', '.html', '.css', '.js', '.md', '.txt', '.json', '.sh']
    
    updated_files = []
    
    for directory in directories:
        if os.path.exists(directory):
            print(f"\n📁 Processing {directory}/")
            
            # Get all files in directory
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if any(file.endswith(ext) for ext in extensions):
                        file_path = os.path.join(root, file)
                        
                        # Skip certain files
                        if any(skip in file_path for skip in ['.git', '__pycache__', 'node_modules', '.vscode', 'vulnscanner.db']):
                            continue
                        
                        if update_file_content(file_path):
                            updated_files.append(file_path)
                            print(f"  ✅ Updated: {file_path}")
    
    print(f"\n🎉 Branding Update Complete!")
    print(f"📋 Updated {len(updated_files)} files:")
    
    for file_path in updated_files[:10]:  # Show first 10
        print(f"  • {file_path}")
    
    if len(updated_files) > 10:
        print(f"  ... and {len(updated_files) - 10} more files")
    
    print(f"\n✨ Your scanner is now branded as 'Website Scanner'")
    print(f"🔗 GitHub references point to: https://github.com/obaidlone/website-scanner")
    print(f"👤 Credited to: Obaid Bashir")

if __name__ == "__main__":
    main()