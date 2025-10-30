#!/usr/bin/env python3
"""
Test VS Code integration for VulScanner
"""
import os
import json

def test_vscode_integration():
    """Test that VS Code files are properly configured for VulScanner"""
    print("🔍 Testing VS Code Integration for VulScanner")
    print("=" * 55)
    
    # Check VS Code files exist
    vscode_files = {
        '.vscode/launch.json': 'Launch configurations',
        '.vscode/tasks.json': 'Task definitions',
        '.vscode/settings.json': 'Workspace settings',
        'vulscanner.code-workspace': 'Workspace file'
    }
    
    all_good = True
    
    print("📁 Checking VS Code files...")
    for file_path, description in vscode_files.items():
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            print(f"  ✅ {file_path}: {description} ({size} bytes)")
        else:
            print(f"  ❌ {file_path}: Missing {description}")
            all_good = False
    
    # Check launch.json content
    print(f"\n🚀 Checking launch configurations...")
    try:
        with open('.vscode/launch.json', 'r') as f:
            launch_config = json.load(f)
        
        expected_configs = [
            "Start VulScanner",
            "Setup SQLite Database", 
            "Test Scanner Components",
            "Verify VulScanner Branding"
        ]
        
        found_configs = [config['name'] for config in launch_config['configurations']]
        
        for expected in expected_configs:
            if expected in found_configs:
                print(f"  ✅ Launch config: {expected}")
            else:
                print(f"  ❌ Missing launch config: {expected}")
                all_good = False
                
    except Exception as e:
        print(f"  ❌ Error reading launch.json: {e}")
        all_good = False
    
    # Check tasks.json content
    print(f"\n⚡ Checking task definitions...")
    try:
        with open('.vscode/tasks.json', 'r') as f:
            tasks_config = json.load(f)
        
        expected_tasks = [
            "Start VulScanner",
            "Setup Database",
            "Test Components",
            "Verify VulScanner Branding",
            "Open VulScanner in Browser"
        ]
        
        found_tasks = [task['label'] for task in tasks_config['tasks']]
        
        for expected in expected_tasks:
            if expected in found_tasks:
                print(f"  ✅ Task: {expected}")
            else:
                print(f"  ❌ Missing task: {expected}")
                all_good = False
                
    except Exception as e:
        print(f"  ❌ Error reading tasks.json: {e}")
        all_good = False
    
    # Check workspace file
    print(f"\n📂 Checking workspace configuration...")
    try:
        with open('vulscanner.code-workspace', 'r') as f:
            workspace_config = json.load(f)
        
        if 'folders' in workspace_config and len(workspace_config['folders']) > 0:
            print(f"  ✅ Workspace folder configured")
        else:
            print(f"  ❌ No workspace folders configured")
            all_good = False
            
        if 'launch' in workspace_config:
            launch_configs = workspace_config['launch']['configurations']
            if any('VulScanner' in config['name'] for config in launch_configs):
                print(f"  ✅ VulScanner launch config in workspace")
            else:
                print(f"  ❌ No VulScanner launch config in workspace")
                all_good = False
        
    except Exception as e:
        print(f"  ❌ Error reading workspace file: {e}")
        all_good = False
    
    # Final result
    print(f"\n" + "=" * 55)
    if all_good:
        print("🎉 VS Code Integration Test PASSED!")
        print("✨ Your VulScanner is perfectly integrated with VS Code!")
        print("\n📋 Available in VS Code:")
        print("  • Press F5 → Start VulScanner")
        print("  • Ctrl+Shift+P → Tasks: Run Task → VulScanner tasks")
        print("  • Integrated debugging and terminal")
        print("  • One-click browser launch")
        print("  • Branding verification tools")
    else:
        print("⚠️  VS Code Integration Test found issues")
        print("Please review the items marked with ❌ above")
    
    print(f"\n🚀 Ready to code VulScanner in VS Code!")
    return all_good

if __name__ == "__main__":
    test_vscode_integration()