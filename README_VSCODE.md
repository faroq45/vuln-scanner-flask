# 🛡️ VulScanner - VS Code Integration

Your vulscanner is now fully integrated with VS Code for an enhanced development experience!

## 🚀 Quick Start in VS Code

### Method 1: Using VS Code Tasks (Recommended)
1. **Open Command Palette**: `Ctrl+Shift+P`
2. **Run Task**: Type "Tasks: Run Task"
3. **Select**: "🚀 Start VulScanner"

### Method 2: Using Debug/Run
1. **Press**: `F5` or `Ctrl+F5`
2. **Select**: "🚀 Start VulScanner"

### Method 3: Using Terminal
1. **Open Terminal**: `Ctrl+`` (backtick)
2. **Run**: `python main.py`

## 📋 Available VS Code Features

### 🎯 Launch Configurations (F5)
- **🚀 Start VulScanner**: Launch the main application
- **🗄️ Setup SQLite Database**: Initialize the database
- **🧪 Test Scanner Components**: Run component tests
- **✅ Verify VulScanner Branding**: Check all branding is correct

### ⚡ Tasks (Ctrl+Shift+P → Tasks: Run Task)
- **🚀 Start VulScanner**: Launch the web application
- **🗄️ Setup Database**: Initialize SQLite database
- **🧪 Test Components**: Test all VulScanner components
- **📋 Install Requirements**: Install Python dependencies
- **🔍 Check Python Path**: Verify Python installation
- **✅ Verify VulScanner Branding**: Check all branding is correct
- **🌐 Open VulScanner in Browser**: Launch web interface

### 🔧 Integrated Features
- **Syntax Highlighting**: Full Python, HTML, CSS, JS support
- **IntelliSense**: Auto-completion for all code
- **Debugging**: Set breakpoints and debug your scanner
- **Terminal Integration**: PowerShell terminal built-in
- **File Explorer**: Easy navigation of scanner components

## 🌐 Access Your Scanner

Once running, access your vulscanner at:
- **Local**: http://127.0.0.1:8080
- **Network**: http://10.55.235.210:8080

## 📁 Project Structure

```
vulscanner/
├── 📁 core/           # Core scanner modules
├── 📁 rules/          # Vulnerability detection rules  
├── 📁 templates/      # Web interface templates
├── 📁 static/         # CSS, JS, images
├── 📁 views/          # Flask route handlers
├── 📁 bin/            # Background processes
├── 🗄️ vulnscanner.db  # SQLite database
├── 🚀 main.py         # Main application entry point
└── ⚙️ config.py       # Configuration settings
```

## 🛠️ Development Workflow

1. **Code**: Edit scanner modules in VS Code
2. **Debug**: Use F5 to run with debugger
3. **Test**: Run tasks to verify components
4. **Scan**: Use the web interface to test scans
5. **Iterate**: Make changes and restart

## 🎨 Customization

### Modify Scanning Rules
- Edit files in `rules/` directory
- Restart scanner to apply changes

### Update Web Interface
- Modify templates in `templates/`
- Edit CSS in `static/css/`
- Changes apply immediately (Flask auto-reload)

### Database Operations
- View database: Use VS Code SQLite extensions
- Query data: Access `/database` endpoint in web interface

## 🚨 Troubleshooting

### If Scanner Won't Start:
1. Check Python path: Run "🔍 Check Python Path" task
2. Install dependencies: Run "📋 Install Requirements" task
3. Setup database: Run "🗄️ Setup Database" task

### If Port is Busy:
- Change `WEB_PORT` in `config.py`
- Or kill existing process

## 🎆 Next Steps

- **Explore Code**: Browse the scanner modules
- **Add Features**: Extend scanning capabilities
- **Create Rules**: Add new vulnerability detection rules
- **Customize UI**: Modify the web interface
- **Deploy**: Package for production use
- **Verify Branding**: Run branding verification anytime

Happy scanning with VulScanner! 🔍✨
