# 🛡️ Advanced Vulnerability Scanner - Flask Edition

A comprehensive, enterprise-grade vulnerability scanning platform with AI/ML-powered payload generation, zero-day detection, and threat intelligence integration.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Redis](https://img.shields.io/badge/Redis-7.0+-red.svg)](https://redis.io/)

---

## 🌟 Features

### Core Capabilities
- 🔍 **Network Scanning**: Port scanning, service detection, OS fingerprinting
- 🎯 **Vulnerability Detection**: OWASP Top 10, CVE database integration
- 🤖 **AI/ML Payload Generation**: 15+ advanced algorithms for sophisticated attack simulation
- 🚨 **Zero-Day Detection**: Pattern-based and behavioral anomaly detection
- 📊 **Threat Intelligence**: Integration with 6+ threat intel feeds
- 📈 **Real-time Dashboard**: Live scanning status and vulnerability tracking
- 📝 **Comprehensive Reports**: PDF/JSON/CSV export capabilities
- 👥 **Multi-user Support**: Role-based access control
- 🔐 **Secure Architecture**: Session management, authentication, and authorization

### Advanced Features

#### 1. **AI/ML-Powered Payload Generation** 🧠
- **15 Algorithms**:
  - Deep Neural Networks with Backpropagation
  - Multi-Objective Genetic Algorithms
  - Deep Q-Learning with Experience Replay
  - Enhanced Particle Swarm Optimization
  - Adversarial Training (GAN-style)
  - Transformer-based Sequence Generation
  - LSTM Neural Networks
  - Simulated Annealing
  - Ant Colony Optimization
  - Bayesian Optimization
  - Actor-Critic Reinforcement Learning
  - Metamorphic Payload Generation
  - Steganographic Encoding
  - Adversarial ML Resistance
  - Real-time Adaptive Learning

#### 2. **Zero-Day Detection Module** 🎯
- Pattern-based vulnerability detection
- Behavioral anomaly analysis
- Time-based blind detection
- Response correlation analysis
- Active exploit detection (Log4Shell, Spring4Shell, ShellShock)

#### 3. **Threat Intelligence Integration** 🌐
- CVE feed integration
- Exploit database correlation
- IOC (Indicators of Compromise) matching
- Real-time threat updates

#### 4. **OWASP Top 10 Coverage** ✅
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Template Injection
- XML External Entity (XXE)
- Deserialization Attacks
- LDAP Injection
- NoSQL Injection
- SSRF (Server-Side Request Forgery)

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Redis Server
- Git

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/faroq45/vuln-scanner-flask.git
cd vuln-scanner-flask
```

2. **Create virtual environment**
```bash
python -m venv env

# Windows
env\Scripts\activate

# Linux/Mac
source env/bin/activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Install additional WSGI server (optional)**
```bash
# For Windows
pip install waitress

# For Linux/Unix
pip install gunicorn
```

5. **Start Redis**
```bash
# Windows (if installed as service)
net start redis

# Linux/Mac
redis-server
```

6. **Run the application**

**Development Mode:**
```bash
python main.py
```

**Production Mode (Windows):**
```bash
python run_waitress.py
# or
start_production.bat
```

**Production Mode (Linux/Unix):**
```bash
gunicorn -c gunicorn_config.py wsgi:application
```

7. **Access the application**
```
http://localhost:8080
```

---

## 📖 Documentation

- [Installation Guide](INSTALLATION.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Advanced Payloads](ADVANCED_PAYLOADS_README.md)
- [API Documentation](docs/API.md)
- [Configuration Guide](docs/CONFIGURATION.md)

---

## 🏗️ Architecture

```
vuln-scanner-flask/
├── bin/                    # Background worker processes
│   ├── scanner.py         # Port and service scanner
│   ├── attacker.py        # Vulnerability exploitation
│   └── scheduler.py       # Scheduled scanning
├── core/                  # Core functionality
│   ├── database.py        # Database management (SQLite/PostgreSQL)
│   ├── redis.py          # Redis session management
│   ├── workers.py        # Worker thread management
│   ├── payload_generator_enhanced.py       # 8 AI/ML algorithms
│   ├── payload_generator_ultra_enhanced.py # 15+ advanced algorithms
│   ├── owasp_wrapper.py  # OWASP scanner integration
│   └── ...
├── rules/                 # Vulnerability detection rules
│   └── vulnerabilities/  # Individual rule modules
│       ├── rule_zeroday-detection.py
│       ├── rule_zeroday-intelligence.py
│       └── rule_advanced-payload-detection.py
├── views/                 # Web interface views
├── templates/            # HTML templates
├── static/               # Static assets (CSS, JS, images)
├── config.py            # Main configuration
├── config_zeroday.py    # Zero-day detection config
├── main.py              # Application entry point
├── wsgi.py              # WSGI entry point
└── requirements.txt     # Python dependencies
```

---

## ⚙️ Configuration

### Basic Configuration (`config.py`)

```python
# Web Server
WEB_HOST = '0.0.0.0'
WEB_PORT = 8080
WEB_DEBUG = False

# Redis
RDS_HOST = 'localhost'
RDS_PORT = 6379

# Database (PostgreSQL or SQLite)
DB_TYPE = 'postgresql'  # or 'sqlite'
DB_HOST = 'localhost'
DB_PORT = 5432
DB_NAME = 'vuln_scanner'
DB_USER = 'your_user'
DB_PASSWORD = 'your_password'
```

### Zero-Day Detection (`config_zeroday.py`)

```python
ZERODAY_ENABLED = True
ZERODAY_AGGRESSIVE_MODE = True
ZERODAY_MAX_PAYLOADS = 100
MACHINE_LEARNING_ENABLED = True
```

---

## 🎯 Usage

### 1. **Create a User Account**
- Navigate to `/signup`
- Create your account
- Login at `/login`

### 2. **Start a Scan**
- Go to **Quick Scan** or **Assessment**
- Enter target IP range or URL
- Configure scan options
- Click **Start Scan**

### 3. **Monitor Progress**
- View real-time progress in the dashboard
- Check discovered assets
- Review vulnerabilities as they're found

### 4. **Generate Reports**
- Navigate to **Reports**
- Select scan session
- Export as PDF, JSON, or CSV

---

## 🔒 Security Features

- ✅ Session-based authentication
- ✅ Password hashing (bcrypt)
- ✅ SQL injection prevention
- ✅ XSS protection
- ✅ CSRF protection
- ✅ Rate limiting on login attempts
- ✅ Secure cookie handling
- ✅ Content Security Policy headers
- ✅ User activity logging

---

## 📊 Supported Vulnerability Types

| Category | Tests |
|----------|-------|
| **SQL Injection** | Union-based, Boolean-based, Time-based, Error-based |
| **XSS** | Reflected, Stored, DOM-based |
| **Command Injection** | OS command, Code execution |
| **Path Traversal** | Directory traversal, File inclusion |
| **Template Injection** | SSTI (Jinja2, Smarty, etc.) |
| **XXE** | XML External Entity attacks |
| **Deserialization** | Pickle, YAML, JSON unsafe deserialization |
| **Authentication** | Weak passwords, Default credentials |
| **Information Disclosure** | Version disclosure, Debug info |
| **Misconfigurations** | Insecure headers, Missing patches |

---

## 🧪 Testing

Run the test suite:

```bash
# All tests
pytest

# Specific test file
pytest test_advanced_payloads.py

# With coverage
pytest --cov=core --cov-report=html
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**

This tool is designed for security professionals and researchers to test their own systems or systems they have explicit permission to test. Unauthorized access to computer systems is illegal.

The developers assume no liability and are not responsible for any misuse or damage caused by this program. Use at your own risk.

---

## 🙏 Acknowledgments

### Project Team
- **[@faroq45](https://github.com/faroq45)** - Creator and lead developer
- **[@obaidlone](https://github.com/obaidlone)** - Security features and vulnerability detection
- **[@shahidwan](https://github.com/shahidwan)** - Infrastructure and deployment
- **[@ASLAM1322](https://github.com/ASLAM1322)** - Frontend and UI/UX

### Special Thanks
- OWASP for vulnerability classifications
- Nmap for port scanning
- Flask community for the excellent web framework
- Redis for session management
- All open-source contributors

For full contributor list, see [CONTRIBUTORS.md](CONTRIBUTORS.md)

---

## 📧 Contact

- **Issues**: [GitHub Issues](https://github.com/faroq45/vuln-scanner-flask/issues)
- **Discussions**: [GitHub Discussions](https://github.com/faroq45/vuln-scanner-flask/discussions)

---

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=faroq45/vuln-scanner-flask&type=Date)](https://star-history.com/#faroq45/vuln-scanner-flask&Date)

---

**Built with ❤️ by Security Researchers, for Security Researchers**
