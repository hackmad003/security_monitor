# 🛡️ Windows Security Event Monitor

A comprehensive, real-time security monitoring system for Windows environments that detects threats like brute-force attacks, privilege escalation, and persistence mechanisms by analyzing Windows Security Event Logs.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Detection Algorithms](#-detection-algorithms)
- [API & Dashboard](#-api--dashboard)
- [Alerting & Notifications](#-alerting--notifications)
- [Security Features](#-security-features)
- [Development](#-development)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

## ✨ Features

### Core Capabilities
- 🔍 **Real-time Security Monitoring** - Continuous analysis of Windows Security Event Logs
- 🎯 **Multi-Target Support** - Monitor multiple Windows machines simultaneously
- 🤖 **Intelligent Threat Detection** - Advanced algorithms for brute-force, privilege escalation, and persistence
- 📊 **Web Dashboard** - Secure, interactive dashboard with JWT authentication
- 🗄️ **Data Persistence** - MongoDB storage with flexible querying capabilities
- 📧 **Multi-Channel Alerts** - Email, Splunk HEC, console, and file-based notifications
- 🔐 **Enterprise Security** - Rate limiting, input validation, secure credential storage

### Detection Capabilities
- **Brute Force Detection** - Identifies failed login patterns across accounts
- **Privilege Escalation** - Detects unauthorized elevation of privileges
- **Persistence Mechanisms** - Identifies scheduled tasks and startup modifications
- **Account Manipulation** - Monitors user creation and privilege assignments

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Monitor                          │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Event Reader │  │  Detectors   │  │   Storage    │     │
│  │              │  │              │  │              │     │
│  │ - Local WMI  │→ │ - Brute Force│→ │ - MongoDB    │     │
│  │ - Remote WMI │  │ - Privilege  │  │ - JSON Export│     │
│  │              │  │ - Persistence│  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                           ↓                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │             Notifications & Alerts                    │  │
│  │  - Email  - Splunk HEC  - Console  - File Logger    │  │
│  └──────────────────────────────────────────────────────┘  │
│                           ↓                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │          Web Dashboard (FastAPI + WebSocket)         │  │
│  │  - JWT Auth  - Rate Limiting  - Real-time Updates   │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 📦 Prerequisites

### System Requirements
- **Operating System**: Windows 10/11 or Windows Server 2016+
- **Python**: 3.8 or higher
- **MongoDB**: 4.0+ (optional, for data persistence)
- **Privileges**: Administrator rights (to read Security Event Logs)

### Python Dependencies
```
fastapi>=0.100.0
uvicorn[standard]>=0.23.0
pymongo>=4.0.0
python-dotenv>=1.0.0
pyyaml>=6.0.0
pywin32>=305
cryptography>=41.0.0
python-jose[cryptography]>=3.3.0
passlib[bcrypt]>=1.7.4
```

## 🚀 Installation

### 1. Clone the Repository
```powershell
git clone https://github.com/yourusername/security-monitor.git
cd security-monitor
```

### 2. Set Up Python Environment
```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment Variables
```powershell
# Copy example configuration
copy .env.example .env

# Edit .env with your settings
notepad .env
```

### 4. Set Up MongoDB (Optional)
```powershell
# Install MongoDB Community Edition
# https://www.mongodb.com/try/download/community

# Start MongoDB service
net start MongoDB
```

### 5. Initialize Security Components
```powershell
# Create admin user for dashboard
python scripts/manage_users.py

# Migrate credentials to secure storage
python scripts/migrate_credentials.py

# Test configuration
python scripts/test_startup.py
```

## ⚙️ Configuration

### Main Configuration Files

#### `config/settings.yaml`
```yaml
event_log:
  server: localhost
  log_type: Security

critical_events:
  4625: Failed Login Attempt
  4624: Successful Login
  4720: User Account Created
  4672: Admin Privileges Assigned
  4698: Scheduled Task Created
  4688: Process Created
  4663: File Access Attempt

detection:
  brute_force_threshold: 5
  alert_reset_interval_hours: 1

detectors:
  brute_force:
    enabled: true
    threshold: 5
  privilege_escalation:
    enabled: true
  persistence:
    enabled: true

monitoring:
  default_event_count: 5000
  realtime_interval_seconds: 10
  events_per_check: 5000
```

#### `config/targets.yaml`
```yaml
targets:
  - name: LocalMachine
    host: localhost
    enabled: true
    description: Main monitoring server
    
  - name: RemoteServer1
    host: 192.168.1.100
    enabled: true
    description: Production web server

credentials:
  username: Administrator
  password: <stored_securely>
```

#### `.env` Configuration
```bash
# MongoDB
MONGO_URI=mongodb://localhost:27017/security_monitor
MONGO_DB_NAME=security_monitor

# Email Alerts
EMAIL_ENABLED=true
EMAIL_FROM=alerts@yourdomain.com
EMAIL_TO=security-team@yourdomain.com
EMAIL_PASSWORD=your-app-password
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587

# Alert Thresholds
FAILED_LOGIN_THRESHOLD=5
ALERT_WINDOW_MINUTES=15

# Dashboard
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=5000

# Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/security_monitor.log
```

## 🎮 Usage

### Command Line Interface

#### Single Analysis (One-time scan)
```powershell
python main.py --mode single --events 5000
```

#### Real-time Monitoring (Continuous)
```powershell
python main.py --mode realtime --interval 10
```

#### Multi-Target Monitoring (All configured targets)
```powershell
python main.py --mode multi
```

#### View Statistics
```powershell
python main.py --mode stats --days 7
```

### Web Dashboard

#### Start Dashboard Server
```powershell
# Simple start
scripts\start_dashboard.bat

# Or with Python
python security_monitor/dashboard/web_dashboard_secure.py
```

#### Access Dashboard
1. Open browser: `http://localhost:5000`
2. Login with credentials created via `scripts/manage_users.py`
3. View real-time alerts, events, and analytics

### Quick Start Scripts

#### Windows Batch Scripts
```powershell
# First time setup and monitoring
START_HERE.bat

# Start monitoring with default settings
start_monitor.bat

# Launch web dashboard
start_dashboard.bat
```

## 📁 Project Structure

```
security-monitor/
├── security_monitor/          # Main application package
│   ├── auth/                  # Authentication & authorization
│   │   ├── jwt_handler.py     # JWT token management
│   │   └── user_store.py      # User management
│   ├── core/                  # Core monitoring logic
│   │   ├── event_reader.py    # Windows event log reader
│   │   ├── monitor.py         # Main orchestration
│   │   ├── multi_target_monitor.py  # Multi-machine monitoring
│   │   └── remote_event_reader.py   # Remote WMI access
│   ├── dashboard/             # Web interface
│   │   ├── dashboard_secure.html    # Frontend UI
│   │   └── web_dashboard_secure.py  # FastAPI backend
│   ├── detectors/             # Threat detection algorithms
│   │   ├── base_detector.py   # Base detector class
│   │   ├── brute_force.py     # Brute force detection
│   │   ├── privilege_escalation.py
│   │   └── persistence.py
│   ├── notifications/         # Alert channels
│   │   ├── console_logger.py  # Console output
│   │   ├── email_sender.py    # Email alerts
│   │   ├── file_logger.py     # File-based logging
│   │   └── splunk_sender.py   # Splunk HEC integration
│   ├── storage/               # Data persistence
│   │   ├── mongodb_handler.py # MongoDB operations
│   │   ├── json_exporter.py   # JSON export
│   │   └── query_validator.py # NoSQL injection prevention
│   └── utils/                 # Utilities
│       ├── config.py          # Configuration management
│       ├── rate_limiter.py    # API rate limiting
│       └── secure_credentials.py  # Encrypted credential storage
├── config/                    # Configuration files
│   ├── settings.yaml
│   ├── targets.yaml
│   └── certs/                 # SSL/TLS certificates
├── scripts/                   # Helper scripts
│   ├── manage_users.py        # User management CLI
│   ├── migrate_credentials.py # Credential migration
│   └── test_startup.py        # Configuration testing
├── tests/                     # Test suite
├── docs/                      # Documentation
├── data/                      # Runtime data
├── logs/                      # Log files
├── main.py                    # Main entry point
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## 🔍 Detection Algorithms

### Brute Force Detection
Identifies multiple failed login attempts within a time window:

```python
# Configurable in config/settings.yaml
detection:
  brute_force_threshold: 5  # Failed attempts trigger alert
  alert_reset_interval_hours: 1
```

**Detection Logic:**
- Monitors Event ID 4625 (Failed Login)
- Groups by target computer
- Alerts when threshold exceeded
- Auto-resets tracking hourly

### Privilege Escalation Detection
Monitors unauthorized privilege assignments:

```python
# Event IDs monitored:
# 4672 - Special privileges assigned to new logon
# 4720 - User account created
# 4728 - Member added to security-enabled global group
```

### Persistence Detection
Identifies persistence mechanisms:

```python
# Event IDs monitored:
# 4698 - Scheduled task created
# 4688 - New process created (suspicious locations)
```

## 🌐 API & Dashboard

### Authentication
All dashboard endpoints require JWT authentication:

```http
POST /api/login
Content-Type: application/json

{
  "username": "admin",
  "password": "SecurePass123!"
}

Response:
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer"
}
```

### Key Endpoints

```http
GET /api/events          # Get recent security events
GET /api/alerts          # Get active alerts
GET /api/stats           # Get system statistics
GET /api/targets         # Get monitored targets
POST /api/monitor/start  # Start monitoring
POST /api/monitor/stop   # Stop monitoring
```

### WebSocket Real-time Updates
```javascript
const ws = new WebSocket('ws://localhost:5000/ws');
ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log('New alert:', alert);
};
```

## 📧 Alerting & Notifications

### Email Alerts
Automatic email notifications for high-severity alerts:

```yaml
# .env configuration
EMAIL_ENABLED=true
EMAIL_FROM=alerts@company.com
EMAIL_TO=security@company.com
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
```

### Splunk Integration
Send events and alerts to Splunk via HEC:

```yaml
SPLUNK_ENABLED=true
SPLUNK_HEC_URL=https://splunk.company.com:8088/services/collector
SPLUNK_HEC_TOKEN=your-hec-token
SPLUNK_INDEX=security
```

### File Logger
All alerts logged to `logs/alerts.log`:

```
[2026-01-14 12:30:15] [HIGH] Brute Force Attack Detected
  Computer: WORKSTATION-01
  Failed Attempts: 8
  Target Accounts: ['admin', 'root']
```

## 🔐 Security Features

### Implemented Security Controls

1. **Authentication & Authorization**
   - JWT-based authentication
   - Password hashing (bcrypt)
   - Role-based access control (RBAC)

2. **Input Validation**
   - Command injection prevention
   - NoSQL injection prevention
   - Path traversal protection

3. **Rate Limiting**
   - API endpoint rate limiting
   - Configurable limits per endpoint
   - IP-based tracking

4. **Secure Storage**
   - Encrypted credential storage (Fernet encryption)
   - Environment variable isolation
   - Secure key management

5. **Audit Logging**
   - All authentication attempts logged
   - User actions tracked
   - Alert history maintained

## 🛠️ Development

### Running Tests
```powershell
# Install test dependencies
pip install pytest pytest-asyncio

# Run all tests
pytest

# Run specific test file
pytest tests/test_security_fixes.py

# Run with coverage
pytest --cov=security_monitor
```

### Code Style
```powershell
# Install development tools
pip install black flake8 mypy

# Format code
black security_monitor/

# Check style
flake8 security_monitor/

# Type checking
mypy security_monitor/
```

### Adding New Detectors

1. Create detector in `security_monitor/detectors/`:
```python
from .base_detector import BaseDetector, Alert

class MyDetector(BaseDetector):
    def detect(self, events):
        alerts = []
        # Your detection logic
        return alerts
```

2. Register in `security_monitor/core/monitor.py`:
```python
from ..detectors import MyDetector

def _initialize_detectors(self):
    detectors.append(MyDetector())
```

3. Add configuration in `config/settings.yaml`:
```yaml
detectors:
  my_detector:
    enabled: true
    threshold: 10
```

## 🐛 Troubleshooting

### Common Issues

#### "Access Denied" when reading event logs
**Solution:** Run PowerShell/Command Prompt as Administrator

#### MongoDB connection failures
```powershell
# Check MongoDB service status
sc query MongoDB

# Start MongoDB service
net start MongoDB

# Verify connection
mongo --eval "db.adminCommand('ping')"
```

#### No events detected
**Solution:** Generate test events:
```powershell
# Failed login test
runas /user:FakeUser cmd

# View Security log
eventvwr.msc
```

#### Rate limiting errors (429)
**Solution:** Adjust rate limits in configuration or wait for rate limit window to reset

### Debug Mode
```powershell
# Enable debug logging
$env:LOG_LEVEL="DEBUG"
python main.py --mode single
```

### Testing Configuration
```powershell
# Test all components
python scripts/test_startup.py

# Verify user authentication
python scripts/manage_users.py
```

## 📚 Additional Resources

- **Documentation**: See `docs/analysis.md` for detailed system analysis
- **Architecture Diagrams**: Available in `assets/diagrams/`
- **Configuration Examples**: Check `config/` directory

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Contribution Guidelines
- Follow PEP 8 style guide
- Add tests for new features
- Update documentation
- Ensure all tests pass

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**hackmad**

## 🙏 Acknowledgments

- Microsoft Windows Event Log documentation
- MITRE ATT&CK Framework for threat detection patterns
- FastAPI framework for the web dashboard
- MongoDB for flexible data storage

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check the documentation in `docs/`
- Review existing issues and discussions

---

**⚠️ Security Notice**: This tool requires administrator privileges to access Windows Security Event Logs. Always follow your organization's security policies when deploying monitoring solutions.

**🔒 Privacy Notice**: This tool processes security event logs which may contain sensitive information. Ensure compliance with your organization's data protection policies.
