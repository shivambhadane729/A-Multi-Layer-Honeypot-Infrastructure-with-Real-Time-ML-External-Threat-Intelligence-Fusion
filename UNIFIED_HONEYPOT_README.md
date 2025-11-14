# 🍯 Unified Honeypot System - Complete Integration

A comprehensive honeypot system that combines multiple attack simulation services with centralized logging and analytics. This system implements the complete Phase 1-3 architecture with enhanced features and unified management.

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    UNIFIED HONEYPOT SYSTEM                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐ │
│  │  Fake Git Repo  │    │  Fake CI/CD     │    │ Consolidated│ │
│  │  (Port 8001)    │    │  Runner         │    │ Honeypot    │ │
│  │                 │    │  (Port 8002)    │    │ (Port 8000) │ │
│  │  • /repo/push   │    │  • /ci/run      │    │             │ │
│  │  • /repo/pull   │    │  • /ci/status   │    │ All Git &   │ │
│  │  • /.env        │    │  • /ci/creds    │    │ CI/CD       │ │
│  │  • /secrets.yml │    │  • /ci/logs     │    │ endpoints   │ │
│  └─────────┬───────┘    └─────────┬───────┘    └─────┬───────┘ │
│            │                      │                  │         │
│            └──────────────────────┼──────────────────┘         │
│                                   │                            │
│                    ┌──────────────▼──────────────┐             │
│                    │     Logging Server          │             │
│                    │     (Port 5000)             │             │
│                    │                             │             │
│                    │  • POST /log                │             │
│                    │  • GET /logs                │             │
│                    │  • GET /stats               │             │
│                    │  • GET /health              │             │
│                    │  • GeoIP Enrichment         │             │
│                    │  • SQLite Database          │             │
│                    └─────────────┬───────────────┘             │
│                                  │                             │
│                    ┌──────────────▼──────────────┐             │
│                    │     SQLite Database         │             │
│                    │     (honeypot.db)           │             │
│                    │                             │             │
│                    │  • Attack logs              │             │
│                    │  • Geographic data          │             │
│                    │  • Session tracking         │             │
│                    │  • Integrity hashes         │             │
│                    └─────────────────────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
HONEYPOT/
├── 🍯 Main Honeypot Services
│   ├── fake_git_repo.py              # Git repository honeypot
│   ├── fake_cicd_runner.py           # CI/CD runner honeypot
│   ├── logging_server.py             # Enhanced logging server
│   ├── start_honeypot.py             # Original startup script
│   └── test_client.py                # Original test client
│
├── 🍯 Phase 2: Consolidated Services
│   └── Honeypot/
│       ├── honeypot_services.py      # Combined Git & CI/CD service
│       ├── test_honeypot.py          # Service-specific tests
│       ├── start_honeypot.py         # Service startup script
│       ├── static/                   # Deceptive static files
│       │   ├── secrets.yml          # Fake secrets
│       │   ├── env_file             # Fake environment variables
│       │   ├── README.md            # Fake project documentation
│       │   └── config.json          # Fake configuration
│       └── README.md                # Phase 2 documentation
│
├── 📊 Phase 3: Logging System
│   └── logging_server/
│       ├── logging_server.py         # Enhanced logging server
│       ├── send_test_log.py          # Logging server tests
│       ├── start_logging_server.py   # Logging server startup
│       └── README.md                 # Phase 3 documentation
│
├── 🚀 Unified System
│   ├── start_unified_honeypot.py     # Unified startup script
│   ├── test_integration.py           # Complete integration tests
│   └── UNIFIED_HONEYPOT_README.md    # This file
│
└── 📋 Documentation & Config
    ├── HONEYPOT_README.md            # Original documentation
    ├── requirements.txt              # Python dependencies
    └── honeypot.db                   # SQLite database (auto-created)
```

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Unified System
```bash
python start_unified_honeypot.py
```

### 3. Run Integration Tests
```bash
python test_integration.py
```

## 🌐 Available Services

### 📊 Logging Server (Port 5000)
**Centralized logging and analytics system**

- `POST /log` - Ingest attack logs from honeypot services
- `GET /logs` - Retrieve stored logs with filtering and pagination
- `GET /stats` - Get comprehensive statistics and analytics
- `GET /health` - Health check and system status

**Features:**
- GeoIP enrichment using ipapi.co
- SQLite database with comprehensive schema
- SHA256 integrity hashing
- Real-time analytics and statistics

### 🍯 Fake Git Repository (Port 8001)
**Simulates a Git repository with sensitive files**

- `GET /` - Repository information page
- `POST /repo/push` - Simulate Git push operations
- `POST /repo/pull` - Simulate Git pull operations
- `GET /.env` - Access fake environment file
- `GET /secrets.yml` - Access fake secrets file
- `GET /config.json` - Access fake configuration file
- `GET /robots.txt` - Access robots.txt file

### 🚀 Fake CI/CD Runner (Port 8002)
**Simulates a CI/CD system with credentials**

- `GET /` - CI/CD dashboard
- `POST /ci/run` - Execute CI/CD jobs
- `GET /ci/status` - Check job status
- `GET /ci/logs/<job_id>` - View job execution logs
- `GET /ci/config` - View CI/CD configuration
- `GET /ci/credentials` - Access fake credentials
- `GET /ci/jobs` - List recent jobs
- `POST /ci/webhook` - Webhook endpoint

### 🍯 Consolidated Honeypot (Port 8000)
**Combined Git and CI/CD services in one**

- `GET /` - Service information
- `GET /health` - Health check
- All Git repository endpoints
- All CI/CD runner endpoints
- Static file serving

## 📊 Data Collection & Analytics

### Attack Data Captured
- **Source IP addresses** with geographic enrichment
- **User agent strings** and request headers
- **Attack payloads** and file access attempts
- **Session tracking** with unique identifiers
- **Timestamps** and action types
- **Target files** and services accessed

### Geographic Enrichment
- **Country, city, region** information
- **ISP and organization** details
- **Timezone** and location data
- **Private network** detection

### Analytics Available
- **Total attack count** and unique attackers
- **Geographic distribution** of attacks
- **Most common attack types** and patterns
- **Service targeting** statistics
- **Recent activity** (24-hour trends)
- **Session analysis** and tracking

## 🧪 Testing & Validation

### Integration Test Suite
The `test_integration.py` script provides comprehensive testing:

```bash
python test_integration.py
```

**Test Coverage:**
- ✅ Service connectivity and health checks
- ✅ Logging server functionality
- ✅ Git repository attack simulations
- ✅ CI/CD runner attack simulations
- ✅ Consolidated honeypot testing
- ✅ Log integration and storage
- ✅ Error handling and edge cases

### Individual Service Tests
```bash
# Test logging server
cd logging_server
python send_test_log.py

# Test consolidated honeypot
cd Honeypot
python test_honeypot.py

# Test original services
python test_client.py
```

## 🔧 Configuration

### Network Configuration
- **Logging Server**: `http://192.168.1.2:5000` (Internal network)
- **Git Repository**: `http://localhost:8001`
- **CI/CD Runner**: `http://localhost:8002`
- **Consolidated**: `http://localhost:8000`

### Database Configuration
- **SQLite Database**: `honeypot.db` (auto-created)
- **Log Storage**: Comprehensive schema with indexes
- **Integrity**: SHA256 hashing for log verification

### GeoIP Configuration
- **Service**: ipapi.co (free tier)
- **Fallback**: Graceful handling of lookup failures
- **Private IPs**: Special handling for local networks

## 🛡️ Security Features

### Data Protection
- **Integrity Hashing**: SHA256 hashes prevent log tampering
- **Input Validation**: Comprehensive data validation
- **Error Handling**: Graceful failure handling
- **Session Tracking**: Unique session identifiers

### Attack Simulation
- **Realistic Responses**: Services behave like real systems
- **Deceptive Content**: Fake credentials and sensitive files
- **Error Simulation**: Proper HTTP status codes
- **Session Management**: Persistent attacker tracking

### Monitoring & Alerting
- **Health Checks**: Automated service monitoring
- **Log Aggregation**: Centralized log collection
- **Statistics**: Real-time analytics
- **Error Tracking**: Comprehensive error logging

## 📈 Usage Examples

### Start the Complete System
```bash
# Start all services with unified manager
python start_unified_honeypot.py

# Or start individual services
python logging_server.py &
python fake_git_repo.py &
python fake_cicd_runner.py &
python Honeypot/honeypot_services.py &
```

### Test Attack Scenarios
```bash
# Test Git push attack
curl -X POST http://localhost:8001/repo/push \
     -H "Content-Type: application/json" \
     -d '{"commit_message": "Add backdoor", "branch": "main"}'

# Test CI/CD job execution
curl -X POST http://localhost:8002/ci/run \
     -H "Content-Type: application/json" \
     -d '{"job_name": "malicious-deploy", "environment": "production"}'

# Access fake credentials
curl http://localhost:8002/ci/credentials
```

### View Analytics
```bash
# Get statistics
curl http://localhost:5000/stats

# Retrieve logs
curl http://localhost:5000/logs

# Health check
curl http://localhost:5000/health
```

## 🔍 Monitoring & Analytics

### Real-time Statistics
Access comprehensive analytics at `http://localhost:5000/stats`:

```json
{
  "total_logs": 150,
  "unique_ips": 25,
  "unique_sessions": 30,
  "recent_logs_24h": 45,
  "top_countries": [
    {"country": "United States", "count": 45},
    {"country": "China", "count": 32},
    {"country": "Russia", "count": 28}
  ],
  "top_actions": [
    {"action": "file_access", "count": 67},
    {"action": "git_push", "count": 34},
    {"action": "ci_job_run", "count": 23}
  ]
}
```

### Log Retrieval
Filter and paginate logs at `http://localhost:5000/logs`:

```bash
# Get all logs
curl "http://localhost:5000/logs"

# Filter by source IP
curl "http://localhost:5000/logs?source_ip=203.0.113.42"

# Filter by action type
curl "http://localhost:5000/logs?action=file_access"

# Paginate results
curl "http://localhost:5000/logs?page=2&per_page=25"
```

## 🚨 Production Considerations

### Security
- **Network Isolation**: Run on isolated network segments
- **Firewall Rules**: Implement proper access controls
- **Authentication**: Add API authentication for production
- **Encryption**: Encrypt sensitive data at rest

### Performance
- **Database**: Consider PostgreSQL for high volume
- **Caching**: Implement Redis for frequently accessed data
- **Load Balancing**: Multiple service instances
- **Rate Limiting**: Prevent log flooding

### Monitoring
- **Health Checks**: Automated service monitoring
- **Alerting**: Notifications for high-risk attacks
- **Backup**: Regular database backups
- **Log Rotation**: Manage log file sizes

## 🔧 Troubleshooting

### Common Issues

**Services won't start:**
- Check if ports are available
- Ensure all dependencies are installed
- Check firewall settings
- Review error logs

**Logging server connection fails:**
- Verify logging server is running
- Check network connectivity
- Review firewall rules
- Check service logs

**Tests fail:**
- Ensure all services are running
- Check port availability
- Verify dependencies
- Review error messages

### Debug Commands
```bash
# Check service health
curl http://localhost:5000/health
curl http://localhost:8001/
curl http://localhost:8002/
curl http://localhost:8000/health

# View logs
tail -f logging_server.log

# Check database
sqlite3 honeypot.db "SELECT COUNT(*) FROM logs;"

# Test connectivity
python test_integration.py
```

## 📚 Integration with Network Architecture

### Phase 1 Network Setup
This unified system integrates with the Phase 1 network architecture:

- **External Zone**: 10.0.0.0/24 (Attacker PC)
- **DMZ Zone**: 172.16.0.0/24 (Honeypot Services)
- **Internal Zone**: 192.168.1.0/24 (Logging Server)

### Service Deployment
- **DMZ Servers**: Deploy honeypot services on 172.16.0.2 and 172.16.0.3
- **Internal Server**: Deploy logging server on 192.168.1.2
- **Router ACLs**: Configure access control lists as specified

## 🎯 System Capabilities

### Attack Detection
- **File Access Attempts**: Monitor access to sensitive files
- **Git Operations**: Track push/pull attempts
- **CI/CD Exploitation**: Detect job execution attempts
- **Credential Theft**: Monitor credential access attempts

### Data Enrichment
- **Geographic Data**: IP address location information
- **Session Tracking**: Persistent attacker identification
- **Payload Analysis**: Detailed attack payload capture
- **Header Analysis**: Request header examination

### Analytics & Reporting
- **Real-time Statistics**: Live attack metrics
- **Geographic Mapping**: Attack origin visualization
- **Trend Analysis**: Attack pattern identification
- **Threat Intelligence**: Actionable security insights

## ⚠️ Legal Notice

This honeypot system is for educational and research purposes only. Users are responsible for:
- Complying with local laws and regulations
- Obtaining proper authorization for deployment
- Using in controlled, authorized environments
- Protecting collected data appropriately

## 🤝 Contributing

This is a security research project. Please:
- Use responsibly and ethically
- Follow security best practices
- Report security issues privately
- Contribute improvements and enhancements

## 📞 Support

For questions or issues:
- Check the troubleshooting section
- Review service logs and error messages
- Run the integration test suite
- Ensure all dependencies are installed
- Verify network connectivity and port availability

---

**Happy Honeypot Hunting! 🍯🔍**

*This unified system provides a complete, production-ready honeypot solution with comprehensive logging, analytics, and monitoring capabilities.*
