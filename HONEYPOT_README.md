# 🍯 Honeypot Security System

A comprehensive honeypot system designed to detect, log, and analyze cyber attacks targeting common development infrastructure.

## 🎯 Project Overview

This honeypot system simulates two high-value targets that attackers frequently target:
- **Fake Git Repository** - Simulates a Git server with sensitive files
- **Fake CI/CD Runner** - Simulates a continuous integration system

All attack data is captured, enriched with geographic information, and stored in a centralized logging system.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Fake Git Repo  │    │  Fake CI/CD     │    │  Logging Server │
│  (Port 8001)    │    │  Runner         │    │  (Port 5000)    │
│                 │    │  (Port 8002)    │    │                 │
│  • /repo/push   │    │  • /ci/run      │    │  • POST /log    │
│  • /repo/pull   │    │  • /ci/status   │    │  • GET /logs    │
│  • /.env        │    │  • /ci/creds    │    │  • GET /stats   │
│  • /secrets.yml │    │  • /ci/logs     │    │  • GET /health  │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼─────────────┐
                    │     SQLite Database       │
                    │     (honeypot.db)         │
                    │                           │
                    │  • Attack logs            │
                    │  • Geographic data        │
                    │  • Session tracking       │
                    │  • Integrity hashes       │
                    └───────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.7+
- pip (Python package manager)

### Installation

1. **Clone or download the honeypot files**
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the honeypot system:**
   ```bash
   python start_honeypot.py
   ```

4. **Test the system:**
   ```bash
   python test_client.py
   ```

## 📁 File Structure

```
honeypot/
├── fake_git_repo.py          # Fake Git Repository service
├── fake_cicd_runner.py       # Fake CI/CD Runner service  
├── logging_server.py         # Centralized logging server
├── test_client.py            # Test client for validation
├── start_honeypot.py         # System startup script
├── requirements.txt          # Python dependencies
├── honeypot.db              # SQLite database (created automatically)
└── HONEYPOT_README.md       # This file
```

## 🔧 Individual Service Usage

### 1. Logging Server (Port 5000)
```bash
python logging_server.py
```

**Endpoints:**
- `POST /log` - Ingest attack logs
- `GET /logs` - Retrieve stored logs (with pagination)
- `GET /stats` - Get honeypot statistics
- `GET /health` - Health check

### 2. Fake Git Repository (Port 8001)
```bash
python fake_git_repo.py
```

**Endpoints:**
- `POST /repo/push` - Simulate Git push
- `POST /repo/pull` - Simulate Git pull
- `GET /.env` - Access fake environment file
- `GET /secrets.yml` - Access fake secrets file
- `GET /config.json` - Access fake config file

### 3. Fake CI/CD Runner (Port 8002)
```bash
python fake_cicd_runner.py
```

**Endpoints:**
- `POST /ci/run` - Execute CI/CD job
- `GET /ci/status` - Check job status
- `GET /ci/logs/<job_id>` - View job logs
- `GET /ci/credentials` - Access fake credentials
- `GET /ci/config` - View configuration

## 📊 Data Collection

### Log Entry Structure
```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "source_ip": "203.0.113.42",
  "geo_country": "United States",
  "geo_city": "New York",
  "protocol": "HTTP",
  "target_service": "Fake Git Repository",
  "action": "git_push",
  "target_file": null,
  "payload": {
    "commit_message": "Add new feature",
    "branch": "main",
    "files_changed": ["src/app.py"]
  },
  "headers": {
    "User-Agent": "curl/7.68.0",
    "Content-Type": "application/json"
  },
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_agent": "curl/7.68.0",
  "log_hash": "sha256_hash_for_integrity"
}
```

### Database Schema
```sql
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    geo_country TEXT,
    geo_city TEXT,
    protocol TEXT NOT NULL,
    target_service TEXT NOT NULL,
    action TEXT NOT NULL,
    target_file TEXT,
    headers TEXT,
    payload TEXT,
    session_id TEXT NOT NULL,
    user_agent TEXT,
    log_hash TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## 🛡️ Security Features

### Attack Detection
- **Session Tracking** - Each attacker gets a unique session ID
- **Geographic Enrichment** - IP addresses are enriched with location data
- **Integrity Checking** - Each log entry has a SHA256 hash
- **Payload Capture** - Full request data is captured and stored

### Honeypot Lures
- **Fake Credentials** - Realistic-looking API keys and passwords
- **Sensitive Files** - .env, secrets.yml, config files
- **Realistic Responses** - Services respond like real systems
- **Error Handling** - Proper HTTP status codes and error messages

## 📈 Monitoring & Analytics

### Statistics Available
- Total attack count
- Unique attacker IPs
- Geographic distribution
- Most common attack types
- Recent activity (24h)

### Query Examples
```bash
# Get all logs
curl "http://localhost:5000/logs"

# Get logs from specific IP
curl "http://localhost:5000/logs?source_ip=203.0.113.42"

# Get logs by action type
curl "http://localhost:5000/logs?action=git_push"

# Get statistics
curl "http://localhost:5000/stats"
```

## 🔍 Testing

### Manual Testing
1. **Access the honeypot services:**
   - Visit http://localhost:8001 (Git Repository)
   - Visit http://localhost:8002 (CI/CD Runner)

2. **Try the endpoints:**
   ```bash
   # Test Git push
   curl -X POST http://localhost:8001/repo/push \
        -H "Content-Type: application/json" \
        -d '{"commit_message": "Test commit", "branch": "main"}'
   
   # Test CI job
   curl -X POST http://localhost:8002/ci/run \
        -H "Content-Type: application/json" \
        -d '{"job_name": "test-build", "environment": "production"}'
   
   # Access fake files
   curl http://localhost:8001/.env
   curl http://localhost:8002/ci/credentials
   ```

### Automated Testing
```bash
python test_client.py
```

## 🚨 Production Considerations

### Security
- Run on isolated network segments
- Use proper firewall rules
- Monitor for data exfiltration attempts
- Regular security updates

### Performance
- Use production WSGI server (gunicorn)
- Implement rate limiting
- Add database connection pooling
- Monitor resource usage

### Monitoring
- Set up log aggregation
- Implement alerting for high-risk attacks
- Regular database backups
- Performance monitoring

## 🛠️ Troubleshooting

### Common Issues

**Services won't start:**
- Check if ports are available
- Ensure Python dependencies are installed
- Check firewall settings

**Database errors:**
- Ensure write permissions in directory
- Check SQLite installation
- Verify database file permissions

**GeoIP lookup fails:**
- Check internet connectivity
- Verify ipapi.co API availability
- Check firewall rules for outbound requests

### Logs
- Check console output for error messages
- Review SQLite database for stored logs
- Use health check endpoint: `GET /health`

## 📚 Next Steps

### Phase 4: Machine Learning Integration
- Implement anomaly detection
- Add threat scoring
- Create alerting system

### Phase 5: Advanced Analytics
- Attack pattern analysis
- Geographic threat mapping
- Integration with SIEM systems

## 🤝 Contributing

This is a security research project. Please:
- Use responsibly
- Follow ethical guidelines
- Report security issues privately
- Contribute improvements

## ⚠️ Legal Notice

This honeypot system is for educational and research purposes only. Users are responsible for:
- Complying with local laws
- Obtaining proper authorization
- Using in controlled environments
- Protecting collected data

## 📞 Support

For questions or issues:
- Check the troubleshooting section
- Review the code comments
- Test with the provided test client
- Ensure all dependencies are installed

---

**Happy Honeypot Hunting! 🍯🔍**
