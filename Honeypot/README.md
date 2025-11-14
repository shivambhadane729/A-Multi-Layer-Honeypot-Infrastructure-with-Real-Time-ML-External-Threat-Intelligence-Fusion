# 🍯 Honeypot Services - Phase 2 Implementation

This directory contains the consolidated honeypot services as specified in Phase 2 of the project creation guide.

## 📁 Directory Structure

```
Honeypot/
├── honeypot_services.py      # Main consolidated honeypot service
├── test_honeypot.py          # Test suite for all endpoints
├── start_honeypot.py         # Startup script
├── requirements.txt          # Python dependencies
├── static/                   # Deceptive static files
│   ├── secrets.yml          # Fake secrets file
│   ├── env_file             # Fake environment variables
│   ├── README.md            # Fake project documentation
│   └── config.json          # Fake configuration file
└── README.md                # This file
```

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Honeypot Service
```bash
python start_honeypot.py
```

Or directly:
```bash
python honeypot_services.py
```

### 3. Test the Service
```bash
python test_honeypot.py
```

## 🌐 Available Endpoints

### Git Repository Endpoints
- `POST /repo/push` - Simulate Git push operation
- `POST /repo/pull` - Simulate Git pull operation
- `GET /.env` - Access fake environment file
- `GET /secrets.yml` - Access fake secrets file
- `GET /config.json` - Access fake configuration file

### CI/CD Runner Endpoints
- `POST /ci/run` - Execute CI/CD job
- `GET /ci/status` - Check job status
- `GET /ci/logs/<job_id>` - View job logs
- `GET /ci/credentials` - Access fake credentials
- `GET /ci/config` - View CI/CD configuration

### System Endpoints
- `GET /health` - Health check
- `GET /` - Service information
- `GET /static/<filename>` - Serve static files

## 🔍 Testing

The test suite (`test_honeypot.py`) validates all endpoints:

```bash
python test_honeypot.py
```

Expected output:
```
🍯 Honeypot Services Test Suite
==================================================
✅ Honeypot service is running

🔍 Testing Git Repository Endpoints...
✅ GET / - Status: 200
✅ GET /health - Status: 200
✅ POST /repo/push - Status: 200
✅ POST /repo/pull - Status: 200
✅ GET /.env - Status: 200
✅ GET /secrets.yml - Status: 200
✅ GET /config.json - Status: 200
📊 Git Endpoints: 7/7 passed

🔍 Testing CI/CD Runner Endpoints...
✅ POST /ci/run - Status: 200
✅ GET /ci/status - Status: 200
✅ GET /ci/logs/job_123456 - Status: 200
✅ GET /ci/credentials - Status: 200
✅ GET /ci/config - Status: 200
📊 CI/CD Endpoints: 5/5 passed

🔍 Testing Static File Serving...
✅ GET /static/secrets.yml - Status: 200
✅ GET /static/env_file - Status: 200
✅ GET /static/README.md - Status: 200
✅ GET /static/config.json - Status: 200
📊 Static Files: 4/4 passed

🔍 Testing Error Handling...
✅ GET /nonexistent - Status: 404
✅ GET /static/nonexistent.txt - Status: 404
📊 Error Handling: 2/2 passed

==================================================
🎉 All tests passed! Honeypot services are working correctly.
```

## 📊 Data Collection

The honeypot service captures and logs:

- **Source IP address** of attackers
- **User agent** information
- **Request headers** and payloads
- **Target files** accessed
- **Actions performed** (git push, file access, etc.)
- **Session tracking** with unique IDs
- **Geographic data** (enriched by logging server)

### Log Format
```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "source_ip": "203.0.113.42",
  "geo_country": "Unknown",
  "geo_city": "Unknown",
  "protocol": "HTTP",
  "target_service": "Consolidated Honeypot Services",
  "action": "git_push",
  "target_file": null,
  "payload": {
    "commit_message": "Test commit",
    "branch": "main"
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

## 🔧 Configuration

### Logging Server
The honeypot is configured to send logs to:
```
http://192.168.1.2:5000/log
```

This matches the internal logging server IP from Phase 1 network setup.

### Service Port
The honeypot runs on port 8000 and is accessible from the network:
```
http://0.0.0.0:8000
```

## 🛡️ Security Features

### Attack Detection
- **Session Tracking** - Each attacker gets a unique session ID
- **Integrity Checking** - Each log entry has a SHA256 hash
- **Payload Capture** - Full request data is captured and stored
- **Error Handling** - Proper HTTP status codes and error messages

### Honeypot Lures
- **Fake Credentials** - Realistic-looking API keys and passwords
- **Sensitive Files** - .env, secrets.yml, config files
- **Realistic Responses** - Services respond like real systems
- **Deceptive Documentation** - Fake README and project files

## 📝 Example Usage

### Test Git Push
```bash
curl -X POST http://localhost:8000/repo/push \
     -H "Content-Type: application/json" \
     -d '{"commit_message": "Test commit", "branch": "main"}'
```

### Test CI Job
```bash
curl -X POST http://localhost:8000/ci/run \
     -H "Content-Type: application/json" \
     -d '{"job_name": "test-build", "environment": "production"}'
```

### Access Fake Files
```bash
curl http://localhost:8000/.env
curl http://localhost:8000/secrets.yml
curl http://localhost:8000/static/README.md
```

## 🚨 Production Considerations

### Security
- Run on isolated network segments
- Use proper firewall rules
- Monitor for data exfiltration attempts
- Regular security updates

### Performance
- Use production WSGI server (gunicorn) for production
- Implement rate limiting
- Monitor resource usage
- Add database connection pooling

### Monitoring
- Set up log aggregation
- Implement alerting for high-risk attacks
- Regular database backups
- Performance monitoring

## 🔍 Troubleshooting

### Common Issues

**Service won't start:**
- Check if port 8000 is available
- Ensure Flask is installed: `pip install Flask`
- Check firewall settings

**Logging server connection fails:**
- Verify logging server is running on 192.168.1.2:5000
- Check network connectivity
- Review firewall rules

**Tests fail:**
- Ensure honeypot service is running
- Check if all dependencies are installed
- Verify port 8000 is accessible

### Logs
- Check console output for error messages
- Use health check endpoint: `GET /health`
- Review test output for specific failures

## 📚 Next Steps

This completes Phase 2 of the honeypot project. The next phases would include:

- **Phase 3**: Network integration and testing
- **Phase 4**: Advanced logging and analytics
- **Phase 5**: Machine learning integration
- **Phase 6**: Production deployment

## ⚠️ Legal Notice

This honeypot system is for educational and research purposes only. Users are responsible for:
- Complying with local laws
- Obtaining proper authorization
- Using in controlled environments
- Protecting collected data

---

**Happy Honeypot Hunting! 🍯🔍**
