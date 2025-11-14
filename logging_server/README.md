# 📊 Honeypot Logging Server - Phase 3 Implementation

This directory contains the centralized logging server for the honeypot system as specified in Phase 3 of the project creation guide.

## 📁 Directory Structure

```
logging_server/
├── logging_server.py         # Main logging server application
├── send_test_log.py          # Test client for validation
├── start_logging_server.py   # Startup script
├── requirements.txt          # Python dependencies
├── README.md                # This file
├── honeypot.db              # SQLite database (created automatically)
├── logging_server.log       # Application logs (created automatically)
└── venv/                    # Virtual environment
```

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Logging Server
```bash
python start_logging_server.py
```

Or directly:
```bash
python logging_server.py
```

### 3. Test the Server
```bash
python send_test_log.py
```

## 🌐 Available Endpoints

### Log Ingestion
- `POST /log` - Receive and process honeypot logs

### Log Retrieval
- `GET /logs` - Retrieve stored logs with optional filtering
- `GET /stats` - Get statistics and analytics
- `GET /health` - Health check and status

### System Information
- `GET /` - Service information and endpoint documentation

## 📊 Data Processing Features

### 1. Log Ingestion (`POST /log`)
- **JSON Payload Processing**: Accepts structured log data from honeypot services
- **Validation**: Validates required fields (source_ip, action, target_service, session_id)
- **GeoIP Enrichment**: Automatically enriches IP addresses with geographic data
- **Integrity Checking**: Calculates SHA256 hash for log integrity
- **Database Storage**: Stores enriched logs in SQLite database

### 2. GeoIP Enrichment
- **External IPs**: Uses ipapi.co for geographic lookup
- **Private IPs**: Handles local/private networks appropriately
- **Fallback**: Graceful handling of lookup failures
- **Data Fields**: Country, city, region, coordinates, timezone, ISP, organization

### 3. Database Schema
```sql
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    geo_country TEXT,
    geo_city TEXT,
    geo_region TEXT,
    geo_latitude REAL,
    geo_longitude REAL,
    geo_timezone TEXT,
    geo_isp TEXT,
    geo_org TEXT,
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

### 4. Log Retrieval (`GET /logs`)
- **Filtering**: Filter by source_ip, action, target_service
- **Pagination**: Limit and offset parameters
- **Sorting**: Ordered by creation time (newest first)
- **JSON Parsing**: Automatically parses stored JSON fields

### 5. Statistics (`GET /stats`)
- **Total Logs**: Count of all stored logs
- **Unique IPs**: Number of unique source IP addresses
- **Geographic Distribution**: Top countries by attack count
- **Attack Types**: Most common attack actions
- **Service Targets**: Most targeted services
- **Recent Activity**: Activity in the last 24 hours

## 🔍 Testing

The test suite (`send_test_log.py`) validates all functionality:

```bash
python send_test_log.py
```

Expected output:
```
📊 Logging Server Test Suite
==================================================
✅ Logging server is running
   Status: healthy
   Total logs: 0

🔍 Testing Git Repository Attack...
✅ Log sent successfully: git_push from 203.0.113.42
   Response: Log received and stored

🔍 Testing CI/CD Runner Attack...
✅ Log sent successfully: ci_job_run from 198.51.100.15
   Response: Log received and stored

🔍 Testing File Access Attack...
✅ Log sent successfully: file_access from 192.0.2.100
   Response: Log received and stored

🔍 Testing Credentials Access Attack...
✅ Log sent successfully: file_access from 203.0.113.200
   Response: Log received and stored

🔍 Testing Private IP Address...
✅ Log sent successfully: git_pull from 192.168.1.100
   Response: Log received and stored

🔍 Testing Log Retrieval...
✅ Retrieved 5 logs

🔍 Testing Statistics...
✅ Statistics retrieved:
   Total logs: 5
   Unique IPs: 5
   Recent activity (24h): 5

==================================================
🎉 All tests passed! Logging server is working correctly.
```

## 📝 Example Usage

### Send a Test Log
```bash
curl -X POST http://localhost:5000/log \
     -H "Content-Type: application/json" \
     -d '{
       "timestamp": "2024-01-15T10:30:00.000Z",
       "source_ip": "203.0.113.42",
       "protocol": "HTTP",
       "target_service": "Fake Git Repository",
       "action": "git_push",
       "payload": {"commit_message": "Test commit", "branch": "main"},
       "session_id": "550e8400-e29b-41d4-a716-446655440000",
       "user_agent": "git/2.34.1"
     }'
```

### Retrieve Logs
```bash
# Get all logs
curl "http://localhost:5000/logs"

# Filter by source IP
curl "http://localhost:5000/logs?source_ip=203.0.113.42"

# Filter by action
curl "http://localhost:5000/logs?action=git_push"

# Get statistics
curl "http://localhost:5000/stats"

# Health check
curl "http://localhost:5000/health"
```

## 🗄️ Database Management

### Database File
- **Location**: `honeypot.db` (SQLite database)
- **Auto-creation**: Created automatically on first run
- **Backup**: Regular backups recommended for production

### Query Examples
```sql
-- Get all logs
SELECT * FROM logs ORDER BY created_at DESC;

-- Get logs by country
SELECT * FROM logs WHERE geo_country = 'United States';

-- Get recent attacks
SELECT * FROM logs WHERE created_at >= datetime('now', '-1 day');

-- Get unique IPs
SELECT DISTINCT source_ip, geo_country, COUNT(*) as attack_count 
FROM logs 
GROUP BY source_ip 
ORDER BY attack_count DESC;
```

## 🔧 Configuration

### Environment Variables
- **Database**: SQLite file location (default: `honeypot.db`)
- **Log Level**: Logging verbosity (default: INFO)
- **GeoIP Service**: ipapi.co (configurable)

### Network Configuration
- **Host**: 0.0.0.0 (accessible from network)
- **Port**: 5000 (matches Phase 1 network setup)
- **Internal IP**: 192.168.1.2 (as specified in Phase 1)

## 🛡️ Security Features

### Data Integrity
- **SHA256 Hashing**: Each log entry has integrity hash
- **Duplicate Prevention**: Hash-based duplicate detection
- **Input Validation**: Validates required fields and data types

### Error Handling
- **Graceful Failures**: Continues operation on individual log failures
- **Comprehensive Logging**: Detailed error logging for debugging
- **Health Monitoring**: Health check endpoint for monitoring

### Privacy Considerations
- **IP Anonymization**: Consider implementing for production
- **Data Retention**: Implement retention policies as needed
- **Access Control**: Add authentication for production use

## 📈 Monitoring & Analytics

### Key Metrics
- **Attack Volume**: Total number of attacks
- **Geographic Distribution**: Where attacks originate
- **Attack Types**: Most common attack patterns
- **Service Targeting**: Which services are most targeted
- **Temporal Patterns**: Attack timing and frequency

### Dashboard Integration
The logging server provides data for:
- Real-time attack monitoring
- Geographic threat mapping
- Attack pattern analysis
- Service health monitoring
- Incident response

## 🚨 Production Considerations

### Performance
- **Database Optimization**: Consider PostgreSQL for high volume
- **Caching**: Implement Redis for frequently accessed data
- **Load Balancing**: Multiple logging server instances
- **Rate Limiting**: Prevent log flooding

### Security
- **Authentication**: Add API key or OAuth authentication
- **Encryption**: Encrypt sensitive data at rest
- **Network Security**: Use HTTPS and proper firewall rules
- **Access Control**: Implement role-based access control

### Monitoring
- **Health Checks**: Automated monitoring of service health
- **Alerting**: Notifications for high-risk attacks
- **Backup**: Regular database backups
- **Log Rotation**: Manage log file sizes

## 🔍 Troubleshooting

### Common Issues

**Server won't start:**
- Check if port 5000 is available
- Ensure all dependencies are installed
- Check database file permissions

**GeoIP lookup fails:**
- Check internet connectivity
- Verify ipapi.co service availability
- Review firewall rules for outbound requests

**Database errors:**
- Ensure write permissions in directory
- Check SQLite installation
- Verify database file integrity

**Test failures:**
- Ensure logging server is running
- Check network connectivity
- Review error logs for details

### Logs
- **Application Logs**: `logging_server.log`
- **Database**: SQLite database for stored logs
- **Health Check**: `GET /health` endpoint
- **Console Output**: Real-time status information

## 📚 Integration with Honeypot Services

### Honeypot Configuration
Update honeypot services to send logs to:
```
http://192.168.1.2:5000/log
```

### Log Format
The logging server expects logs in this format:
```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "source_ip": "203.0.113.42",
  "protocol": "HTTP",
  "target_service": "Fake Git Repository",
  "action": "git_push",
  "target_file": null,
  "payload": {
    "commit_message": "Test commit",
    "branch": "main"
  },
  "headers": {
    "User-Agent": "git/2.34.1"
  },
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_agent": "git/2.34.1"
}
```

## 📚 Next Steps

This completes Phase 3 of the honeypot project. The next phases would include:

- **Phase 4**: Network integration and testing
- **Phase 5**: Advanced analytics and machine learning
- **Phase 6**: Production deployment and monitoring
- **Phase 7**: Dashboard and visualization

## ⚠️ Legal Notice

This logging server is for educational and research purposes only. Users are responsible for:
- Complying with local laws
- Obtaining proper authorization
- Using in controlled environments
- Protecting collected data

---

**Happy Logging! 📊🔍**
