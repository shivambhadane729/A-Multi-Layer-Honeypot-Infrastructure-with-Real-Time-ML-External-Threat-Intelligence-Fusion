#!/usr/bin/env python3
"""
Logging Server - Phase 3 Implementation
Centralized logging system for honeypot events with GeoIP enrichment
"""

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import sqlite3
import hashlib
import json
import datetime
import logging
import requests
import os
import time
from typing import Dict, Any, Optional

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# Configuration
# Database file path - use absolute path to avoid issues
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(BASE_DIR)

# Check for database in parent directory (root) first, then current directory
if os.path.exists(os.path.join(PARENT_DIR, "honeypot.db")):
    DATABASE_FILE = os.path.join(PARENT_DIR, "honeypot.db")
elif os.path.exists(os.path.join(BASE_DIR, "honeypot.db")):
    DATABASE_FILE = os.path.join(BASE_DIR, "honeypot.db")
else:
    # Create in parent directory (root) by default
    DATABASE_FILE = os.path.join(PARENT_DIR, "honeypot.db")

LOG_LEVEL = logging.INFO

# Set up logging
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logging_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def init_database():
    """Initialize the SQLite database with the logs table"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Create logs table with comprehensive schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
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
                ml_score REAL,
                ml_risk_level TEXT,
                is_anomaly INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Add ML columns if they don't exist (for existing databases)
        try:
            cursor.execute('ALTER TABLE logs ADD COLUMN ml_score REAL')
        except sqlite3.OperationalError:
            pass  # Column already exists
        try:
            cursor.execute('ALTER TABLE logs ADD COLUMN ml_risk_level TEXT')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE logs ADD COLUMN is_anomaly INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        
        # Create indexes for better query performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON logs(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_action ON logs(action)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_target_service ON logs(target_service)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ml_score ON logs(ml_score)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_is_anomaly ON logs(is_anomaly)')
        
        conn.commit()
        conn.close()
        
        logger.info(f"Database initialized: {DATABASE_FILE}")
        return True
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False

def get_geoip_data(ip_address: str) -> Dict[str, Any]:
    """
    Get GeoIP data for an IP address using ipapi.co
    Returns enriched geographic information
    """
    try:
        # Skip GeoIP lookup for private/local IPs
        if ip_address.startswith(('127.', '192.168.', '10.', '172.')):
            return {
                'country': 'Private Network',
                'city': 'Local',
                'region': 'Private',
                'latitude': None,
                'longitude': None,
                'timezone': 'Local',
                'isp': 'Private',
                'org': 'Private Network'
            }
        
        # Use ipapi.co for GeoIP lookup
        url = f"https://ipapi.co/{ip_address}/json/"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            geo_data = response.json()
            
            return {
                'country': geo_data.get('country_name', 'Unknown'),
                'city': geo_data.get('city', 'Unknown'),
                'region': geo_data.get('region', 'Unknown'),
                'latitude': geo_data.get('latitude'),
                'longitude': geo_data.get('longitude'),
                'timezone': geo_data.get('timezone', 'Unknown'),
                'isp': geo_data.get('org', 'Unknown'),
                'org': geo_data.get('org', 'Unknown')
            }
        else:
            logger.warning(f"GeoIP lookup failed for {ip_address}: {response.status_code}")
            return get_default_geoip_data()
            
    except requests.exceptions.RequestException as e:
        logger.warning(f"GeoIP lookup error for {ip_address}: {e}")
        return get_default_geoip_data()
    except Exception as e:
        logger.error(f"Unexpected error in GeoIP lookup for {ip_address}: {e}")
        return get_default_geoip_data()

def get_default_geoip_data() -> Dict[str, Any]:
    """Return default GeoIP data when lookup fails"""
    return {
        'country': 'Unknown',
        'city': 'Unknown',
        'region': 'Unknown',
        'latitude': None,
        'longitude': None,
        'timezone': 'Unknown',
        'isp': 'Unknown',
        'org': 'Unknown'
    }

def calculate_log_hash(log_data: Dict[str, Any]) -> str:
    """Calculate SHA256 hash of the log data for integrity checking"""
    try:
        # Create a copy and remove the hash field if it exists
        data_copy = log_data.copy()
        data_copy.pop('log_hash', None)
        
        # Sort keys for consistent hashing
        json_string = json.dumps(data_copy, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(json_string.encode('utf-8')).hexdigest()
        
    except Exception as e:
        logger.error(f"Error calculating log hash: {e}")
        return "hash_error"

def store_log(log_data: Dict[str, Any]) -> bool:
    """Store log entry in the database"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Prepare data for insertion
        insert_data = (
            log_data.get('timestamp'),
            log_data.get('source_ip'),
            log_data.get('geo_country'),
            log_data.get('geo_city'),
            log_data.get('geo_region'),
            log_data.get('geo_latitude'),
            log_data.get('geo_longitude'),
            log_data.get('geo_timezone'),
            log_data.get('geo_isp'),
            log_data.get('geo_org'),
            log_data.get('protocol'),
            log_data.get('target_service'),
            log_data.get('action'),
            log_data.get('target_file'),
            json.dumps(log_data.get('headers', {})),
            json.dumps(log_data.get('payload', {})),
            log_data.get('session_id'),
            log_data.get('user_agent'),
            log_data.get('log_hash')
        )
        
        cursor.execute('''
            INSERT INTO logs (
                timestamp, source_ip, geo_country, geo_city, geo_region,
                geo_latitude, geo_longitude, geo_timezone, geo_isp, geo_org,
                protocol, target_service, action, target_file, headers,
                payload, session_id, user_agent, log_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', insert_data)
        
        conn.commit()
        conn.close()
        
        logger.info(f"Log stored successfully: {log_data.get('action')} from {log_data.get('source_ip')}")
        return True
        
    except sqlite3.IntegrityError as e:
        logger.warning(f"Duplicate log entry (hash collision): {e}")
        return False
    except Exception as e:
        logger.error(f"Database storage error: {e}")
        return False

@app.route('/log', methods=['POST'])
def receive_log():
    """
    Main endpoint for receiving honeypot logs
    Processes, enriches, and stores log data
    """
    try:
        # Get the JSON payload
        log_data = request.get_json()
        
        if not log_data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        # Validate required fields
        required_fields = ['source_ip', 'action', 'target_service', 'session_id']
        for field in required_fields:
            if field not in log_data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Get GeoIP data
        source_ip = log_data['source_ip']
        geo_data = get_geoip_data(source_ip)
        
        # Enrich log data with GeoIP information
        log_data.update({
            'geo_country': geo_data['country'],
            'geo_city': geo_data['city'],
            'geo_region': geo_data['region'],
            'geo_latitude': geo_data['latitude'],
            'geo_longitude': geo_data['longitude'],
            'geo_timezone': geo_data['timezone'],
            'geo_isp': geo_data['isp'],
            'geo_org': geo_data['org']
        })
        
        # Calculate integrity hash
        log_data['log_hash'] = calculate_log_hash(log_data)
        
        # Store in database
        if store_log(log_data):
            return jsonify({
                'status': 'success',
                'message': 'Log received and stored',
                'log_id': log_data.get('log_hash', 'unknown')
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to store log'
            }), 500
            
    except Exception as e:
        logger.error(f"Error processing log: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/logs', methods=['GET'])
def get_logs():
    """
    Retrieve logs with optional filtering and pagination
    Supports query parameters: source_ip, action, target_service, limit, offset
    """
    try:
        # Get query parameters
        source_ip = request.args.get('source_ip')
        action = request.args.get('action')
        target_service = request.args.get('target_service')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Build query
        query = "SELECT * FROM logs WHERE 1=1"
        params = []
        
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        
        if action:
            query += " AND action = ?"
            params.append(action)
        
        if target_service:
            query += " AND target_service = ?"
            params.append(target_service)
        
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        # Execute query
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(query, params)
        
        # Get column names
        columns = [description[0] for description in cursor.description]
        
        # Fetch results
        rows = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        logs = []
        for row in rows:
            log_dict = dict(zip(columns, row))
            
            # Parse JSON fields
            try:
                log_dict['headers'] = json.loads(log_dict['headers']) if log_dict['headers'] else {}
                log_dict['payload'] = json.loads(log_dict['payload']) if log_dict['payload'] else {}
            except json.JSONDecodeError:
                log_dict['headers'] = {}
                log_dict['payload'] = {}
            
            logs.append(log_dict)
        
        return jsonify({
            'status': 'success',
            'logs': logs,
            'count': len(logs),
            'limit': limit,
            'offset': offset
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving logs: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get honeypot statistics and analytics"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Get total count
        cursor.execute("SELECT COUNT(*) FROM logs")
        total_logs = cursor.fetchone()[0]
        
        # Get unique IPs
        cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM logs")
        unique_ips = cursor.fetchone()[0]
        
        # Get top countries
        cursor.execute("""
            SELECT geo_country, COUNT(*) as count 
            FROM logs 
            WHERE geo_country IS NOT NULL AND geo_country != 'Unknown'
            GROUP BY geo_country 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_countries = [{'country': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Get top actions
        cursor.execute("""
            SELECT action, COUNT(*) as count 
            FROM logs 
            GROUP BY action 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_actions = [{'action': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Get top target services
        cursor.execute("""
            SELECT target_service, COUNT(*) as count 
            FROM logs 
            GROUP BY target_service 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_services = [{'service': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Get recent activity (last 24 hours)
        cursor.execute("""
            SELECT COUNT(*) FROM logs 
            WHERE created_at >= datetime('now', '-1 day')
        """)
        recent_activity = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'statistics': {
                'total_logs': total_logs,
                'unique_ips': unique_ips,
                'recent_activity_24h': recent_activity,
                'top_countries': top_countries,
                'top_actions': top_actions,
                'top_services': top_services
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check database connectivity
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        log_count = cursor.fetchone()[0]
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'service': 'Honeypot Logging Server',
            'timestamp': datetime.datetime.now().isoformat(),
            'database': 'connected',
            'total_logs': log_count,
            'version': '1.0.0'
        }), 200
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/', methods=['GET'])
def index():
    """Root endpoint - show available endpoints"""
    return jsonify({
        'service': 'Honeypot Logging Server',
        'version': '1.0.0',
        'endpoints': {
            'log_ingestion': 'POST /log',
            'log_retrieval': 'GET /logs',
            'statistics': 'GET /stats',
            'health_check': 'GET /health'
        },
        'query_parameters': {
            'logs': {
                'source_ip': 'Filter by source IP address',
                'action': 'Filter by action type',
                'target_service': 'Filter by target service',
                'limit': 'Number of logs to return (default: 100)',
                'offset': 'Number of logs to skip (default: 0)'
            }
        },
        'note': 'This is a centralized logging server for honeypot events'
    }), 200

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# ========== NEW ENDPOINTS FOR FRONTEND ==========

@app.route('/api/live-events', methods=['GET'])
def get_live_events():
    """Get recent events for Live Events page with ML scores"""
    try:
        limit = int(request.args.get('limit', 50))
        source_ip = request.args.get('source_ip')
        min_score = request.args.get('min_score', type=float)
        
        query = """
            SELECT id, timestamp, source_ip, geo_country, geo_city, 
                   protocol, target_service, action, target_file,
                   ml_score, ml_risk_level, is_anomaly, user_agent
            FROM logs WHERE 1=1
        """
        params = []
        
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        
        if min_score is not None:
            query += " AND ml_score >= ?"
            params.append(min_score)
        
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, params)
        
        events = []
        for row in cursor.fetchall():
            events.append({
                'id': row['id'],
                'time': row['timestamp'],
                'ip': row['source_ip'],
                'country': row['geo_country'] or 'Unknown',
                'city': row['geo_city'] or 'Unknown',
                'protocol': row['protocol'],
                'service': row['target_service'],
                'action': row['action'],
                'target_file': row['target_file'],
                'ml_score': row['ml_score'] if row['ml_score'] else 0.0,
                'risk_level': row['ml_risk_level'] or 'UNKNOWN',
                'is_anomaly': bool(row['is_anomaly']),
                'user_agent': row['user_agent']
            })
        
        conn.close()
        return jsonify({'events': events, 'count': len(events)}), 200
        
    except Exception as e:
        logger.error(f"Error getting live events: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    """Get analytics data for Analytics page"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Total attacks
        cursor.execute("SELECT COUNT(*) FROM logs")
        total_attacks = cursor.fetchone()[0]
        
        # High-risk attacks (score >= 0.8)
        cursor.execute("SELECT COUNT(*) FROM logs WHERE ml_score >= 0.8")
        high_risk = cursor.fetchone()[0]
        
        # Unique IPs
        cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM logs")
        unique_ips = cursor.fetchone()[0]
        
        # Average ML score
        cursor.execute("SELECT AVG(ml_score) FROM logs WHERE ml_score IS NOT NULL")
        avg_score = cursor.fetchone()[0] or 0.0
        
        # Top countries
        cursor.execute("""
            SELECT geo_country, COUNT(*) as count 
            FROM logs 
            WHERE geo_country IS NOT NULL AND geo_country != 'Unknown'
            GROUP BY geo_country 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_countries = [{'country': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Top ports (from protocol)
        cursor.execute("""
            SELECT protocol, COUNT(*) as count 
            FROM logs 
            GROUP BY protocol 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_ports = [{'port': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Top IPs by attack count
        cursor.execute("""
            SELECT source_ip, COUNT(*) as count 
            FROM logs 
            GROUP BY source_ip 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_ips = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Attacks over time (last 24 hours, hourly)
        cursor.execute("""
            SELECT strftime('%Y-%m-%d %H:00:00', created_at) as hour, COUNT(*) as count
            FROM logs
            WHERE created_at >= datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour
        """)
        time_series = [{'time': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            'total_attacks': total_attacks,
            'high_risk_attacks': high_risk,
            'unique_ips': unique_ips,
            'avg_ml_score': round(avg_score, 4),
            'top_countries': top_countries,
            'top_ports': top_ports,
            'top_ips': top_ips,
            'time_series': time_series
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting analytics: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/map-data', methods=['GET'])
def get_map_data():
    """Get geographic data for Map View"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Get all logs with coordinates
        cursor.execute("""
            SELECT geo_country, geo_city, geo_latitude, geo_longitude, 
                   source_ip, COUNT(*) as attack_count,
                   AVG(ml_score) as avg_score
            FROM logs
            WHERE geo_latitude IS NOT NULL AND geo_longitude IS NOT NULL
            GROUP BY geo_country, geo_city, geo_latitude, geo_longitude, source_ip
        """)
        
        map_points = []
        for row in cursor.fetchall():
            map_points.append({
                'country': row[0] or 'Unknown',
                'city': row[1] or 'Unknown',
                'lat': row[2],
                'lng': row[3],
                'ip': row[4],
                'attack_count': row[5],
                'avg_score': round(row[6] or 0.0, 2)
            })
        
        # Country aggregation
        cursor.execute("""
            SELECT geo_country, COUNT(*) as count, AVG(ml_score) as avg_score
            FROM logs
            WHERE geo_country IS NOT NULL AND geo_country != 'Unknown'
            GROUP BY geo_country
            ORDER BY count DESC
        """)
        
        country_stats = []
        for row in cursor.fetchall():
            country_stats.append({
                'country': row[0],
                'count': row[1],
                'avg_score': round(row[2] or 0.0, 2)
            })
        
        conn.close()
        
        return jsonify({
            'points': map_points,
            'country_stats': country_stats
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting map data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ml-insights', methods=['GET'])
def get_ml_insights():
    """Get ML insights data"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Average anomaly score
        cursor.execute("SELECT AVG(ml_score) FROM logs WHERE ml_score IS NOT NULL")
        avg_score = cursor.fetchone()[0] or 0.0
        
        # High-score IPs
        cursor.execute("""
            SELECT source_ip, AVG(ml_score) as avg_score, COUNT(*) as count
            FROM logs
            WHERE ml_score IS NOT NULL
            GROUP BY source_ip
            HAVING avg_score >= 0.8
            ORDER BY avg_score DESC
            LIMIT 10
        """)
        high_score_ips = [
            {'ip': row[0], 'avg_score': round(row[1], 4), 'count': row[2]}
            for row in cursor.fetchall()
        ]
        
        # Anomaly trend over time
        cursor.execute("""
            SELECT strftime('%Y-%m-%d %H:00:00', created_at) as hour,
                   AVG(ml_score) as avg_score,
                   COUNT(*) as count
            FROM logs
            WHERE created_at >= datetime('now', '-24 hours') AND ml_score IS NOT NULL
            GROUP BY hour
            ORDER BY hour
        """)
        anomaly_trend = [
            {'time': row[0], 'avg_score': round(row[1], 4), 'count': row[2]}
            for row in cursor.fetchall()
        ]
        
        # Risk level distribution
        cursor.execute("""
            SELECT ml_risk_level, COUNT(*) as count
            FROM logs
            WHERE ml_risk_level IS NOT NULL
            GROUP BY ml_risk_level
        """)
        risk_distribution = [
            {'risk_level': row[0], 'count': row[1]}
            for row in cursor.fetchall()
        ]
        
        # Anomaly count
        cursor.execute("SELECT COUNT(*) FROM logs WHERE is_anomaly = 1")
        anomaly_count = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'avg_anomaly_score': round(avg_score, 4),
            'high_score_ips': high_score_ips,
            'anomaly_trend': anomaly_trend,
            'risk_distribution': risk_distribution,
            'total_anomalies': anomaly_count
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting ML insights: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get alerts (high-risk events)"""
    try:
        threshold = float(request.args.get('threshold', 0.85))
        limit = int(request.args.get('limit', 50))
        
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, timestamp, source_ip, geo_country, action, 
                   target_service, ml_score, ml_risk_level, target_file
            FROM logs
            WHERE ml_score >= ? OR is_anomaly = 1
            ORDER BY ml_score DESC, created_at DESC
            LIMIT ?
        """, (threshold, limit))
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'id': row['id'],
                'timestamp': row['timestamp'],
                'source_ip': row['source_ip'],
                'country': row['geo_country'] or 'Unknown',
                'action': row['action'],
                'service': row['target_service'],
                'score': round(row['ml_score'] or 0.0, 4),
                'risk_level': row['ml_risk_level'] or 'HIGH',
                'target_file': row['target_file']
            })
        
        conn.close()
        return jsonify({'alerts': alerts, 'count': len(alerts)}), 200
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/investigate/<ip>', methods=['GET'])
def investigate_ip(ip):
    """Get detailed investigation data for a specific IP"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get all logs for this IP
        cursor.execute("""
            SELECT * FROM logs
            WHERE source_ip = ?
            ORDER BY created_at DESC
            LIMIT 100
        """, (ip,))
        
        logs = []
        for row in cursor.fetchall():
            log_dict = dict(row)
            try:
                log_dict['headers'] = json.loads(log_dict['headers']) if log_dict['headers'] else {}
                log_dict['payload'] = json.loads(log_dict['payload']) if log_dict['payload'] else {}
            except:
                log_dict['headers'] = {}
                log_dict['payload'] = {}
            logs.append(log_dict)
        
        # Get statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_attacks,
                AVG(ml_score) as avg_score,
                MAX(ml_score) as max_score,
                COUNT(DISTINCT action) as unique_actions,
                COUNT(DISTINCT target_service) as unique_services
            FROM logs
            WHERE source_ip = ?
        """, (ip,))
        
        stats_row = cursor.fetchone()
        stats = {
            'total_attacks': stats_row['total_attacks'],
            'avg_score': round(stats_row['avg_score'] or 0.0, 4),
            'max_score': round(stats_row['max_score'] or 0.0, 4),
            'unique_actions': stats_row['unique_actions'],
            'unique_services': stats_row['unique_services']
        }
        
        # Get first seen / last seen
        cursor.execute("""
            SELECT MIN(created_at) as first_seen, MAX(created_at) as last_seen
            FROM logs
            WHERE source_ip = ?
        """, (ip,))
        
        time_row = cursor.fetchone()
        stats['first_seen'] = time_row['first_seen']
        stats['last_seen'] = time_row['last_seen']
        
        # Get geo info
        cursor.execute("""
            SELECT geo_country, geo_city, geo_region, geo_latitude, geo_longitude, geo_isp
            FROM logs
            WHERE source_ip = ?
            LIMIT 1
        """, (ip,))
        
        geo_row = cursor.fetchone()
        geo_info = {
            'country': geo_row['geo_country'] if geo_row else None,
            'city': geo_row['geo_city'] if geo_row else None,
            'region': geo_row['geo_region'] if geo_row else None,
            'latitude': geo_row['geo_latitude'] if geo_row else None,
            'longitude': geo_row['geo_longitude'] if geo_row else None,
            'isp': geo_row['geo_isp'] if geo_row else None
        }
        
        # Get ML score trend
        cursor.execute("""
            SELECT strftime('%Y-%m-%d %H:00:00', created_at) as hour,
                   AVG(ml_score) as avg_score
            FROM logs
            WHERE source_ip = ? AND ml_score IS NOT NULL
            GROUP BY hour
            ORDER BY hour
        """, (ip,))
        
        score_trend = [
            {'time': row[0], 'score': round(row[1], 4)}
            for row in cursor.fetchall()
        ]
        
        conn.close()
        
        return jsonify({
            'ip': ip,
            'stats': stats,
            'geo_info': geo_info,
            'logs': logs,
            'score_trend': score_trend
        }), 200
        
    except Exception as e:
        logger.error(f"Error investigating IP {ip}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/events-stream', methods=['GET'])
def events_stream():
    """Server-Sent Events stream for real-time updates"""
    def generate():
        last_id = int(request.args.get('last_id', 0))
        while True:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, source_ip, geo_country, action, 
                       target_service, ml_score, ml_risk_level, is_anomaly
                FROM logs
                WHERE id > ?
                ORDER BY id ASC
                LIMIT 10
            """, (last_id,))
            
            events = cursor.fetchall()
            conn.close()
            
            for event in events:
                last_id = event[0]
                data = {
                    'id': event[0],
                    'timestamp': event[1],
                    'source_ip': event[2],
                    'country': event[3] or 'Unknown',
                    'action': event[4],
                    'service': event[5],
                    'ml_score': event[6] or 0.0,
                    'risk_level': event[7] or 'UNKNOWN',
                    'is_anomaly': bool(event[8])
                }
                yield f"data: {json.dumps(data)}\n\n"
            
            time.sleep(2)  # Check every 2 seconds
    
    return Response(generate(), mimetype='text/event-stream')

def main():
    """Main application entry point"""
    print("📊 Starting Honeypot Logging Server...")
    print("=" * 50)
    
    # Initialize database
    if not init_database():
        print("❌ Failed to initialize database. Exiting.")
        return
    
    print("✅ Database initialized successfully")
    print("🌐 Available endpoints:")
    print("   POST /log - Ingest honeypot logs")
    print("   GET /logs - Retrieve stored logs")
    print("   GET /stats - Get statistics and analytics")
    print("   GET /health - Health check")
    print("   GET / - Service information")
    print("\n🚀 Starting Flask server on 0.0.0.0:5000...")
    print("📡 Ready to receive logs from honeypot services")
    print("=" * 50)
    
    # Run the application
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == '__main__':
    main()
