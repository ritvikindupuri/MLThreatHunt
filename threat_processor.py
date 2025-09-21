"""
GCP Cloud Function for threat intelligence processing
Processes Pub/Sub messages and performs AI-based threat analysis
"""

import json
import base64
import logging
from datetime import datetime
from google.cloud import aiplatform
from google.cloud import bigquery
from google.cloud import secretmanager
import numpy as np
import functions_framework

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize clients
bq_client = bigquery.Client()
secret_client = secretmanager.SecretManagerServiceClient()

@functions_framework.cloud_event
def process_threat_event(cloud_event):
    """
    Main Cloud Function entry point for processing threat events
    """
    try:
        # Decode Pub/Sub message
        message_data = base64.b64decode(cloud_event.data["message"]["data"])
        event_data = json.loads(message_data)
        
        logger.info(f"Processing threat event: {event_data.get('event_id', 'unknown')}")
        
        # Perform threat analysis
        analysis_result = analyze_threat_intelligence(event_data)
        
        # Get AI predictions
        ai_prediction = get_vertex_ai_prediction(event_data)
        
        # Enrich event data
        enriched_event = {
            'timestamp': datetime.utcnow().isoformat(),
            'original_event': event_data,
            'threat_analysis': analysis_result,
            'ai_prediction': ai_prediction,
            'processing_metadata': {
                'function_name': 'threat_processor',
                'version': '1.0',
                'processed_at': datetime.utcnow().isoformat()
            }
        }
        
        # Store in BigQuery
        store_in_bigquery(enriched_event)
        
        # Generate alerts if necessary
        if analysis_result['risk_score'] > 0.7:
            generate_security_alert(enriched_event)
        
        logger.info(f"Successfully processed event with risk score: {analysis_result['risk_score']}")
        
        return {'status': 'success', 'risk_score': analysis_result['risk_score']}
        
    except Exception as e:
        logger.error(f"Error processing threat event: {str(e)}")
        raise

def analyze_threat_intelligence(event_data):
    """
    Perform comprehensive threat intelligence analysis
    """
    risk_score = 0.0
    indicators = []
    
    # IP reputation analysis
    if 'source_ip' in event_data:
        ip_risk = analyze_ip_reputation(event_data['source_ip'])
        risk_score += ip_risk['score']
        if ip_risk['indicators']:
            indicators.extend(ip_risk['indicators'])
    
    # Domain analysis
    if 'domain' in event_data:
        domain_risk = analyze_domain_reputation(event_data['domain'])
        risk_score += domain_risk['score']
        if domain_risk['indicators']:
            indicators.extend(domain_risk['indicators'])
    
    # File hash analysis
    if 'file_hash' in event_data:
        hash_risk = analyze_file_hash(event_data['file_hash'])
        risk_score += hash_risk['score']
        if hash_risk['indicators']:
            indicators.extend(hash_risk['indicators'])
    
    # Behavioral analysis
    behavioral_risk = analyze_behavior_patterns(event_data)
    risk_score += behavioral_risk['score']
    if behavioral_risk['indicators']:
        indicators.extend(behavioral_risk['indicators'])
    
    # Normalize risk score
    risk_score = min(risk_score, 1.0)
    
    return {
        'risk_score': risk_score,
        'risk_level': categorize_risk_level(risk_score),
        'indicators': indicators,
        'analysis_timestamp': datetime.utcnow().isoformat()
    }

def analyze_ip_reputation(ip_address):
    """
    Analyze IP address reputation using threat intelligence
    """
    indicators = []
    score = 0.0
    
    # Check against known malicious IP ranges
    malicious_ranges = [
        '192.168.1.0/24',  # Example ranges
        '10.0.0.0/8'
    ]
    
    # Simplified geolocation risk
    high_risk_countries = ['CN', 'RU', 'KP', 'IR']
    
    # In real implementation, query threat intelligence APIs
    # For demo purposes, using simplified logic
    
    if any(ip_address.startswith(r.split('/')[0][:7]) for r in malicious_ranges):
        score += 0.4
        indicators.append({
            'type': 'malicious_ip_range',
            'description': f'IP {ip_address} matches known malicious range',
            'severity': 'medium'
        })
    
    # Check for suspicious patterns
    if ip_address.count('.') != 3:  # Invalid IPv4
        score += 0.2
        indicators.append({
            'type': 'invalid_ip_format',
            'description': f'Invalid IP format: {ip_address}',
            'severity': 'low'
        })
    
    return {'score': score, 'indicators': indicators}

def analyze_domain_reputation(domain):
    """
    Analyze domain reputation and characteristics
    """
    indicators = []
    score = 0.0
    
    # Check for suspicious domain patterns
    suspicious_patterns = [
        'bit.ly', 'tinyurl.com', 'goo.gl',  # URL shorteners
        'tempmail', 'guerrillamail',        # Temporary email domains
        'duckdns.org', 'no-ip.com'         # Dynamic DNS
    ]
    
    # Domain length analysis
    if len(domain) > 50:
        score += 0.2
        indicators.append({
            'type': 'long_domain',
            'description': f'Unusually long domain: {domain}',
            'severity': 'low'
        })
    
    # Suspicious pattern check
    for pattern in suspicious_patterns:
        if pattern in domain.lower():
            score += 0.3
            indicators.append({
                'type': 'suspicious_domain_pattern',
                'description': f'Domain contains suspicious pattern: {pattern}',
                'severity': 'medium'
            })
    
    # Check for homograph attacks
    if has_homograph_characters(domain):
        score += 0.5
        indicators.append({
            'type': 'homograph_attack',
            'description': f'Domain may use homograph characters: {domain}',
            'severity': 'high'
        })
    
    return {'score': score, 'indicators': indicators}

def analyze_file_hash(file_hash):
    """
    Analyze file hash against threat intelligence
    """
    indicators = []
    score = 0.0
    
    # In real implementation, check against VirusTotal, etc.
    # For demo, using simplified logic
    
    known_malicious_hashes = [
        'e3b0c44298fc1c149afbf4c8996fb924',  # Example hashes
        '5d41402abc4b2a76b9719d911017c592'
    ]
    
    if file_hash.lower() in known_malicious_hashes:
        score += 0.9
        indicators.append({
            'type': 'known_malware',
            'description': f'File hash matches known malware: {file_hash}',
            'severity': 'critical'
        })
    
    return {'score': score, 'indicators': indicators}

def analyze_behavior_patterns(event_data):
    """
    Analyze behavioral patterns in the event data
    """
    indicators = []
    score = 0.0
    
    # Check for unusual timing patterns
    if 'timestamp' in event_data:
        hour = datetime.fromisoformat(event_data['timestamp'].replace('Z', '+00:00')).hour
        if hour < 6 or hour > 22:  # Outside business hours
            score += 0.1
            indicators.append({
                'type': 'unusual_timing',
                'description': f'Activity outside normal hours: {hour}:00',
                'severity': 'low'
            })
    
    # Check for high frequency patterns
    if 'request_count' in event_data and event_data['request_count'] > 100:
        score += 0.3
        indicators.append({
            'type': 'high_frequency',
            'description': f'High request frequency: {event_data["request_count"]}',
            'severity': 'medium'
        })
    
    # Check for privilege escalation attempts
    if 'command' in event_data:
        escalation_commands = ['sudo', 'su', 'runas', 'net user']
        if any(cmd in event_data['command'].lower() for cmd in escalation_commands):
            score += 0.4
            indicators.append({
                'type': 'privilege_escalation',
                'description': f'Potential privilege escalation: {event_data["command"]}',
                'severity': 'high'
            })
    
    return {'score': score, 'indicators': indicators}

def has_homograph_characters(domain):
    """
    Check for homograph attack characters in domain
    """
    # Simplified homograph detection
    suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х']  # Cyrillic lookalikes
    return any(char in domain for char in suspicious_chars)

def categorize_risk_level(risk_score):
    """
    Categorize risk level based on score
    """
    if risk_score >= 0.8:
        return 'CRITICAL'
    elif risk_score >= 0.6:
        return 'HIGH'
    elif risk_score >= 0.4:
        return 'MEDIUM'
    elif risk_score >= 0.2:
        return 'LOW'
    else:
        return 'MINIMAL'

def get_vertex_ai_prediction(event_data):
    """
    Get prediction from Vertex AI model
    """
    try:
        # Initialize Vertex AI client
        aiplatform.init(project=os.environ.get('PROJECT_ID'))
        
        # Prepare features
        features = extract_ml_features(event_data)
        
        # Get prediction (simplified for demo)
        # In real implementation, call actual Vertex AI endpoint
        prediction = {
            'threat_probability': min(sum(features.values()) / len(features), 1.0),
            'confidence': 0.85,
            'model_version': '1.2.3'
        }
        
        return prediction
        
    except Exception as e:
        logger.warning(f"Vertex AI prediction failed: {str(e)}")
        return {'threat_probability': 0.0, 'confidence': 0.0, 'error': str(e)}

def extract_ml_features(event_data):
    """
    Extract features for ML model
    """
    return {
        'ip_entropy': calculate_entropy(event_data.get('source_ip', '')),
        'domain_length': len(event_data.get('domain', '')),
        'request_size': event_data.get('request_size', 0) / 1000,  # Normalize
        'time_of_day': datetime.now().hour / 24,  # Normalize to 0-1
        'has_suspicious_keywords': int(has_suspicious_keywords(event_data))
    }

def calculate_entropy(string):
    """
    Calculate Shannon entropy
    """
    if not string:
        return 0.0
    
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = -sum([p * np.log2(p) for p in prob if p > 0])
    return entropy / 8  # Normalize

def has_suspicious_keywords(event_data):
    """
    Check for suspicious keywords in event data
    """
    suspicious_keywords = [
        'exploit', 'payload', 'shell', 'backdoor', 'malware',
        'phishing', 'ransomware', 'trojan', 'rootkit'
    ]
    
    event_str = json.dumps(event_data).lower()
    return any(keyword in event_str for keyword in suspicious_keywords)

def store_in_bigquery(enriched_event):
    """
    Store enriched event in BigQuery
    """
    try:
        dataset_id = os.environ.get('BIGQUERY_DATASET', 'threat_analytics')
        table_id = 'threat_events'
        
        # Prepare row for insertion
        row = {
            'timestamp': enriched_event['timestamp'],
            'source_ip': enriched_event['original_event'].get('source_ip'),
            'destination_ip': enriched_event['original_event'].get('destination_ip'),
            'event_type': enriched_event['original_event'].get('event_type'),
            'threat_score': enriched_event['threat_analysis']['risk_score'],
            'indicators': json.dumps(enriched_event['threat_analysis']['indicators'])
        }
        
        # Insert row (simplified for demo)
        logger.info(f"Storing event in BigQuery: {row['timestamp']}")
        
    except Exception as e:
        logger.error(f"Failed to store in BigQuery: {str(e)}")

def generate_security_alert(enriched_event):
    """
    Generate security alert for high-risk events
    """
    try:
        alert = {
            'alert_id': f"alert_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            'severity': enriched_event['threat_analysis']['risk_level'],
            'risk_score': enriched_event['threat_analysis']['risk_score'],
            'indicators': enriched_event['threat_analysis']['indicators'],
            'event_summary': enriched_event['original_event'],
            'timestamp': enriched_event['timestamp']
        }
        
        logger.warning(f"SECURITY ALERT: {alert['alert_id']} - Risk Score: {alert['risk_score']}")
        
        # In real implementation, send to Security Center, Pub/Sub, etc.
        
    except Exception as e:
        logger.error(f"Failed to generate security alert: {str(e)}")