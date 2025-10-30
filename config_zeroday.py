# Zero-Day Detection Module Configuration
# Advanced settings for zero-day vulnerability detection

import os

# Zero-Day Detection Settings
ZERODAY_ENABLED = True
ZERODAY_AGGRESSIVE_MODE = True  # Set to True for more comprehensive testing
ZERODAY_TIMEOUT = 45  # Timeout for each test in seconds
ZERODAY_MAX_PAYLOADS = 100  # Maximum number of payloads to test per target
ZERODAY_CONFIDENCE_THRESHOLD = 'low'  # minimum confidence level: low, medium, high, very_high

# Threat Intelligence Integration
THREAT_INTEL_ENABLED = True
THREAT_INTEL_CACHE_TTL = 3600  # Cache threat intel data for 1 hour
THREAT_INTEL_MAX_CVES = 10  # Maximum number of recent CVEs to check

# API Keys for Threat Intelligence Sources (add your own keys)
THREAT_INTEL_APIS = {
    'nvd_api_key': os.environ.get('NVD_API_KEY', ''),
    'exploit_db_key': os.environ.get('EXPLOIT_DB_KEY', ''),
    'threatfox_key': os.environ.get('THREATFOX_KEY', ''),
    'malwarebazaar_key': os.environ.get('MALWAREBAZAAR_KEY', ''),
    'virustotal_key': os.environ.get('VIRUSTOTAL_KEY', ''),
    'shodan_key': os.environ.get('SHODAN_KEY', '')
}

# Advanced Detection Patterns
CUSTOM_ZERODAY_PATTERNS = {
    # Add your custom patterns here
    'custom_rce': [
        r'Runtime\.getRuntime\(\)\.exec',
        r'ProcessBuilder\s*\(',
        r'cmd\.exe',
        r'/bin/sh',
        r'/bin/bash'
    ],
    
    'custom_sqli': [
        r'UNION\s+SELECT',
        r'information_schema',
        r'@@version',
        r'LOAD_FILE\(',
        r'INTO\s+OUTFILE'
    ],
    
    'custom_xss': [
        r'<script[^>]*>',
        r'javascript:',
        r'vbscript:',
        r'onload\s*=',
        r'onerror\s*='
    ]
}

# Behavioral Analysis Settings
BEHAVIORAL_ANALYSIS_ENABLED = True
BEHAVIORAL_BASELINE_REQUESTS = 3  # Number of baseline requests
BEHAVIORAL_ANOMALY_THRESHOLD = 2.0  # Deviation multiplier to flag anomalies
BEHAVIORAL_TIME_THRESHOLD = 3.0  # Time deviation multiplier

# Reporting and Alerting
ZERODAY_ALERT_WEBHOOK = os.environ.get('ZERODAY_WEBHOOK_URL', '')
ZERODAY_EMAIL_ALERTS = os.environ.get('ZERODAY_EMAIL_ALERTS', '').split(',')
ZERODAY_SLACK_WEBHOOK = os.environ.get('ZERODAY_SLACK_WEBHOOK', '')

# Advanced Features
MACHINE_LEARNING_ENABLED = True  # Enable ML-based anomaly detection
FUZZING_ENABLED = True  # Enable smart fuzzing capabilities
SIGNATURE_UPDATES_AUTO = True  # Automatically update signature database

# Performance Settings
ZERODAY_PARALLEL_REQUESTS = 5  # Number of parallel requests
ZERODAY_REQUEST_DELAY = 0.1  # Delay between requests in seconds
ZERODAY_MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # Max response size to analyze (10MB)

# Logging and Debug
ZERODAY_DEBUG_MODE = True
ZERODAY_VERBOSE_LOGGING = True
ZERODAY_LOG_PAYLOADS = True  # Log all tested payloads
ZERODAY_LOG_RESPONSES = True  # Log all responses (can be very verbose)

# Zero-Day Signature Database
SIGNATURE_DB_PATH = 'data/zeroday_signatures.json'
SIGNATURE_UPDATE_URL = 'https://api.example.com/zeroday-signatures'
SIGNATURE_UPDATE_INTERVAL = 24 * 3600  # Update every 24 hours

# Export configuration
ZERODAY_CONFIG = {
    'enabled': ZERODAY_ENABLED,
    'aggressive_mode': ZERODAY_AGGRESSIVE_MODE,
    'timeout': ZERODAY_TIMEOUT,
    'max_payloads': ZERODAY_MAX_PAYLOADS,
    'confidence_threshold': ZERODAY_CONFIDENCE_THRESHOLD,
    'threat_intel_enabled': THREAT_INTEL_ENABLED,
    'threat_intel_cache_ttl': THREAT_INTEL_CACHE_TTL,
    'threat_intel_max_cves': THREAT_INTEL_MAX_CVES,
    'api_keys': THREAT_INTEL_APIS,
    'custom_patterns': CUSTOM_ZERODAY_PATTERNS,
    'behavioral_analysis': BEHAVIORAL_ANALYSIS_ENABLED,
    'behavioral_baseline_requests': BEHAVIORAL_BASELINE_REQUESTS,
    'behavioral_anomaly_threshold': BEHAVIORAL_ANOMALY_THRESHOLD,
    'behavioral_time_threshold': BEHAVIORAL_TIME_THRESHOLD,
    'alert_webhook': ZERODAY_ALERT_WEBHOOK,
    'email_alerts': ZERODAY_EMAIL_ALERTS,
    'slack_webhook': ZERODAY_SLACK_WEBHOOK,
    'machine_learning': MACHINE_LEARNING_ENABLED,
    'fuzzing_enabled': FUZZING_ENABLED,
    'signature_updates_auto': SIGNATURE_UPDATES_AUTO,
    'parallel_requests': ZERODAY_PARALLEL_REQUESTS,
    'request_delay': ZERODAY_REQUEST_DELAY,
    'max_response_size': ZERODAY_MAX_RESPONSE_SIZE,
    'debug_mode': ZERODAY_DEBUG_MODE,
    'verbose_logging': ZERODAY_VERBOSE_LOGGING,
    'log_payloads': ZERODAY_LOG_PAYLOADS,
    'log_responses': ZERODAY_LOG_RESPONSES,
    'signature_db_path': SIGNATURE_DB_PATH,
    'signature_update_url': SIGNATURE_UPDATE_URL,
    'signature_update_interval': SIGNATURE_UPDATE_INTERVAL
}