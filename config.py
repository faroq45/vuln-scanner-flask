import os

# Logger Configuration
LOG_LEVEL = 'DEBUG'

# Webserver Configuration
WEB_HOST = '0.0.0.0'
WEB_PORT = 8080
WEB_DEBUG = True
WEB_USER = os.environ.get('WEB_USER', 'admin')
WEB_PASSW = os.environ.get('WEB_PASSW', 'admin')
WEB_LOG = 'vulscanner.log'

# Web Security
# Setting this to True will return all responses with security headers.
WEB_SECURITY = True
WEB_SEC_HEADERS = {
  'CSP':'default-src \'self\' \'unsafe-inline\'; object-src \'none\'; img-src \'self\' data:',
  'CTO':'nosniff',
  'XSS':'1; mode=block',
  'XFO':'DENY',
  'RP':'no-referrer',
  'Server':'vulscanner'
}

# Maximum allowed attempts before banning the remote origin
MAX_LOGIN_ATTEMPTS = 5

# Redis Configuration
# This should not be set to anything else except localhost unless you want to do a multi-node deployment.
RDS_HOST = '127.0.0.1'
RDS_PORT = 6379
RDS_PASSW = None

# PostgreSQL Database Configuration
DB_PORT = os.environ.get('DB_PORT', '5432')
DB_NAME = os.environ.get('DB_NAME', 'vulnscanner')
DB_PASSWORD = os.environ.get('DB_PASSWORD', '')

# Get the directory where this config file is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_URL = f"sqlite:///{os.path.join(BASE_DIR, 'vulnscanner.db')}"

# Database settings
USE_DATABASE = True
DB_ECHO = False  # Set to False to reduce log verbosity

# Scan Configuration
USER_AGENT = 'vulscanner'

# Machine Learning feature toggle
# Set to True to enable ML payload generation (requires numpy, pandas, scikit-learn, joblib)
# If ML dependencies are missing but this is True, the app will instruct you to install
# the required packages. Use conda-forge on Windows to obtain prebuilt binaries.
ENABLE_ML = True

# Default scan configuration
# This will be used in the "Quick Start" scan. 
DEFAULT_SCAN = {
  'targets':{
    'networks':[],
    'excluded_networks':[],
    'domains':[],
    'urls':[]
  },
  'config':{
    'name':'Default',
    'description':'My Default Scan',
    'engineer':'John Doe',
    'allow_aggressive':3,
    'allow_dos':False,
    'allow_bf':False,
    'allow_internet':True,
    'dictionary':{
      'usernames':[],
      'passwords':[]
    },
    'scan_opts':{
      'interface':None,
      'max_ports':100,
      'custom_ports':[],
      'parallel_scan':50,
      'parallel_attack':30,
    },
    'post_event':{
      'webhook':None
    },
    'frequency':'once'
  }
}
