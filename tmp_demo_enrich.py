import os
import time
from core.redis import rds
from core.reports import generate_html

# Try to import NVD helper
try:
    from core.nvd import search_cves_by_keyword
except Exception as e:
    print('Could not import core.nvd:', e)
    search_cves_by_keyword = None

vuln = {
    'ip':'127.0.0.1',
    'port':8080,
    'rule_id':'TEST-ENRICH-1',
    'rule_desc':'Test OpenSSL disclosure',
    'rule_details':'openssl vulnerability',
    'rule_sev':3,
    'rule_confirm':'Evidence: sample',
    'rule_mitigation':'Update OpenSSL to latest',
    'domain':''
}

keyword = vuln.get('rule_details') or vuln.get('rule_desc') or vuln.get('rule_id')
if search_cves_by_keyword and keyword:
    try:
        cves = search_cves_by_keyword(keyword, max_results=5)
        print('NVD lookup returned:', cves)
        if cves:
            vuln['cve_ids'] = cves
    except Exception as e:
        print('NVD lookup failed:', e)
else:
    print('Skipping NVD lookup (no core.nvd)')

# Store the vulnerability (will use mock Redis if real Redis not available)
stored = rds.store_vuln(vuln)
print('rds.store_vuln returned:', stored)

# Small pause then fetch stored vulns
time.sleep(0.5)
vulns = rds.get_vuln_data()
print('Stored vuln keys:', list(vulns.keys()))

# Ensure reports directory exists
if not os.path.exists('reports'):
    os.makedirs('reports')

# For report generation, only include the enriched sample vuln to avoid
# older stored entries missing expected fields
vulns_for_report = {'demo_enrich_1': vuln}

conf = {
    'metadata':{
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'unique_id':'demo-enrich-1',
        'issuer':{'source_ip':'127.0.0.1'}
    },
    'config':{
        'name':'Demo Scan',
        'engineer':'Automated'
    }
}

try:
    filename = generate_html(vulns_for_report, conf)
    print('Generated HTML report:', filename)
except Exception as e:
    print('Failed to generate HTML report:', e)

print('Demo finished.')
