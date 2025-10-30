import re
import json
import hashlib
import requests
from datetime import datetime, timedelta

from core.redis import rds
from core.triage import Triage
from core.parser import ScanParser, ConfParser

class Rule:
    def __init__(self):
        self.rule = 'VLN_0DAY'
        self.rule_severity = 4  # Critical severity
        self.rule_description = 'Advanced Zero-Day Vulnerability Detection Module'
        self.rule_confirm = 'Potential Zero-Day Vulnerability Detected'
        self.rule_details = ''
        self.rule_mitigation = '''Potential zero-day vulnerability detected. Immediate action required:
1. Isolate the affected system from network
2. Apply emergency security patches if available
3. Monitor for unusual network activity
4. Contact security team immediately
5. Document all findings for analysis'''
        self.intensity = 3
        
        # Zero-day indicators and patterns
        self.zeroday_patterns = {
            # Memory corruption indicators
            'buffer_overflow': [
                r'buffer\s+overflow',
                r'stack\s+overflow',
                r'heap\s+overflow',
                r'segmentation\s+fault',
                r'access\s+violation'
            ],
            
            # Code injection patterns
            'code_injection': [
                r'eval\s*\(',
                r'system\s*\(',
                r'exec\s*\(',
                r'shell_exec',
                r'passthru\s*\(',
                r'proc_open'
            ],
            
            # Deserialization attacks
            'deserialization': [
                r'__wakeup',
                r'__destruct',
                r'unserialize\s*\(',
                r'pickle\.loads',
                r'yaml\.load',
                r'java\.io\.ObjectInputStream'
            ],
            
            # Template injection
            'template_injection': [
                r'\{\{.*\}\}',
                r'\$\{.*\}',
                r'<%.*%>',
                r'{{.*}}',
                r'#{.*}'
            ],
            
            # XXE indicators
            'xxe_patterns': [
                r'<!ENTITY',
                r'SYSTEM\s+["\']',
                r'DOCTYPE.*\[',
                r'xml\s+version',
                r'<!DOCTYPE.*ENTITY'
            ],
            
            # LDAP injection
            'ldap_injection': [
                r'\*\)\(.*=',
                r'\(\|\(',
                r'\(&\(',
                r'objectClass=\*',
                r'cn=\*'
            ],
            
            # NoSQL injection
            'nosql_injection': [
                r'\$ne\s*:',
                r'\$gt\s*:',
                r'\$regex\s*:',
                r'\$where\s*:',
                r'this\..*=='
            ]
        }
        
        # Anomaly detection patterns
        self.anomaly_patterns = {
            'unusual_headers': [
                'X-Forwarded-Proto: file',
                'X-Original-URL: /',
                'X-Rewrite-URL: /',
                'Content-Length: -1',
                'Transfer-Encoding: identity'
            ],
            
            'suspicious_responses': [
                'java.lang.OutOfMemoryError',
                'Microsoft JET Database',
                'ORA-00921',
                'PostgreSQL query failed',
                'Warning: mysql_'
            ],
            
            'info_disclosure': [
                'Server: Apache/2.4.1 (Unix)',
                'X-Powered-By: PHP/',
                'Set-Cookie: JSESSIONID',
                'Server: Microsoft-IIS/',
                'X-AspNet-Version:'
            ]
        }

    def check_rule(self, ip, port, values, conf):
        """Main rule checking function"""
        c = ConfParser(conf)
        t = Triage()
        p = ScanParser(port, values)
        
        domain = p.get_domain()
        module = p.get_module()
        
        if 'http' not in module:
            return
            
        # Perform multiple zero-day detection checks
        findings = []
        
        # 1. Pattern-based detection
        pattern_results = self._check_vulnerability_patterns(t, ip, port)
        if pattern_results:
            findings.extend(pattern_results)
            
        # 2. Anomaly detection
        anomaly_results = self._check_anomalies(t, ip, port)
        if anomaly_results:
            findings.extend(anomaly_results)
            
        # 3. Response analysis
        response_results = self._analyze_responses(t, ip, port)
        if response_results:
            findings.extend(response_results)
            
        # 4. Advanced payload testing
        payload_results = self._test_advanced_payloads(t, ip, port)
        if payload_results:
            findings.extend(payload_results)
            
        # 5. Behavioral analysis
        behavioral_results = self._behavioral_analysis(t, ip, port)
        if behavioral_results:
            findings.extend(behavioral_results)
        
        # Store findings
        if findings:
            self._store_findings(ip, port, domain, findings)
            
    def _check_vulnerability_patterns(self, triage, ip, port):
        """Check for known zero-day vulnerability patterns"""
        findings = []
        
        test_payloads = [
            # Buffer overflow tests
            'A' * 1000,
            '%s' * 100,
            '\x00' * 500,
            
            # Code injection tests  
            '$(id)',
            '`id`',
            ';id;',
            '|id|',
            
            # Template injection
            '{{7*7}}',
            '${7*7}',
            '<%=7*7%>',
            '#{7*7}',
            
            # XXE tests
            '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
            
            # NoSQL injection
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
        ]
        
        for payload in test_payloads:
            try:
                # Test different injection points
                for param in ['q', 'search', 'id', 'user', 'data']:
                    resp = triage.http_request(ip, port, uri=f'/?{param}={payload}')
                    if resp:
                        for pattern_type, patterns in self.zeroday_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, resp.text, re.IGNORECASE):
                                    findings.append({
                                        'type': 'pattern_match',
                                        'category': pattern_type,
                                        'payload': payload,
                                        'pattern': pattern,
                                        'url': resp.url,
                                        'confidence': 'high'
                                    })
            except:
                continue
                
        return findings
        
    def _check_anomalies(self, triage, ip, port):
        """Check for anomalous server behavior"""
        findings = []
        
        # Test unusual HTTP methods
        unusual_methods = ['TRACE', 'CONNECT', 'PATCH', 'PURGE', 'LINK', 'UNLINK']
        
        for method in unusual_methods:
            try:
                resp = triage.http_request(ip, port, method=method)
                if resp and resp.status_code not in [405, 501]:
                    findings.append({
                        'type': 'anomaly',
                        'category': 'unusual_method',
                        'method': method,
                        'status_code': resp.status_code,
                        'confidence': 'medium'
                    })
            except:
                continue
                
        # Test malformed requests
        malformed_tests = [
            {'uri': '/' + 'A' * 8000},  # Long URI
            {'uri': '/\x00'},           # Null byte
            {'uri': '//'},              # Double slash
            {'uri': '/..\\..\\'},       # Mixed path traversal
        ]
        
        for test in malformed_tests:
            try:
                resp = triage.http_request(ip, port, **test)
                if resp and resp.status_code == 200:
                    findings.append({
                        'type': 'anomaly',
                        'category': 'malformed_accepted',
                        'test': test,
                        'status_code': resp.status_code,
                        'confidence': 'high'
                    })
            except:
                continue
                
        return findings
        
    def _analyze_responses(self, triage, ip, port):
        """Analyze server responses for zero-day indicators"""
        findings = []
        
        try:
            resp = triage.http_request(ip, port)
            if not resp:
                return findings
                
            # Check response headers
            for header, value in resp.headers.items():
                for suspicious_header in self.anomaly_patterns['unusual_headers']:
                    if suspicious_header.lower() in f"{header}: {value}".lower():
                        findings.append({
                            'type': 'response_analysis',
                            'category': 'suspicious_header',
                            'header': f"{header}: {value}",
                            'confidence': 'medium'
                        })
                        
            # Check response body
            for suspicious_response in self.anomaly_patterns['suspicious_responses']:
                if suspicious_response.lower() in resp.text.lower():
                    findings.append({
                        'type': 'response_analysis',
                        'category': 'suspicious_response',
                        'content': suspicious_response,
                        'confidence': 'high'
                    })
                    
        except:
            pass
            
        return findings
        
    def _test_advanced_payloads(self, triage, ip, port):
        """Test advanced exploitation payloads"""
        findings = []
        
        # Time-based detection payloads
        time_payloads = [
            '; sleep(5) #',
            '; waitfor delay \'00:00:05\' --',
            '; SELECT pg_sleep(5) --',
            '\'; setTimeout(function(){}, 5000); //',
        ]
        
        for payload in time_payloads:
            try:
                start_time = datetime.now()
                resp = triage.http_request(ip, port, uri=f'/?test={payload}')
                end_time = datetime.now()
                
                time_diff = (end_time - start_time).total_seconds()
                
                if time_diff >= 4:  # Allow some tolerance
                    findings.append({
                        'type': 'time_based',
                        'category': 'delay_injection',
                        'payload': payload,
                        'delay': time_diff,
                        'confidence': 'very_high'
                    })
            except:
                continue
                
        return findings
        
    def _behavioral_analysis(self, triage, ip, port):
        """Analyze behavioral patterns for zero-day detection"""
        findings = []
        
        try:
            # Baseline request
            baseline = triage.http_request(ip, port)
            if not baseline:
                return findings
                
            baseline_size = len(baseline.text)
            baseline_time = baseline.elapsed.total_seconds()
            
            # Test with various payloads and analyze behavioral changes
            test_cases = [
                {'payload': '../' * 10, 'type': 'path_traversal'},
                {'payload': '<script>alert(1)</script>', 'type': 'xss'},
                {'payload': '\' OR 1=1 --', 'type': 'sql_injection'},
                {'payload': '{$smarty.version}', 'type': 'template_injection'},
            ]
            
            for test in test_cases:
                resp = triage.http_request(ip, port, uri=f"/?test={test['payload']}")
                if resp:
                    size_diff = abs(len(resp.text) - baseline_size)
                    time_diff = abs(resp.elapsed.total_seconds() - baseline_time)
                    
                    # Significant behavioral changes might indicate vulnerability
                    if size_diff > baseline_size * 0.5 or time_diff > baseline_time * 2:
                        findings.append({
                            'type': 'behavioral',
                            'category': test['type'],
                            'payload': test['payload'],
                            'size_change': size_diff,
                            'time_change': time_diff,
                            'confidence': 'medium'
                        })
                        
        except:
            pass
            
        return findings
        
    def _store_findings(self, ip, port, domain, findings):
        """Store zero-day findings in the database"""
        high_confidence_findings = [f for f in findings if f.get('confidence') in ['high', 'very_high']]
        
        if high_confidence_findings:
            # Create detailed report
            details = "Zero-Day Vulnerability Indicators Found:\n\n"
            
            for i, finding in enumerate(high_confidence_findings, 1):
                details += f"{i}. {finding['type'].upper()} - {finding['category']}\n"
                details += f"   Confidence: {finding['confidence']}\n"
                
                if 'payload' in finding:
                    details += f"   Payload: {finding['payload']}\n"
                if 'pattern' in finding:
                    details += f"   Pattern: {finding['pattern']}\n"
                if 'delay' in finding:
                    details += f"   Delay: {finding['delay']}s\n"
                    
                details += "\n"
                
            details += f"\nTotal indicators found: {len(findings)}"
            details += f"\nHigh-confidence indicators: {len(high_confidence_findings)}"
            details += f"\nScan timestamp: {datetime.now().isoformat()}"
            
            self.rule_details = details
            
            # Store the vulnerability
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