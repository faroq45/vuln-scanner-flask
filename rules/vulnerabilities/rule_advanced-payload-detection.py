import re
import json
import random
from datetime import datetime
from typing import List, Dict, Any

from core.redis import rds
from core.triage import Triage
from core.parser import ScanParser, ConfParser
from core.payload_generator import PayloadGenerator

class Rule:
    def __init__(self):
        self.rule = 'VLN_ADVPAY'
        self.rule_severity = 4  # Critical severity
        self.rule_description = 'Advanced Payload Generation and Zero-Day Detection Engine'
        self.rule_confirm = 'Advanced Vulnerability Detected via Dynamic Payload Generation'
        self.rule_details = ''
        self.rule_mitigation = '''Advanced vulnerability detected through dynamic payload generation:
1. IMMEDIATE: Isolate affected systems from network
2. URGENT: Apply emergency patches if available
3. ANALYZE: Review payload that triggered detection
4. MONITOR: Implement enhanced logging and monitoring
5. UPDATE: Update WAF/security tools with new signatures
6. DOCUMENT: Create incident report with technical details'''
        self.intensity = 4
        
        # Initialize the advanced payload generator
        self.payload_generator = PayloadGenerator()
        
        # Advanced detection configuration
        self.detection_config = {
            'max_payloads_per_type': 15,
            'enable_polyglot_testing': True,
            'enable_mutation_testing': True,
            'enable_context_aware': True,
            'confidence_threshold': 0.7,
            'max_generations': 3,
            'enable_evasion_testing': True
        }
        
        # Success indicators for different attack types
        self.success_indicators = {
            'sql_injection': [
                r'syntax error.*SQL',
                r'ORA-\d+',
                r'MySQL.*error',
                r'PostgreSQL.*error',
                r'Microsoft.*ODBC.*SQL',
                r'Warning.*mysql_',
                r'valid MySQL result',
                r'SQLite.*error',
                r'sqlite3.OperationalError'
            ],
            
            'xss': [
                r'<script[^>]*>.*</script>',
                r'javascript:',
                r'eval\s*\(',
                r'alert\s*\(',
                r'confirm\s*\(',
                r'prompt\s*\(',
                r'document\.cookie',
                r'window\.location'
            ],
            
            'command_injection': [
                r'root:x:0:0',
                r'uid=\d+\(.*\)',
                r'Microsoft Windows',
                r'Directory of',
                r'total \d+',
                r'drwxr-xr-x',
                r'SYSTEM.*Windows',
                r'bash.*version'
            ],
            
            'path_traversal': [
                r'root:x:0:0:root:/root:/bin/',
                r'\[boot loader\]',
                r'<title>Index of /',
                r'Parent Directory',
                r'Directory Listing',
                r'etc/passwd',
                r'boot.ini',
                r'win.ini'
            ],
            
            'template_injection': [
                r'49',  # 7*7 calculation result
                r'TemplateCompileError',
                r'UndefinedError',
                r'jinja2\.exceptions',
                r'Traceback.*template',
                r'Template.*error',
                r'eval.*result'
            ],
            
            'xml_injection': [
                r'root:x:0:0',
                r'XMLSyntaxError',
                r'XML.*parsing.*error',
                r'DTD.*forbidden',
                r'External.*entity.*reference',
                r'ENTITY.*declaration'
            ],
            
            'deserialization': [
                r'java\.io\.ObjectInputStream',
                r'pickle\.UnpicklingError',
                r'yaml\.constructor\.ConstructorError',
                r'__reduce__.*called',
                r'ObjectMapper.*error',
                r'deserialization.*failed'
            ]
        }

    def check_rule(self, ip, port, values, conf):
        """Main rule checking function with advanced payload generation"""
        c = ConfParser(conf)
        t = Triage()
        p = ScanParser(port, values)
        
        domain = p.get_domain()
        module = p.get_module()
        
        if 'http' not in module:
            return
            
        # Collect target information for context-aware payload generation
        target_info = self._gather_target_info(t, ip, port)
        
        findings = []
        
        # 1. Advanced payload testing for each vulnerability type
        for vuln_type in self.payload_generator.base_templates.keys():
            vuln_findings = self._test_vulnerability_with_advanced_payloads(
                t, ip, port, vuln_type, target_info
            )
            findings.extend(vuln_findings)
            
        # 2. Polyglot payload testing
        if self.detection_config['enable_polyglot_testing']:
            polyglot_findings = self._test_polyglot_payloads(t, ip, port)
            findings.extend(polyglot_findings)
            
        # 3. Mutation-based testing
        if self.detection_config['enable_mutation_testing']:
            mutation_findings = self._test_mutation_payloads(t, ip, port, target_info)
            findings.extend(mutation_findings)
            
        # 4. Context-aware adaptive testing
        if self.detection_config['enable_context_aware']:
            adaptive_findings = self._test_adaptive_payloads(t, ip, port, target_info)
            findings.extend(adaptive_findings)
            
        # 5. Evasion technique testing
        if self.detection_config['enable_evasion_testing']:
            evasion_findings = self._test_evasion_payloads(t, ip, port, target_info)
            findings.extend(evasion_findings)
        
        # Filter and store high-confidence findings
        high_confidence_findings = [
            f for f in findings 
            if f.get('confidence', 0) >= self.detection_config['confidence_threshold']
        ]
        
        if high_confidence_findings:
            self._store_advanced_findings(ip, port, domain, high_confidence_findings)
            
    def _gather_target_info(self, triage, ip, port):
        """Gather information about the target for context-aware payload generation"""
        target_info = {
            'server': '',
            'technologies': [],
            'headers': {},
            'content_type': '',
            'response_patterns': []
        }
        
        try:
            # Initial probe request
            resp = triage.http_request(ip, port)
            if resp:
                target_info['headers'] = dict(resp.headers)
                target_info['server'] = resp.headers.get('Server', '')
                target_info['content_type'] = resp.headers.get('Content-Type', '')
                
                # Detect technologies from headers and content
                content = resp.text.lower()
                
                # Technology detection
                if 'php' in content or 'x-powered-by' in resp.headers and 'php' in resp.headers['x-powered-by'].lower():
                    target_info['technologies'].append('php')
                if 'java' in content or 'jsessionid' in content:
                    target_info['technologies'].append('java')
                if 'python' in content or 'django' in content or 'flask' in content:
                    target_info['technologies'].append('python')
                if 'asp.net' in content or 'aspnet' in resp.headers.get('x-aspnet-version', ''):
                    target_info['technologies'].append('aspnet')
                    
                # Response pattern analysis
                target_info['response_patterns'] = self._analyze_response_patterns(content)
                
        except Exception:
            pass
            
        return target_info
        
    def _analyze_response_patterns(self, content):
        """Analyze response content for patterns that might indicate vulnerabilities"""
        patterns = []
        
        # Error message patterns
        error_patterns = [
            r'error.*sql',
            r'warning.*mysql',
            r'exception.*java',
            r'traceback.*python',
            r'fatal error.*php',
            r'stack trace',
            r'debug.*mode'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                patterns.append(pattern)
                
        return patterns
        
    def _test_vulnerability_with_advanced_payloads(self, triage, ip, port, vuln_type, target_info):
        """Test specific vulnerability type with advanced payload generation"""
        findings = []
        
        try:
            # Generate advanced payloads for this vulnerability type
            payloads = self.payload_generator.generate_advanced_payloads(
                vuln_type,
                count=self.detection_config['max_payloads_per_type'],
                target_info=target_info
            )
            
            success_patterns = self.success_indicators.get(vuln_type, [])
            
            for payload in payloads:
                # Test payload in different contexts
                contexts = ['url_param', 'form_data', 'json', 'header']
                
                for context in contexts:
                    result = self._test_payload_in_context(
                        triage, ip, port, payload, context, success_patterns, vuln_type
                    )
                    if result:
                        findings.append(result)
                        
        except Exception as e:
            pass
            
        return findings
        
    def _test_payload_in_context(self, triage, ip, port, payload, context, success_patterns, vuln_type):
        """Test a single payload in a specific context"""
        try:
            resp = None
            
            if context == 'url_param':
                resp = triage.http_request(ip, port, uri=f'/?test={payload}')
            elif context == 'form_data':
                resp = triage.http_request(ip, port, method='POST', data={'input': payload})
            elif context == 'json':
                json_payload = json.dumps({'data': payload})
                resp = triage.http_request(ip, port, method='POST', 
                                         data=json_payload, 
                                         headers={'Content-Type': 'application/json'})
            elif context == 'header':
                resp = triage.http_request(ip, port, headers={'X-Test': payload})
                
            if resp:
                # Check for success indicators
                confidence = self._calculate_confidence(resp.text, success_patterns)
                
                if confidence > 0.5:  # Threshold for potential vulnerability
                    return {
                        'vulnerability_type': vuln_type,
                        'context': context,
                        'payload': payload[:100],  # Truncate for storage
                        'confidence': confidence,
                        'response_code': resp.status_code,
                        'response_length': len(resp.text),
                        'detection_method': 'advanced_payload_generation',
                        'timestamp': datetime.now().isoformat()
                    }
                    
        except Exception:
            pass
            
        return None
        
    def _calculate_confidence(self, response_text, success_patterns):
        """Calculate confidence score based on response analysis"""
        if not success_patterns:
            return 0.0
            
        matches = 0
        total_patterns = len(success_patterns)
        
        for pattern in success_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                matches += 1
                
        base_confidence = matches / total_patterns
        
        # Boost confidence for multiple matches
        if matches > 1:
            base_confidence = min(1.0, base_confidence * 1.2)
            
        # Additional confidence indicators
        error_keywords = ['error', 'exception', 'warning', 'failed', 'invalid']
        error_count = sum(1 for keyword in error_keywords if keyword in response_text.lower())
        
        if error_count > 0:
            base_confidence = min(1.0, base_confidence + 0.1)
            
        return base_confidence
        
    def _test_polyglot_payloads(self, triage, ip, port):
        """Test polyglot payloads that work across multiple vulnerability types"""
        findings = []
        
        try:
            polyglot_payloads = self.payload_generator.generate_polyglot_payloads(count=8)
            
            for payload in polyglot_payloads:
                resp = triage.http_request(ip, port, uri=f'/?polyglot={payload}')
                
                if resp:
                    # Check against all vulnerability types
                    for vuln_type, patterns in self.success_indicators.items():
                        confidence = self._calculate_confidence(resp.text, patterns)
                        
                        if confidence > 0.6:  # Higher threshold for polyglots
                            findings.append({
                                'vulnerability_type': vuln_type,
                                'context': 'polyglot',
                                'payload': payload[:150],
                                'confidence': confidence,
                                'response_code': resp.status_code,
                                'detection_method': 'polyglot_payload',
                                'timestamp': datetime.now().isoformat()
                            })
                            
        except Exception:
            pass
            
        return findings
        
    def _test_mutation_payloads(self, triage, ip, port, target_info):
        """Test mutated payloads using genetic algorithm principles"""
        findings = []
        
        try:
            # Select successful payloads for mutation
            base_payloads = [
                "' OR 1=1 --",
                "<script>alert(1)</script>", 
                "; id",
                "{{7*7}}"
            ]
            
            for base_payload in base_payloads:
                mutations = self.payload_generator.generate_mutation_payloads(
                    base_payload,
                    generations=self.detection_config['max_generations']
                )
                
                for mutation in mutations[:10]:  # Limit mutations to prevent overload
                    resp = triage.http_request(ip, port, uri=f'/?mutation={mutation}')
                    
                    if resp:
                        # Analyze response for any vulnerability indicators
                        overall_confidence = self._analyze_mutation_response(resp.text)
                        
                        if overall_confidence > 0.7:
                            findings.append({
                                'vulnerability_type': 'mutation_detected',
                                'context': 'genetic_algorithm',
                                'payload': mutation[:100],
                                'base_payload': base_payload,
                                'confidence': overall_confidence,
                                'detection_method': 'mutation_testing',
                                'timestamp': datetime.now().isoformat()
                            })
                            
        except Exception:
            pass
            
        return findings
        
    def _analyze_mutation_response(self, response_text):
        """Analyze response from mutation testing"""
        confidence_indicators = [
            (r'error|exception|warning', 0.3),
            (r'sql.*error|mysql.*error|ora-\d+', 0.7),
            (r'<script.*>|javascript:', 0.8),
            (r'root:x:0:0|uid=\d+', 0.9),
            (r'49|7\*7', 0.6),  # Template injection result
        ]
        
        max_confidence = 0.0
        
        for pattern, confidence in confidence_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                max_confidence = max(max_confidence, confidence)
                
        return max_confidence
        
    def _test_adaptive_payloads(self, triage, ip, port, target_info):
        """Test context-aware adaptive payloads"""
        findings = []
        
        try:
            # Generate context-aware payloads based on initial response
            initial_resp = triage.http_request(ip, port)
            if not initial_resp:
                return findings
                
            context_payloads = self.payload_generator.generate_context_aware_payloads(
                initial_resp.headers,
                initial_resp.text,
                'adaptive'
            )
            
            for payload in context_payloads:
                resp = triage.http_request(ip, port, uri=f'/?adaptive={payload}')
                
                if resp:
                    # Compare with baseline to detect anomalies
                    anomaly_score = self._calculate_response_anomaly(
                        initial_resp, resp
                    )
                    
                    if anomaly_score > 0.75:
                        findings.append({
                            'vulnerability_type': 'adaptive_anomaly',
                            'context': 'context_aware',
                            'payload': payload[:100],
                            'confidence': anomaly_score,
                            'anomaly_score': anomaly_score,
                            'detection_method': 'adaptive_testing',
                            'timestamp': datetime.now().isoformat()
                        })
                        
        except Exception:
            pass
            
        return findings
        
    def _calculate_response_anomaly(self, baseline_resp, test_resp):
        """Calculate anomaly score by comparing responses"""
        anomaly_score = 0.0
        
        # Status code changes
        if baseline_resp.status_code != test_resp.status_code:
            anomaly_score += 0.3
            
        # Significant size difference
        size_diff = abs(len(test_resp.text) - len(baseline_resp.text))
        if size_diff > len(baseline_resp.text) * 0.5:
            anomaly_score += 0.4
            
        # Response time difference
        time_diff = abs(test_resp.elapsed.total_seconds() - baseline_resp.elapsed.total_seconds())
        if time_diff > 2.0:  # More than 2 seconds difference
            anomaly_score += 0.3
            
        return min(1.0, anomaly_score)
        
    def _test_evasion_payloads(self, triage, ip, port, target_info):
        """Test payloads with various evasion techniques"""
        findings = []
        
        evasion_payloads = [
            # WAF evasion techniques
            "' /*!50000OR*/ 1=1 --",
            "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
            "; /bin/cat /etc/passwd",
            "{{7*'7'}}",
            "../%2e%2e/%2e%2e/etc/passwd"
        ]
        
        for payload in evasion_payloads:
            try:
                resp = triage.http_request(ip, port, uri=f'/?evasion={payload}')
                
                if resp:
                    # Check for evasion success
                    for vuln_type, patterns in self.success_indicators.items():
                        confidence = self._calculate_confidence(resp.text, patterns)
                        
                        if confidence > 0.8:  # High threshold for evasion
                            findings.append({
                                'vulnerability_type': vuln_type,
                                'context': 'evasion_testing',
                                'payload': payload[:100],
                                'confidence': confidence,
                                'detection_method': 'evasion_bypass',
                                'timestamp': datetime.now().isoformat()
                            })
                            
            except Exception:
                continue
                
        return findings
        
    def _store_advanced_findings(self, ip, port, domain, findings):
        """Store advanced payload testing findings"""
        if not findings:
            return
            
        # Group findings by vulnerability type
        vuln_summary = {}
        for finding in findings:
            vuln_type = finding['vulnerability_type']
            if vuln_type not in vuln_summary:
                vuln_summary[vuln_type] = []
            vuln_summary[vuln_type].append(finding)
            
        # Create detailed report
        details = "Advanced Payload Generation Results:\n\n"
        
        for vuln_type, vuln_findings in vuln_summary.items():
            details += f"🎯 {vuln_type.upper()} VULNERABILITIES:\n"
            
            # Show top 3 highest confidence findings
            sorted_findings = sorted(vuln_findings, key=lambda x: x['confidence'], reverse=True)
            
            for i, finding in enumerate(sorted_findings[:3], 1):
                details += f"  {i}. Confidence: {finding['confidence']:.2f}\n"
                details += f"     Method: {finding['detection_method']}\n"
                details += f"     Context: {finding['context']}\n"
                details += f"     Payload: {finding['payload'][:50]}...\n"
                if 'response_code' in finding:
                    details += f"     Response: HTTP {finding['response_code']}\n"
                details += f"     Time: {finding['timestamp']}\n\n"
                
        # Summary statistics
        total_vulns = len(findings)
        high_confidence = len([f for f in findings if f['confidence'] > 0.8])
        unique_types = len(vuln_summary)
        
        details += f"📊 SUMMARY:\n"
        details += f"  Total vulnerabilities found: {total_vulns}\n"
        details += f"  High-confidence detections: {high_confidence}\n"
        details += f"  Vulnerability types: {unique_types}\n"
        details += f"  Analysis timestamp: {datetime.now().isoformat()}\n"
        
        # Payload generation statistics
        payload_stats = self.payload_generator.get_payload_statistics()
        details += f"\n🔧 PAYLOAD GENERATION STATS:\n"
        details += f"  Payload types available: {payload_stats['total_payload_types']}\n"
        details += f"  Base templates: {payload_stats['total_base_templates']}\n"
        details += f"  Encoding techniques: {payload_stats['encoding_techniques']}\n"
        
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