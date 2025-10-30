import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urlencode, parse_qs, urlparse, parse_qsl
from core import Finding
from checks.base import BaseCheck


class SQLInjectionCheck(BaseCheck):
    """Check for SQL injection vulnerabilities."""
    
    name = "sql_injection"
    
    # Safe SQL injection payloads for detection (non-destructive)
    SQL_PAYLOADS = [
        # Error-based detection
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' AND '1'='2",
        "' UNION SELECT NULL--",
        "'; WAITFOR DELAY '00:00:01'--",
        "' OR 1=1#",
        "admin'--",
        "' OR 'x'='x",
        "1' AND SLEEP(1)#",
        "1' OR '1'='1' /*",
        
        # Time-based detection (very short delays)
        "'; SELECT pg_sleep(0.1)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(0.1)))a)--",
        
        # Union-based detection
        "' UNION SELECT 'SQLI_TEST_12345'--",
        "\" UNION SELECT 'SQLI_TEST_12345'--",
        
        # Boolean-based detection
        "' AND 1=1--",
        "' AND 1=2--",
    ]
    
    # Database error patterns
    ERROR_PATTERNS = [
        # MySQL
        r"You have an error in your SQL syntax",
        r"mysql_fetch_array\(\)",
        r"mysql_fetch_assoc\(\)",
        r"mysql_num_rows\(\)",
        r"supplied argument is not a valid MySQL",
        
        # PostgreSQL
        r"PostgreSQL.*ERROR",
        r"pg_query\(\)",
        r"pg_exec\(\)",
        
        # Microsoft SQL Server
        r"Microsoft OLE DB Provider for ODBC Drivers",
        r"Unclosed quotation mark after the character string",
        r"Microsoft JET Database Engine",
        r"\[SQL Server\]",
        
        # Oracle
        r"ORA-[0-9]+",
        r"Oracle error",
        r"Oracle.*Driver",
        
        # SQLite
        r"SQLite/JDBCDriver",
        r"sqlite3.OperationalError",
        
        # General
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"syntax error at or near",
        r"unterminated quoted string",
    ]
    
    def __init__(self):
        super().__init__()
        self.tested_params = set()
        self.baseline_responses = {}
    
    async def run(self, url: str, response: Dict[str, Any], http_client) -> List[Finding]:
        """Run SQL injection check on the given URL."""
        findings = []
        
        try:
            # Store baseline response for comparison
            self.baseline_responses[url] = response
            
            # Test query parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                findings.extend(await self._test_query_params(url, http_client))
            
            # Test form parameters
            if response.get('text'):
                findings.extend(await self._test_form_params(url, response['text'], http_client))
            
        except Exception as e:
            self.logger.error(f"Error in SQL injection check for {url}: {e}")
        
        return findings
    
    async def _test_query_params(self, url: str, http_client) -> List[Finding]:
        """Test SQL injection in URL query parameters."""
        findings = []
        parsed_url = urlparse(url)
        
        if not parsed_url.query:
            return findings
        
        params = dict(parse_qsl(parsed_url.query))
        
        for param_name, param_value in params.items():
            param_key = f"{parsed_url.netloc}_{param_name}"
            
            if param_key in self.tested_params:
                continue
            
            self.tested_params.add(param_key)
            
            # Test each payload
            for payload in self.SQL_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                if test_params:
                    test_url += "?" + urlencode(test_params)
                
                try:
                    response = await http_client.get(test_url)
                    
                    if response and response.text:
                        vulnerability = self._analyze_response_for_sqli(
                            response, payload, url, param_name
                        )
                        
                        if vulnerability:
                            finding = Finding(
                                id="",
                                target="",
                                url=test_url,
                                title="SQL Injection Vulnerability",
                                severity=vulnerability['severity'],
                                description=vulnerability['description'],
                                evidence=vulnerability['evidence'],
                                confidence=vulnerability['confidence'],
                                cwe=89,
                                param=param_name,
                                payload=payload,
                                request=f"GET {test_url}",
                                response_snippet=vulnerability['snippet']
                            )
                            
                            findings.append(finding)
                            self.logger.info(f"SQL injection found in parameter {param_name} at {url}")
                            break  # Found vulnerability, no need to test more payloads
                
                except Exception as e:
                    self.logger.error(f"Error testing SQL injection payload: {e}")
                    continue
                
                # Rate limiting between requests
                await asyncio.sleep(0.1)
        
        return findings
    
    async def _test_form_params(self, url: str, html_content: str, http_client) -> List[Finding]:
        """Test SQL injection in form parameters."""
        findings = []
        
        # Simple form detection
        form_pattern = r'<form[^>]*action=[\'"]*([^\'">\s]*)[^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, html_content, re.IGNORECASE | re.DOTALL)
        
        for form_action, form_content in forms:
            input_pattern = r'<input[^>]*name=[\'"]*([^\'">\s]*)[^>]*>'
            input_names = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            if not input_names:
                continue
            
            # Resolve form action URL
            if form_action.startswith('http'):
                form_url = form_action
            else:
                parsed_url = urlparse(url)
                if form_action.startswith('/'):
                    form_url = f"{parsed_url.scheme}://{parsed_url.netloc}{form_action}"
                else:
                    form_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}/{form_action}"
            
            # Test each input field
            for input_name in input_names:
                param_key = f"{urlparse(form_url).netloc}_form_{input_name}"
                
                if param_key in self.tested_params:
                    continue
                
                self.tested_params.add(param_key)
                
                # Test SQL injection payloads
                for payload in self.SQL_PAYLOADS[:5]:  # Test fewer payloads on forms
                    form_data = {input_name: payload}
                    
                    try:
                        response = await http_client.post(form_url, data=form_data)
                        
                        if response and response.text:
                            vulnerability = self._analyze_response_for_sqli(
                                response, payload, form_url, input_name
                            )
                            
                            if vulnerability:
                                finding = Finding(
                                    id="",
                                    target="",
                                    url=form_url,
                                    title="SQL Injection in Form",
                                    severity=vulnerability['severity'],
                                    description=vulnerability['description'],
                                    evidence=vulnerability['evidence'],
                                    confidence=vulnerability['confidence'],
                                    cwe=89,
                                    param=input_name,
                                    payload=payload,
                                    request=f"POST {form_url}",
                                    response_snippet=vulnerability['snippet']
                                )
                                
                                findings.append(finding)
                                break
                    
                    except Exception as e:
                        self.logger.error(f"Error testing form SQL injection: {e}")
                        continue
                    
                    await asyncio.sleep(0.1)
        
        return findings
    
    def _analyze_response_for_sqli(self, response, payload: str, url: str, param: str) -> Dict[str, Any]:
        """Analyze response for SQL injection indicators."""
        response_text = response.text
        status_code = response.status_code
        
        # Check for database errors
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                error_match = re.search(pattern, response_text, re.IGNORECASE)
                error_snippet = response_text[max(0, error_match.start()-100):error_match.end()+100]
                
                return {
                    'severity': 'High',
                    'description': f'SQL error message detected in response to injection payload',
                    'evidence': f'Database error: {error_match.group()}',
                    'confidence': 95,
                    'snippet': error_snippet,
                    'type': 'error_based'
                }
        
        # Check for test marker in response (union-based)
        if 'SQLI_TEST_12345' in response_text:
            marker_index = response_text.find('SQLI_TEST_12345')
            snippet = response_text[max(0, marker_index-100):marker_index+200]
            
            return {
                'severity': 'High',
                'description': 'Union-based SQL injection detected',
                'evidence': 'Test marker "SQLI_TEST_12345" found in response',
                'confidence': 90,
                'snippet': snippet,
                'type': 'union_based'
            }
        
        # Check for time-based delays (basic heuristic)
        response_time = response.response_time
        if response_time > 1.0 and ('SLEEP' in payload.upper() or 'WAITFOR' in payload.upper()):
            return {
                'severity': 'Medium',
                'description': 'Possible time-based SQL injection detected',
                'evidence': f'Response time: {response_time:.2f}s with time-based payload',
                'confidence': 70,
                'snippet': f'Response time: {response_time:.2f} seconds',
                'type': 'time_based'
            }
        
        # Check for boolean-based differences
        baseline_response = self.baseline_responses.get(url)
        if baseline_response:
            baseline_text = baseline_response.get('text', '')
            
            # Compare response lengths and content
            length_diff = abs(len(response_text) - len(baseline_text))
            
            # Significant difference in response might indicate boolean-based SQLi
            if length_diff > 100:
                return {
                    'severity': 'Medium',
                    'description': 'Possible boolean-based SQL injection detected',
                    'evidence': f'Response length difference: {length_diff} characters',
                    'confidence': 60,
                    'snippet': f'Original length: {len(baseline_text)}, Modified length: {len(response_text)}',
                    'type': 'boolean_based'
                }
        
        return None