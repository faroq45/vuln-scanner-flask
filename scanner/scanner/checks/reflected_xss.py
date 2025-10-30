import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urlencode, parse_qs, urlparse, parse_qsl
from core import Finding
from checks.base import BaseCheck


class ReflectedXSSCheck(BaseCheck):
    """Check for reflected XSS vulnerabilities."""
    
    name = "reflected_xss"
    
    # XSS test payloads - safe for detection purposes
    XSS_PAYLOADS = [
        # Basic reflection tests
        "SCAN_XSS_TEST_12345",  # Simple unique marker
        "<SCAN_XSS_TEST_67890>",  # HTML tag test
        '"SCAN_XSS_TEST_QUOTES"',  # Quote test
        "'SCAN_XSS_TEST_SINGLE'",  # Single quote test
        
        # Common XSS vectors (for detection only)
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        
        # Event handlers
        "onmouseover=alert('XSS')",
        "onfocus=alert('XSS')",
        
        # HTML attribute injection
        '" onmouseover="alert(1)"',
        "' onmouseover='alert(1)'",
        
        # URL schemes
        "data:text/html,<script>alert('XSS')</script>",
    ]
    
    # Context-aware encoding checks
    HTML_CONTEXTS = [
        r'<[^>]*SCAN_XSS_TEST_\d+[^>]*>',  # HTML tag context
        r'>SCAN_XSS_TEST_\d+<',  # Between tags
        r'"SCAN_XSS_TEST_\d+"',  # Attribute value
        r"'SCAN_XSS_TEST_\d+'",  # Single-quoted attribute
    ]
    
    def __init__(self):
        super().__init__()
        self.tested_params = set()
    
    async def run(self, url: str, response: Dict[str, Any], http_client) -> List[Finding]:
        """Check for reflected XSS vulnerabilities."""
        findings = []
        
        try:
            # Test query parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                findings.extend(await self._test_query_params(url, http_client))
            
            # Test form parameters
            if response.get('text'):
                findings.extend(await self._test_form_params(url, response['text'], http_client))
            
        except Exception as e:
            self.logger.error(f"Error in XSS check for {url}: {e}")
        
        return findings
    
    async def _test_query_params(self, url: str, http_client) -> List[Finding]:
        """Test XSS in URL query parameters."""
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
            
            # Test each XSS payload
            for payload in self.XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                if test_params:
                    test_url += "?" + urlencode(test_params)
                
                try:
                    response = await http_client.get(test_url)
                    
                    if response and response.text:
                        xss_result = self._analyze_response_for_xss(
                            response.text, payload, url, param_name
                        )
                        
                        if xss_result:
                            finding = Finding(
                                id="",
                                target="",
                                url=test_url,
                                title="Reflected XSS Vulnerability",
                                severity=xss_result['severity'],
                                description="User input is reflected without proper encoding",
                                evidence=xss_result['evidence'],
                                confidence=xss_result['confidence'],
                                cwe=79,
                                param=param_name,
                                payload=payload,
                                request=f"GET {test_url}",
                                response_snippet=xss_result['snippet']
                            )
                            
                            findings.append(finding)
                            self.logger.info(f"XSS found in parameter {param_name} at {url}")
                            break  # Found vulnerability, no need to test more payloads
                
                except Exception as e:
                    self.logger.error(f"Error testing XSS payload: {e}")
                    continue
                
                # Rate limiting
                await asyncio.sleep(0.1)
        
        return findings
    
    async def _test_form_params(self, url: str, html_content: str, http_client) -> List[Finding]:
        """Test XSS in form parameters."""
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
                
                # Test XSS payloads (use fewer on forms)
                for payload in self.XSS_PAYLOADS[:5]:
                    form_data = {input_name: payload}
                    
                    try:
                        response = await http_client.post(form_url, data=form_data)
                        
                        if response and response.text:
                            xss_result = self._analyze_response_for_xss(
                                response.text, payload, form_url, input_name
                            )
                            
                            if xss_result:
                                finding = Finding(
                                    id="",
                                    target="",
                                    url=form_url,
                                    title="Reflected XSS in Form",
                                    severity=xss_result['severity'],
                                    description="Form input reflected without encoding",
                                    evidence=xss_result['evidence'],
                                    confidence=xss_result['confidence'],
                                    cwe=79,
                                    param=input_name,
                                    payload=payload,
                                    request=f"POST {form_url}",
                                    response_snippet=xss_result['snippet']
                                )
                                
                                findings.append(finding)
                                break
                    
                    except Exception as e:
                        self.logger.error(f"Error testing form XSS: {e}")
                        continue
                    
                    await asyncio.sleep(0.1)
        
        return findings
    
    def _analyze_response_for_xss(self, response_text: str, payload: str, url: str, param: str) -> Dict[str, Any]:
        """Analyze response for XSS indicators."""
        
        # Check if payload is reflected in response
        if payload in response_text:
            # Find the context where payload is reflected
            payload_index = response_text.find(payload)
            snippet = response_text[max(0, payload_index-100):payload_index+len(payload)+100]
            
            # Determine context and severity
            context = self._determine_xss_context(response_text, payload)
            severity = self._assess_xss_severity(payload, context)
            confidence = self._assess_xss_confidence(payload, context, response_text)
            
            return {
                'evidence': f"Parameter '{param}' reflects payload '{payload}' in {context} context",
                'confidence': confidence,
                'snippet': snippet,
                'severity': severity,
                'context': context
            }
        
        # Check for successful XSS execution indicators
        xss_indicators = [
            r'<script[^>]*>.*alert\s*\(',  # Script execution
            r'onerror\s*=\s*["\']?alert\s*\(',  # Event handler
            r'onload\s*=\s*["\']?alert\s*\(',
            r'javascript:\s*alert\s*\(',  # JavaScript URL scheme
        ]
        
        for pattern in xss_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                match = re.search(pattern, response_text, re.IGNORECASE)
                snippet = response_text[max(0, match.start()-100):match.end()+100]
                
                return {
                    'evidence': f"XSS payload execution detected in response",
                    'confidence': 95,
                    'snippet': snippet,
                    'severity': 'High',
                    'context': 'executable'
                }
        
        return None
    
    def _determine_xss_context(self, response_text: str, payload: str) -> str:
        """Determine the context where XSS payload was reflected."""
        
        # Find payload location in response
        payload_index = response_text.find(payload)
        if payload_index == -1:
            return 'unknown'
        
        # Get surrounding context (200 chars before and after)
        start = max(0, payload_index - 200)
        end = min(len(response_text), payload_index + len(payload) + 200)
        context = response_text[start:end]
        
        # Analyze context
        if re.search(r'<script[^>]*>' + re.escape(payload), response_text, re.IGNORECASE):
            return 'script'
        elif re.search(r'<[^>]*' + re.escape(payload) + r'[^>]*>', response_text):
            return 'attribute'
        elif re.search(r'>[^<]*' + re.escape(payload) + r'[^<]*<', response_text):
            return 'html_body'
        elif 'javascript:' in context.lower():
            return 'javascript_url'
        else:
            return 'html'
    
    def _assess_xss_severity(self, payload: str, context: str) -> str:
        """Assess XSS severity based on payload and context."""
        
        if context in ['script', 'javascript_url']:
            return 'High'
        elif 'alert(' in payload or 'eval(' in payload:
            return 'High'  
        elif context == 'attribute' and any(event in payload.lower() for event in ['onclick', 'onload', 'onerror']):
            return 'High'
        elif context == 'html_body':
            return 'Medium'
        else:
            return 'Medium'
    
    def _assess_xss_confidence(self, payload: str, context: str, response_text: str) -> int:
        """Assess confidence level of XSS detection."""
        
        confidence = 70  # Base confidence
        
        # Higher confidence for exact payload matches
        if payload in response_text:
            confidence += 20
        
        # Higher confidence for dangerous contexts
        if context in ['script', 'javascript_url']:
            confidence += 10
        
        # Lower confidence for simple string reflections
        if payload.startswith('SCAN_XSS_TEST_'):
            confidence -= 10
        
        # Higher confidence for executable payloads
        if any(keyword in payload.lower() for keyword in ['alert', 'eval', 'script']):
            confidence += 10
        
        return min(100, max(50, confidence))