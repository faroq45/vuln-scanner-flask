import asyncio
import sys
import os
from urllib.parse import urlparse
import json
from core.logging import logger
from core.redis import rds

class URLScanner:
    """URL-based vulscanner using OWASP scanner modules."""

    def __init__(self):
        self.logger = logger

    def scan_urls(self, urls, ScanConfig):
        """Scan provided URLs for vulnerabilities."""
        try:
            # Add scanner path for OWASP modules
            scanner_path = os.path.join(os.path.dirname(__file__), '..', 'scanner', 'scanner')
            if scanner_path not in sys.path:
                sys.path.insert(0, scanner_path)

            # Try to import OWASP scanner
            try:
                from scanner.scanner.core.scanner_engine import VulnerabilityScanner
                from scanner.scanner.core import ScanConfig


                # Run async scanning
                results = asyncio.run(self._async_scan_urls(urls, ScanConfig))
                return results

            except ImportError as e:
                self.logger.warning(f"OWASP scanner not available: {e}")
                # Fallback to basic URL validation and simple checks
                return self._basic_url_scan(urls, ScanConfig)

        except Exception as e:
            self.logger.error(f"Error in URL scanning: {e}")
            return None

    async def _async_scan_urls(self, urls, ScanConfig):
        """Async OWASP scanner implementation."""
        from scanner.scanner.core.scanner_engine import VulnerabilityScanner
        from scanner.scanner.core import ScanConfig

        all_results = []

        for url in urls:
            try:
                self.logger.info(f"Starting OWASP scan of {url}")

                # Create OWASP scan configuration
                owasp_config = ScanConfig(
                    target=url,
                    max_pages=10,
                    concurrency=2,
                    timeout=10,
                    checks=[
                        'security_headers',
                        'reflected_xss',
                        'sql_injection',
                        'directory_traversal',
                        'open_redirect'
                    ]
                )

                # Initialize and run scanner
                scanner = VulnerabilityScanner()
                results = await scanner.scan(owasp_config)

                # Process results and store in Redis
                if results and results.get('findings'):
                    for finding in results['findings']:
                        vuln_data = {
                            'ip': urlparse(url).netloc,
                            'port': 443 if url.startswith('https') else 80,
                            'rule_id': f"owasp_{finding.get('id', 'unknown')}",
                            'rule_details': finding.get('title', 'Unknown vulnerability'),
                            'rule_sev': self._map_severity(finding.get('severity', 'Low')),
                            'rule_desc': finding.get('description', ''),
                            'evidence': finding.get('evidence', ''),
                            'url': url,
                            'owasp_category': finding.get('owasp_category', ''),
                            'cwe': finding.get('cwe', 0)
                        }
                                                # --- attempt to attach HTTP evidence if present in finding ---
                        raw_output = None
                        poc = None
                        try:
                            # common keys detectors might use
                            candidate_resp = finding.get('response') or finding.get('http_response') or finding.get('resp')
                            if candidate_resp:
                                # candidate_resp might already be a string or a requests-like object
                                if isinstance(candidate_resp, str):
                                    body_str = candidate_resp
                                else:
                                    # best-effort: requests.Response style
                                    body_str = getattr(candidate_resp, "text", None) or getattr(candidate_resp, "content", None)
                                    if body_str is not None and not isinstance(body_str, str):
                                        try:
                                            body_str = body_str.decode("utf-8", "replace")
                                        except Exception:
                                            body_str = str(body_str)
                                if body_str:
                                    raw_output = body_str if len(body_str) <= 20000 else (body_str[:20000] + "\n...[truncated]")
                                # try build basic PoC
                                try:
                                    req_obj = getattr(candidate_resp, "request", None)
                                    req_line = ""
                                    if req_obj is not None:
                                        method = getattr(req_obj, "method", "") or ""
                                        url_req = getattr(req_obj, "url", "") or getattr(req_obj, "path_url", "")
                                        req_line = f"{method} {url_req}"
                                    poc = {
                                        "request": req_line,
                                        "status_code": getattr(candidate_resp, "status_code", None),
                                        "response_snippet": (raw_output[:2000] if raw_output else None)
                                    }
                                except Exception:
                                    poc = None
                        except Exception:
                            raw_output = None
                            poc = None

                        # attach to vuln_data
                        vuln_data['raw_output'] = raw_output
                        vuln_data['proof_of_concept'] = json.dumps(poc, default=str) if poc is not None else None

                        # finally store
                        rds.store_vuln(vuln_data)



                all_results.append(results)
                self.logger.info(f"Completed scan of {url}: {len(results.get('findings', []))} vulnerabilities found")

            except Exception as e:
                self.logger.error(f"Error scanning {url}: {e}")
                continue

        return all_results

    def _basic_url_scan(self, urls, scan_config):
        """Basic URL scanning when OWASP scanner is not available."""
        import requests
        import urllib3
        from urllib.parse import urlparse

        # Suppress SSL warnings for testing
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        results = []

        for url in urls:
            try:
                self.logger.info(f"Starting basic scan of {url}")

                # Basic HTTP checks
                response = requests.get(url, timeout=10, verify=False)
                parsed_url = urlparse(url)

                # Basic security header checks
                security_headers = {
                    'X-Frame-Options': 'Missing X-Frame-Options header',
                    'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                    'X-XSS-Protection': 'Missing X-XSS-Protection header',
                    'Strict-Transport-Security': 'Missing HSTS header',
                    'Content-Security-Policy': 'Missing CSP header'
                }

                # Check for missing security headers
                for header, description in security_headers.items():
                    if header not in response.headers:
                        vuln_data = {
                            'ip': parsed_url.netloc,
                            'port': 443 if url.startswith('https') else 80,
                            'rule_id': f"basic_header_{header.lower().replace('-', '_')}",
                            'rule_details': description,
                            'rule_sev': 2,  # Medium severity
                            'rule_desc': f'The {header} security header is missing',
                            'evidence': f'Header {header} not found in response',
                            'url': url
                        }
                                        # attach raw response & PoC to vuln_data
                try:
                    body = response.text if hasattr(response, "text") else (response.content.decode("utf-8","replace") if hasattr(response, "content") else None)
                    raw_output = body if (body and len(body) <= 20000) else (body[:20000] + "\n...[truncated]") if body else None
                    req_line = f"GET {response.request.url}" if getattr(response, "request", None) is not None else f"GET {url}"
                    poc = {"request": req_line, "status_code": getattr(response, "status_code", None), "response_snippet": (raw_output[:2000] if raw_output else None)}
                except Exception:
                    raw_output = None
                    poc = None

                vuln_data['raw_output'] = raw_output
                vuln_data['proof_of_concept'] = json.dumps(poc, default=str) if poc is not None else None

                rds.store_vuln(vuln_data)


                # Check for HTTPS
                if not url.startswith('https://'):
                    vuln_data = {
                        'ip': parsed_url.netloc,
                        'port': 80,
                        'rule_id': 'basic_no_https',
                        'rule_details': 'No HTTPS encryption',
                        'rule_sev': 3,  # High severity
                        'rule_desc': 'The website does not use HTTPS encryption',
                        'evidence': f'URL accessed over HTTP: {url}',
                        'url': url
                    }
                    rds.store_vuln(vuln_data)

                # Basic information disclosure check
                server_header = response.headers.get('Server', '')
                if server_header:
                    vuln_data = {
                        'ip': parsed_url.netloc,
                        'port': 443 if url.startswith('https') else 80,
                        'rule_id': 'basic_server_disclosure',
                        'rule_details': 'Server information disclosure',
                        'rule_sev': 1,  # Low severity
                        'rule_desc': 'Server header reveals information about the web server',
                        'evidence': f'Server header: {server_header}',
                        'url': url
                    }
                    rds.store_vuln(vuln_data)

                result = {
                    'status': 'completed',
                    'target': url,
                    'basic_scan': True,
                    'response_code': response.status_code
                }
                results.append(result)

                self.logger.info(f"Completed basic scan of {url}")

            except Exception as e:
                self.logger.error(f"Error in basic scan of {url}: {e}")
                continue

        return results

    def _map_severity(self, severity_str):
        """Map OWASP severity strings to numeric values."""
        severity_map = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1
        }
        return severity_map.get(severity_str, 1)

    def get_urls_to_scan(self):
        """Get URLs from Redis that need to be scanned."""
        urls = []
        try:
            for key in rds.r.scan_iter(match="url_*"):
                url = rds.r.get(key)
                if url:
                    if isinstance(url, bytes):
                        url = url.decode('utf-8')
                    urls.append(url)
                    rds.r.delete(key)  # Remove from queue after getting
        except Exception as e:
            self.logger.error(f"Error getting URLs from Redis: {e}")

        return urls
