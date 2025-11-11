from typing import List, Dict, Any
from scanner.scanner.core import Finding
from checks.base import BaseCheck


class SecurityHeadersCheck(BaseCheck):
    """Check for missing or misconfigured security headers."""

    name = "security_headers"

    REQUIRED_HEADERS = {
        'Content-Security-Policy': {
            'severity': 'Medium',
            'description': 'Content Security Policy (CSP) helps prevent XSS attacks',
            'cwe': 79,
        },
        'X-Frame-Options': {
            'severity': 'Medium',
            'description': 'X-Frame-Options prevents clickjacking attacks',
            'cwe': 1021,
        },
        'X-Content-Type-Options': {
            'severity': 'Low',
            'description': 'X-Content-Type-Options prevents MIME type sniffing',
            'cwe': 79,
        },
        'Strict-Transport-Security': {
            'severity': 'High',
            'description': 'HSTS enforces secure HTTPS connections',
            'cwe': 319,
        },
        'Referrer-Policy': {
            'severity': 'Low',
            'description': 'Referrer Policy controls referrer information',
            'cwe': 200,
        },
        'Permissions-Policy': {
            'severity': 'Low',
            'description': 'Permissions Policy controls browser features',
            'cwe': 285,
        }
    }

    INSECURE_HEADERS = {
        'Server': {
            'patterns': [r'Apache/[\d\.]+', r'nginx/[\d\.]+', r'Microsoft-IIS/[\d\.]+'],
            'severity': 'Low',
            'description': 'Server version information disclosed',
            'cwe': 200,
        },
        'X-Powered-By': {
            'patterns': ['*'],  # Any value is considered information disclosure
            'severity': 'Low',
            'description': 'Technology stack information disclosed',
            'cwe': 200,
        }
    }

    async def run(self, url: str, response: Dict[str, Any], http_client) -> List[Finding]:
        """Check security headers in the response."""
        findings = []

        try:
            headers = response.get('headers', {})

            # Convert headers to lowercase for case-insensitive comparison
            headers_lower = {k.lower(): v for k, v in headers.items()}

            # Check for missing security headers
            findings.extend(self._check_missing_headers(url, headers_lower))

            # Check for insecure header values
            findings.extend(self._check_insecure_headers(url, headers))

            # Check for misconfigured headers
            findings.extend(self._check_misconfigured_headers(url, headers_lower))

        except Exception as e:
            self.logger.error(f"Error in security headers check for {url}: {e}")

        return findings

    def _check_missing_headers(self, url: str, headers: Dict[str, str]) -> List[Finding]:
        """Check for missing security headers."""
        findings = []

        for header_name, config in self.REQUIRED_HEADERS.items():
            header_key = header_name.lower()

            if header_key not in headers:
                finding = Finding(
                    id="",
                    target="",
                    url=url,
                    title=f"Missing Security Header: {header_name}",
                    severity=config['severity'],
                    description=config['description'],
                    evidence=f"Required security header '{header_name}' is missing",
                    confidence=100,
                    cwe=config['cwe']
                )

                findings.append(finding)

        return findings

    def _check_insecure_headers(self, url: str, headers: Dict[str, str]) -> List[Finding]:
        """Check for headers that disclose sensitive information."""
        findings = []

        for header_name, config in self.INSECURE_HEADERS.items():
            if header_name in headers:
                header_value = headers[header_name]

                # Check if header value matches insecure patterns
                is_insecure = False
                if '*' in config['patterns']:
                    is_insecure = True
                else:
                    import re
                    for pattern in config['patterns']:
                        if re.search(pattern, header_value, re.IGNORECASE):
                            is_insecure = True
                            break

                if is_insecure:
                    finding = Finding(
                        id="",
                        target="",
                        url=url,
                        title=f"Information Disclosure: {header_name}",
                        severity=config['severity'],
                        description=config['description'],
                        evidence=f"Header '{header_name}' reveals: {header_value}",
                        confidence=100,
                        cwe=config['cwe']
                    )

                    findings.append(finding)

        return findings

    def _check_misconfigured_headers(self, url: str, headers: Dict[str, str]) -> List[Finding]:
        """Check for misconfigured security headers."""
        findings = []

        # Check CSP configuration
        csp = headers.get('content-security-policy')
        if csp:
            findings.extend(self._analyze_csp(url, csp))

        # Check X-Frame-Options
        xfo = headers.get('x-frame-options')
        if xfo and xfo.upper() not in ['DENY', 'SAMEORIGIN']:
            finding = Finding(
                id="",
                target="",
                url=url,
                title="Weak X-Frame-Options Configuration",
                severity="Medium",
                description="X-Frame-Options should be set to DENY or SAMEORIGIN",
                evidence=f"X-Frame-Options set to: {xfo}",
                confidence=100,
                cwe=1021
            )
            findings.append(finding)

        # Check HSTS configuration
        hsts = headers.get('strict-transport-security')
        if hsts and url.startswith('https://'):
            if 'max-age=' not in hsts.lower():
                finding = Finding(
                    id="",
                    target="",
                    url=url,
                    title="Incomplete HSTS Configuration",
                    severity="Medium",
                    description="HSTS header missing max-age directive",
                    evidence=f"HSTS header: {hsts}",
                    confidence=100,
                    cwe=319
                )
                findings.append(finding)

        return findings

    def _analyze_csp(self, url: str, csp: str) -> List[Finding]:
        """Analyze Content Security Policy for weaknesses."""
        findings = []

        csp_lower = csp.lower()

        # Check for unsafe-inline
        if "'unsafe-inline'" in csp_lower:
            finding = Finding(
                id="",
                target="",
                url=url,
                title="Unsafe CSP Configuration",
                severity="High",
                description="CSP allows unsafe-inline, which defeats XSS protection",
                evidence="CSP contains 'unsafe-inline' directive",
                confidence=100,
                cwe=79
            )
            findings.append(finding)

        # Check for unsafe-eval
        if "'unsafe-eval'" in csp_lower:
            finding = Finding(
                id="",
                target="",
                url=url,
                title="Unsafe CSP Configuration",
                severity="High",
                description="CSP allows unsafe-eval, which can enable code injection",
                evidence="CSP contains 'unsafe-eval' directive",
                confidence=100,
                cwe=79
            )
            findings.append(finding)

        # Check for wildcard sources
        if "* " in csp or " *" in csp or csp.startswith("*") or csp.endswith("*"):
            finding = Finding(
                id="",
                target="",
                url=url,
                title="Weak CSP Configuration",
                severity="Medium",
                description="CSP uses wildcard (*) which reduces security effectiveness",
                evidence="CSP contains wildcard source",
                confidence=90,
                cwe=79
            )
            findings.append(finding)

        return findings
