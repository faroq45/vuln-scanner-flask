"""
OWASP Top 10 VulScanner Core Module
"""
import time
from datetime import datetime
from typing import Optional, Dict, Any
from dataclasses import dataclass, field


@dataclass
class Finding:
    """Data class representing a security vulnerability finding."""
    
    id: str = ""
    target: str = ""
    url: str = ""
    title: str = ""
    severity: str = ""  # Critical, High, Medium, Low
    description: str = ""
    evidence: str = ""
    confidence: int = 0  # 0-100
    cwe: int = 0
    param: Optional[str] = None
    payload: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    request: Optional[str] = None
    response_snippet: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            'id': self.id,
            'target': self.target,
            'url': self.url,
            'title': self.title,
            'severity': self.severity,
            'description': self.description,
            'evidence': self.evidence,
            'confidence': self.confidence,
            'cwe': self.cwe,
            'param': self.param,
            'payload': self.payload,
            'timestamp': self.timestamp,
            'request': self.request,
            'response_snippet': self.response_snippet,
            'owasp_category': self.owasp_category,
            'remediation': self.remediation
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create finding from dictionary."""
        return cls(**data)


@dataclass
class ScanConfig:
    """Configuration for vulnerability scans."""
    
    target: str = ""
    max_pages: int = 20
    concurrency: int = 3
    timeout: int = 10
    user_agent: str = "OWASP-Scanner/1.0"
    respect_robots: bool = True
    max_depth: int = 3
    follow_redirects: bool = True
    max_redirects: int = 5
    exclude_extensions: list = field(default_factory=lambda: ['.jpg', '.png', '.gif', '.css', '.js', '.ico'])
    rate_limit_delay: float = 0.1
    checks: list = field(default_factory=list)


@dataclass 
class ScanStatus:
    """Status of a running scan."""
    
    target: str = ""
    status: str = "idle"  # idle, running, completed, failed
    progress: int = 0
    total_requests: int = 0
    findings_count: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    error_message: Optional[str] = None
    
    @property
    def duration(self) -> Optional[float]:
        """Get scan duration in seconds."""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        elif self.start_time:
            return time.time() - self.start_time
        return None
    
    @property
    def is_running(self) -> bool:
        """Check if scan is currently running."""
        return self.status == "running"
    
    @property
    def is_completed(self) -> bool:
        """Check if scan is completed."""
        return self.status in ["completed", "failed"]


# OWASP Top 10 2021 Categories
OWASP_CATEGORIES = {
    'A01_2021': 'Broken Access Control',
    'A02_2021': 'Cryptographic Failures', 
    'A03_2021': 'Injection',
    'A04_2021': 'Insecure Design',
    'A05_2021': 'Security Misconfiguration',
    'A06_2021': 'Vulnerable and Outdated Components',
    'A07_2021': 'Identification and Authentication Failures',
    'A08_2021': 'Software and Data Integrity Failures',
    'A09_2021': 'Security Logging and Monitoring Failures',
    'A10_2021': 'Server-Side Request Forgery (SSRF)'
}

# CWE to OWASP mapping
CWE_TO_OWASP = {
    79: 'A03_2021',   # XSS
    89: 'A03_2021',   # SQL Injection
    22: 'A03_2021',   # Path Traversal
    601: 'A01_2021',  # Open Redirect
    918: 'A10_2021',  # SSRF
    285: 'A01_2021',  # Broken Access Control
    287: 'A07_2021',  # Authentication Bypass
    200: 'A02_2021',  # Information Disclosure
    319: 'A05_2021',  # Security Misconfiguration
    1021: 'A05_2021', # Clickjacking
}


def get_owasp_category(cwe: int) -> Optional[str]:
    """Get OWASP category for a given CWE."""
    return CWE_TO_OWASP.get(cwe)


def get_severity_score(severity: str) -> int:
    """Convert severity to numeric score for sorting."""
    severity_map = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1
    }
    return severity_map.get(severity, 0)