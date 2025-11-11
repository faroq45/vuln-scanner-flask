"""
OWASP Top 10 VulScanner Engine
"""
import asyncio
import logging
import time
import uuid
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from scanner.scanner.core import Finding, ScanConfig, ScanStatus,OWASP_CATEGORIES,CWE_TO_OWASP,get_owasp_category
from core.http_client import HttpClient, UrlCrawler
from checks.base import get_available_checks


class VulnerabilityScanner:
    """Main vulscanner engine."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.scan_status = ScanStatus()
        self.findings: List[Finding] = []
        self.http_client: Optional[HttpClient] = None
        self.url_crawler: Optional[UrlCrawler] = None
        self.security_checks = {}

        # Initialize security checks
        self._initialize_checks()

    def _initialize_checks(self):
        """Initialize available security checks."""
        try:
            available_checks = get_available_checks()
            for check in available_checks:
                self.security_checks[check.name] = check
                self.logger.info(f"Loaded security check: {check.name}")
        except Exception as e:
            self.logger.error(f"Failed to initialize security checks: {e}")

    async def scan(self, config: ScanConfig) -> Dict[str, Any]:
        """Run vulnerability scan with given configuration."""

        self.logger.info(f"Starting OWASP Top 10 scan of {config.target}")

        # Reset scan state
        self.findings.clear()
        self.scan_status = ScanStatus(
            target=config.target,
            status="running",
            start_time=time.time()
        )

        try:
            # Initialize HTTP client
            self.http_client = HttpClient(
                timeout=config.timeout,
                user_agent=config.user_agent,
                max_redirects=config.max_redirects,
                rate_limit_delay=config.rate_limit_delay
            )

            # Initialize URL crawler
            self.url_crawler = UrlCrawler(
                http_client=self.http_client,
                max_pages=config.max_pages,
                max_depth=config.max_depth,
                respect_robots=config.respect_robots,
                exclude_extensions=config.exclude_extensions
            )

            async with self.http_client:
                # Discover URLs to scan
                self.logger.info("Discovering URLs...")
                urls_to_scan = await self.url_crawler.crawl(config.target)

                if not urls_to_scan:
                    urls_to_scan = [config.target]  # Fallback to just the target URL

                self.logger.info(f"Found {len(urls_to_scan)} URLs to scan")
                self.scan_status.total_requests = len(urls_to_scan)

                # Scan each discovered URL
                for i, url in enumerate(urls_to_scan):
                    await self._scan_url(url, config)
                    self.scan_status.progress = int((i + 1) / len(urls_to_scan) * 100)
                    self.logger.debug(f"Scan progress: {self.scan_status.progress}%")

                # Complete scan
                self.scan_status.status = "completed"
                self.scan_status.end_time = time.time()
                self.scan_status.findings_count = len(self.findings)

                self.logger.info(f"Scan completed. Found {len(self.findings)} vulnerabilities")

                return self._generate_scan_results()

        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            self.scan_status.status = "failed"
            self.scan_status.error_message = str(e)
            self.scan_status.end_time = time.time()

            return self._generate_scan_results()

        finally:
            if self.http_client:
                await self.http_client.close()

    async def _scan_url(self, url: str, config: ScanConfig):
        """Scan a specific URL for vulnerabilities."""

        try:
            self.logger.debug(f"Scanning URL: {url}")

            # Get initial response
            response = await self.http_client.get(url)

            if not response:
                self.logger.warning(f"No response received for {url}")
                return

            # Convert response to dict format expected by checks
            response_dict = {
                'status_code': response.status_code,
                'headers': response.headers,
                'text': response.text,
                'url': response.url,
                'response_time': response.response_time
            }

            # Run selected security checks
            enabled_checks = config.checks if config.checks else list(self.security_checks.keys())

            for check_name in enabled_checks:
                if check_name in self.security_checks:
                    try:
                        check = self.security_checks[check_name]
                        findings = await check.run(url, response_dict, self.http_client)

                        # Process findings
                        for finding in findings:
                            finding.id = str(uuid.uuid4())
                            finding.target = config.target
                            finding.owasp_category = get_owasp_category(finding.cwe)

                            self.findings.append(finding)
                            self.logger.info(f"Found {finding.severity} vulnerability: {finding.title}")

                    except Exception as e:
                        self.logger.error(f"Error running check {check_name} on {url}: {e}")

                else:
                    self.logger.warning(f"Unknown security check: {check_name}")

        except Exception as e:
            self.logger.error(f"Error scanning URL {url}: {e}")

    def _generate_scan_results(self) -> Dict[str, Any]:
        """Generate scan results summary."""

        # Count findings by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for finding in self.findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1

        # Count findings by OWASP category
        owasp_counts = {}
        for finding in self.findings:
            if finding.owasp_category:
                category = finding.owasp_category
                owasp_counts[category] = owasp_counts.get(category, 0) + 1

        return {
            'status': self.scan_status.status,
            'target': self.scan_status.target,
            'start_time': self.scan_status.start_time,
            'end_time': self.scan_status.end_time,
            'duration': self.scan_status.duration,
            'error_message': self.scan_status.error_message,
            'findings': [finding.to_dict() for finding in self.findings],
            'summary': {
                'total_findings': len(self.findings),
                'critical_count': severity_counts['Critical'],
                'high_count': severity_counts['High'],
                'medium_count': severity_counts['Medium'],
                'low_count': severity_counts['Low'],
                'pages_scanned': self.scan_status.total_requests,
                'owasp_categories': owasp_counts
            }
        }

    def get_scan_status(self) -> Dict[str, Any]:
        """Get current scan status."""
        return {
            'status': self.scan_status.status,
            'progress': self.scan_status.progress,
            'target': self.scan_status.target,
            'findings_count': len(self.findings),
            'duration': self.scan_status.duration,
            'error_message': self.scan_status.error_message
        }


class ScanManager:
    """Manages multiple concurrent scans."""

    def __init__(self):
        self.active_scans: Dict[str, VulnerabilityScanner] = {}
        self.scan_results: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger(__name__)

    def start_scan(self, scan_id: str, config: ScanConfig) -> str:
        """Start a new vulnerability scan."""

        self.logger.info(f"Starting scan {scan_id} for target {config.target}")

        if scan_id in self.active_scans:
            raise ValueError(f"Scan {scan_id} is already running")

        scanner = VulnerabilityScanner()
        self.active_scans[scan_id] = scanner

        # Start scan in background with proper event loop handling
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._run_scan(scan_id, scanner, config))
        except RuntimeError:
            # No event loop running, create one
            import threading
            thread = threading.Thread(
                target=self._run_scan_in_new_loop,
                args=(scan_id, scanner, config),
                daemon=True
            )
            thread.start()

        return scan_id

    def _run_scan_in_new_loop(self, scan_id: str, scanner: VulnerabilityScanner, config: ScanConfig):
        """Run scan in a new event loop."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._run_scan(scan_id, scanner, config))
        finally:
            loop.close()

    async def _run_scan(self, scan_id: str, scanner: VulnerabilityScanner, config: ScanConfig):
        """Run scan and store results."""

        try:
            self.logger.info(f"Running scan task for {scan_id}")
            results = await scanner.scan(config)
            self.scan_results[scan_id] = results
            self.logger.info(f"Scan {scan_id} completed successfully")
        except Exception as e:
            self.logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            self.scan_results[scan_id] = {
                'status': 'failed',
                'error_message': str(e),
                'findings': [],
                'summary': {'total_findings': 0}
            }
        finally:
            # Remove from active scans
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
                self.logger.debug(f"Removed scan {scan_id} from active scans")

    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific scan."""

        if scan_id in self.active_scans:
            return self.active_scans[scan_id].get_scan_status()
        elif scan_id in self.scan_results:
            return {
                'status': self.scan_results[scan_id]['status'],
                'progress': 100,
                'findings_count': self.scan_results[scan_id]['summary']['total_findings']
            }
        else:
            return None

    def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get results of a completed scan."""
        return self.scan_results.get(scan_id)

    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an active scan."""

        if scan_id in self.active_scans:
            # Note: Proper cancellation would need more sophisticated async task management
            del self.active_scans[scan_id]
            return True
        return False


# Global scan manager instance
scan_manager = ScanManager()
