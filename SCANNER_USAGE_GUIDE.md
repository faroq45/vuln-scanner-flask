# Scanner Usage Guide

## Quick Start

The scan engine has been fixed and is now operational. Here's how to use it:

### Starting the Application

```bash
python main.py
```

The scanner will automatically initialize when the application starts.

### Using the OWASP Scanner via Web Interface

1. Navigate to `/owasp-scan` in your browser
2. Enter a target URL (e.g., `https://example.com`)
3. Configure scan options:
   - Max Pages: Number of pages to crawl (default: 20)
   - Concurrency: Number of concurrent requests (default: 3)
   - Timeout: Request timeout in seconds (default: 10)
4. Click "Start Scan"
5. Monitor scan progress on the results page

### Using the OWASP Scanner via API

#### Start a Scan

```bash
POST /api/owasp/start
Content-Type: application/json

{
  "target": "https://example.com",
  "maxPages": 20,
  "concurrency": 3,
  "timeout": 10,
  "checks": [
    "security_headers",
    "reflected_xss",
    "sql_injection",
    "directory_traversal",
    "open_redirect"
  ]
}
```

Response:
```json
{
  "success": true,
  "scan_id": "uuid-here",
  "message": "OWASP Top 10 scan started successfully"
}
```

#### Check Scan Status

```bash
GET /api/owasp/status/<scan_id>
```

Response:
```json
{
  "success": true,
  "status": "running",
  "progress": 50,
  "findings_count": 3
}
```

#### Get Scan Results

```bash
GET /api/owasp/results/<scan_id>
```

Response:
```json
{
  "success": true,
  "results": {
    "status": "completed",
    "target": "https://example.com",
    "duration": 15.5,
    "findings": [...],
    "summary": {
      "total_findings": 5,
      "critical_count": 0,
      "high_count": 1,
      "medium_count": 3,
      "low_count": 1
    }
  }
}
```

#### Cancel a Scan

```bash
POST /api/owasp/cancel/<scan_id>
```

### Using the URL Scanner (Legacy)

The URL scanner in `core/url_scanner.py` can also be used:

```python
from core.url_scanner import URLScanner

scanner = URLScanner()
urls = ["https://example.com", "https://test.com"]
results = scanner.scan_urls(urls, scan_config)
```

## Available Security Checks

The scanner supports the following OWASP Top 10 checks:

1. **security_headers** - Missing security headers
2. **reflected_xss** - Reflected XSS vulnerabilities
3. **sql_injection** - SQL injection vulnerabilities
4. **directory_traversal** - Path traversal vulnerabilities
5. **open_redirect** - Open redirect vulnerabilities
6. **ssrf** - Server-Side Request Forgery
7. **broken_access_control** - Access control issues
8. **authentication_bypass** - Authentication bypass attempts
9. **information_disclosure** - Information leakage
10. **security_misconfiguration** - Security configuration issues

## Troubleshooting

### Scanner Not Starting

Check the logs in `logs/` directory for error messages. Common issues:

1. **Event loop errors**: Fixed in this version - scanner now properly handles async operations
2. **Module import errors**: Ensure all dependencies are installed: `pip install -r requirements.txt`
3. **Redis connection**: Ensure Redis is running if using Redis backend

### Scans Timing Out

- Increase the `timeout` parameter
- Reduce `maxPages` for faster scans
- Check network connectivity to target

### No Findings Reported

- Target may not have detectable vulnerabilities
- Security checks may not have loaded (check logs for warnings)
- Target may be blocking scanner requests (check headers)

## Logging

Scanner logs include:
- Module initialization status
- Scan start/stop events
- Vulnerability findings
- Error messages with stack traces

Check logs at:
- Console output (stdout)
- Log files in `logs/` directory

## Performance Tips

1. **Concurrency**: Adjust based on your system resources
   - Low: 1-2 concurrent requests (safe, slow)
   - Medium: 3-5 concurrent requests (default)
   - High: 5-10 concurrent requests (fast, more resource intensive)

2. **Rate Limiting**: Controlled by `rateLimitDelay` (default: 0.1 seconds)
   - Increase for rate-limited targets
   - Decrease for faster scanning (may trigger rate limits)

3. **Page Limit**: Set `maxPages` based on site size
   - Small sites: 10-20 pages
   - Medium sites: 50-100 pages
   - Large sites: 100+ pages (may take significant time)

## Security Considerations

⚠️ **Important**: Only scan systems you own or have permission to test

- Scanner may trigger security alerts
- Some payloads may appear malicious to IDS/IPS systems
- Always get written permission before scanning production systems
- Use in controlled environments for testing

## Integration with Application

The scanner integrates with the main application:

1. **Worker Thread**: Scanner runs in background via `bin/scanner.py`
2. **Redis Queue**: URLs to scan are queued in Redis
3. **Results Storage**: Findings are stored in Redis and/or database
4. **Web Interface**: Results viewable through dashboard

## Next Steps

1. Run `python test_scanner.py` to verify functionality
2. Test with a safe target (your own test server)
3. Review scan results and configure checks as needed
4. Monitor logs during initial scans
5. Adjust parameters based on your requirements
