"""
HTTP Client for OWASP Top 10 VulScanner
"""
import asyncio
import json
import aiohttp
import time
import logging
from typing import Optional, Dict, Any, Union
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass

# ------------------ vulscanner evidence capture helpers ------------------
def _capture_response_info_sync(resp, max_body=20000, max_snippet=2000):
    """
    Best-effort: extract a string body and attach small PoC to the response object.
    Works for requests.Response and similar sync objects.
    """
    try:
        body = None
        # requests.Response has .text and .content
        if hasattr(resp, "text"):
            body = resp.text
        elif hasattr(resp, "content"):
            body = resp.content
            if isinstance(body, (bytes, bytearray)):
                body = body.decode("utf-8", "replace")

        if body is not None and not isinstance(body, str):
            body = str(body)

        raw_output = None
        if body:
            raw_output = body if len(body) <= max_body else (body[:max_body] + "\n...[truncated]")

        req_line = ""
        req_obj = getattr(resp, "request", None)
        if req_obj is not None:
            method = getattr(req_obj, "method", "") or ""
            url_req = getattr(req_obj, "url", "") or getattr(req_obj, "path_url", "")
            req_line = f"{method} {url_req}"

        status_code = getattr(resp, "status_code", getattr(resp, "status", None))
        poc = {
            "request": req_line,
            "status_code": status_code,
            "response_snippet": (raw_output[:max_snippet] if raw_output else None)
        }

        # attach as attributes (safe attach)
        try:
            setattr(resp, "_vulscanner_raw_output", raw_output)
            setattr(resp, "_vulscanner_poc", json.dumps(poc, default=str))
        except Exception:
            # fallback: ignore attach failure silently
            pass

    except Exception:
        # never raise from logger helpers
        pass


async def _capture_response_info_async(resp, max_body=20000, max_snippet=2000):
    """
    Async-aware capture: awaits resp.text() when needed (aiohttp).
    """
    try:
        body = None
        # aiohttp.ClientResponse.text is a coroutine
        text_attr = getattr(resp, "text", None)
        if text_attr and asyncio.iscoroutinefunction(text_attr):
            try:
                body = await resp.text()
            except Exception:
                # sometimes resp.text() fails if stream consumed; try content read
                try:
                    raw_c = await resp.read()
                    if isinstance(raw_c, (bytes, bytearray)):
                        body = raw_c.decode("utf-8", "replace")
                    else:
                        body = str(raw_c)
                except Exception:
                    body = None
        else:
            # fallback to sync properties
            if hasattr(resp, "text"):
                body = getattr(resp, "text")
            elif hasattr(resp, "content"):
                body = getattr(resp, "content")
                if isinstance(body, (bytes, bytearray)):
                    body = body.decode("utf-8", "replace")

        if body is not None and not isinstance(body, str):
            body = str(body)

        raw_output = None
        if body:
            raw_output = body if len(body) <= max_body else (body[:max_body] + "\n...[truncated]")

        req_line = ""
        req_obj = getattr(resp, "request", None)
        if req_obj is not None:
            method = getattr(req_obj, "method", "") or ""
            url_req = getattr(req_obj, "url", "") or getattr(req_obj, "path_url", "")
            req_line = f"{method} {url_req}"

        status_code = getattr(resp, "status", getattr(resp, "status_code", None))
        poc = {
            "request": req_line,
            "status_code": status_code,
            "response_snippet": (raw_output[:max_snippet] if raw_output else None)
        }

        try:
            setattr(resp, "_vulscanner_raw_output", raw_output)
            setattr(resp, "_vulscanner_poc", json.dumps(poc, default=str))
        except Exception:
            pass

    except Exception:
        pass
# ------------------ end helpers ------------------

@dataclass
class HttpResponse:
    """HTTP Response wrapper."""

    status_code: int
    headers: Dict[str, str]
    text: str
    url: str
    response_time: float
    history: list = None
    raw_output: Optional[str]=None
    proof_of_concept: Optional[str]=None


class HttpClient:
    """Async HTTP client for security scanning."""

    def __init__(self,
                 timeout: int = 10,
                 user_agent: str = "OWASP-Scanner/1.0",
                 max_redirects: int = 5,
                 rate_limit_delay: float = 0.1):

        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent = user_agent
        self.max_redirects = max_redirects
        self.rate_limit_delay = rate_limit_delay
        self.session = None
        self.logger = logging.getLogger(__name__)
        self.request_count = 0
        self.last_request_time = 0

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def start(self):
        """Initialize the HTTP session."""
        if self.session is None:
            connector = aiohttp.TCPConnector(
                limit=50,
                limit_per_host=10,
                ssl=False  # For testing purposes - in production, verify SSL
            )

            self.session = aiohttp.ClientSession(
                timeout=self.timeout,
                connector=connector,
                headers={'User-Agent': self.user_agent}
            )

    async def close(self):
        """Close the HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None

    async def _rate_limit(self):
        """Apply rate limiting between requests."""
        if self.rate_limit_delay > 0:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time

            if time_since_last < self.rate_limit_delay:
                await asyncio.sleep(self.rate_limit_delay - time_since_last)

            self.last_request_time = time.time()

    async def _make_request(self,
                           method: str,
                           url: str,
                           **kwargs) -> Optional[HttpResponse]:
        """Make HTTP request with error handling."""

        if not self.session:
            await self.start()

        await self._rate_limit()

        start_time = time.time()

        try:
            # Set default parameters
            params = {
                'allow_redirects': kwargs.get('allow_redirects', True),
                'max_redirects': kwargs.get('max_redirects', self.max_redirects),
                'ssl': False  # For testing - verify in production
            }

            # Add data for POST requests
            if 'data' in kwargs:
                params['data'] = kwargs['data']

            # Add custom headers
            if 'headers' in kwargs:
                params['headers'] = kwargs['headers']

            async with self.session.request(method, url, **params) as response:
                response_time = time.time() - start_time

                # Read response text with encoding fallback
                try:
                    text = await response.text()
                except UnicodeDecodeError:
                    try:
                        text = await response.text(encoding='latin-1')
                    except:
                        text = str(await response.read())
                try:
                    await _capture_response_info_async(response)
                except Exception:
                    pass

                # Convert headers to dict
                headers = dict(response.headers)

                # Get redirect history
                history = []
                if hasattr(response, 'history'):
                    history = [str(h.url) for h in response.history]

                self.request_count += 1

                raw_output = getattr(response, "_vulscanner_raw_output", None)
                poc = getattr(response, "_vulscanner_poc", None)

                return HttpResponse(
                    status_code=response.status,
                    headers=headers,
                    text=text,
                    url=str(response.url),
                    response_time=response_time,
                    history=history,
                    raw_output=raw_output,
                    proof_of_concept=poc
                )
            

        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout for {method} {url}")
            return None
        except aiohttp.ClientError as e:
            self.logger.warning(f"Client error for {method} {url}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error for {method} {url}: {e}")
            return None

    async def get(self, url: str, **kwargs) -> Optional[HttpResponse]:
        """Make GET request."""
        return await self._make_request('GET', url, **kwargs)

    async def post(self, url: str, **kwargs) -> Optional[HttpResponse]:
        """Make POST request."""
        return await self._make_request('POST', url, **kwargs)

    async def head(self, url: str, **kwargs) -> Optional[HttpResponse]:
        """Make HEAD request."""
        return await self._make_request('HEAD', url, **kwargs)

    async def options(self, url: str, **kwargs) -> Optional[HttpResponse]:
        """Make OPTIONS request."""
        return await self._make_request('OPTIONS', url, **kwargs)


class UrlCrawler:
    """URL crawler for discovering pages to scan."""

    def __init__(self,
                 http_client: HttpClient,
                 max_pages: int = 20,
                 max_depth: int = 3,
                 respect_robots: bool = True,
                 exclude_extensions: list = None):

        self.http_client = http_client
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.exclude_extensions = exclude_extensions or ['.jpg', '.png', '.gif', '.css', '.js', '.ico']
        self.visited_urls = set()
        self.found_urls = set()
        self.logger = logging.getLogger(__name__)

    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain."""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return domain1 == domain2
        except:
            return False

    def _should_exclude_url(self, url: str) -> bool:
        """Check if URL should be excluded from crawling."""
        try:
            parsed = urlparse(url)

            # Check file extension
            path = parsed.path.lower()
            for ext in self.exclude_extensions:
                if path.endswith(ext):
                    return True

            # Check for common non-HTML resources
            if any(keyword in path for keyword in ['/api/', '/ajax/', '.xml', '.json']):
                return True

            return False
        except:
            return True

    async def crawl(self, start_url: str) -> list:
        """Crawl website starting from given URL."""

        self.visited_urls.clear()
        self.found_urls.clear()

        urls_to_process = [(start_url, 0)]  # (url, depth)

        while urls_to_process and len(self.found_urls) < self.max_pages:
            url, depth = urls_to_process.pop(0)

            if url in self.visited_urls or depth > self.max_depth:
                continue

            if self._should_exclude_url(url):
                continue

            self.visited_urls.add(url)
            self.found_urls.add(url)

            try:
                response = await self.http_client.get(url)

                if not response or response.status_code != 200:
                    continue

                # Extract links from HTML
                if 'text/html' in response.headers.get('content-type', '').lower():
                    new_urls = self._extract_links(response.text, url)

                    # Add new URLs to process queue
                    for new_url in new_urls:
                        if (new_url not in self.visited_urls and
                            len(self.found_urls) < self.max_pages and
                            self._is_same_domain(start_url, new_url)):

                            urls_to_process.append((new_url, depth + 1))

            except Exception as e:
                self.logger.error(f"Error crawling {url}: {e}")
                continue

        return list(self.found_urls)

    def _extract_links(self, html_content: str, base_url: str) -> list:
        """Extract links from HTML content."""
        import re

        links = []

        # Simple regex-based link extraction (could be improved with proper HTML parsing)
        link_patterns = [
            r'href=[\'"]([^\'"]+)[\'"]',
            r'action=[\'"]([^\'"]+)[\'"]',
        ]

        for pattern in link_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                try:
                    # Resolve relative URLs
                    full_url = urljoin(base_url, match)

                    # Basic URL validation
                    parsed = urlparse(full_url)
                    if parsed.scheme in ['http', 'https'] and parsed.netloc:
                        links.append(full_url)
                except:
                    continue

        return list(set(links))  # Remove duplicates
