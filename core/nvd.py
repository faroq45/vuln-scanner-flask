# core/nvd.py
import time
import requests
import logging
import config

logger = logging.getLogger(__name__)

NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Basic backoff / rate-safe helper for small-volume queries
def search_cves_by_keyword(keyword: str, max_results: int = 5):
    """
    Search NVD CVE index for keyword. Returns list of CVE IDs (strings).
    Uses config.NVD_API_KEY if set. Respects simple rate/sleep to avoid hitting limits.
    """
    if not keyword:
        return []

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }
    headers = {}
    api_key = getattr(config, "NVD_API_KEY", None)
    if api_key:
        headers["apiKey"] = api_key

    try:
        # small sleep to be kind to rate limits (without API key NVD is very limited)
        time.sleep(0.2)
        resp = requests.get(NVD_CVE_ENDPOINT, params=params, headers=headers, timeout=8)
        if resp.status_code != 200:
            logger.warning(f"NVD lookup failed (status {resp.status_code}) for '{keyword}'")
            return []
        data = resp.json()
        # v2.0 returns items under 'vulnerabilities' each with 'cve' : { 'id': 'CVE-...'}
        cves = []
        for item in data.get("vulnerabilities", []):
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id")
            if cve_id:
                cves.append(cve_id)
        return cves
    except Exception as e:
        logger.warning(f"NVD lookup error for '{keyword}': {e}")
        return []
