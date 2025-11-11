import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urlencode, parse_qsl, urlparse
from scanner.scanner.core import Finding
from checks.reflected_xss import ReflectedXSSCheck
try:
    from core.ml_payload_generator import ml_payload_generator
except Exception:
    # Fallback to load directly from core folder for dynamic import contexts
    import importlib.util, os, sys
    _fallback_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'core', 'ml_payload_generator.py'))
    if os.path.exists(_fallback_path):
        spec = importlib.util.spec_from_file_location('core.ml_payload_generator', _fallback_path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            sys.modules['core.ml_payload_generator'] = mod
            spec.loader.exec_module(mod)
            ml_payload_generator = getattr(mod, 'ml_payload_generator')
    else:
        raise
import sys
import os

# Add the project root to Python path so we can import core
project_root = r"c:Users\ASUS\.vscode\vuln-scanner-flask"
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.ml_payload_generator import ml_payload_generator

class EnhancedReflectedXSSCheck(ReflectedXSSCheck):
    """Enhanced XSS check with ML payload generation."""

    name = "enhanced_reflected_xss"

    def __init__(self):
        super().__init__()
        self.ml_generator = ml_payload_generator
        self.ml_tested_params = set()

    async def run(self, url: str, response: Dict[str, Any], http_client) -> List[Finding]:
        """Run both original and ML-enhanced XSS checks."""
        findings = []

        try:
            # First run the original XSS check
            original_findings = await super().run(url, response, http_client)
            findings.extend(original_findings)

            # Then run ML-enhanced checks
            ml_findings = await self._run_ml_checks(url, response, http_client)
            findings.extend(ml_findings)

        except Exception as e:
            self.logger.error(f"Error in enhanced XSS check for {url}: {e}")

        return findings

    async def _run_ml_checks(self, url: str, response: Dict[str, Any], http_client) -> List[Finding]:
        """Run ML-enhanced XSS tests."""
        findings = []

        # Test query parameters with ML payloads
        parsed_url = urlparse(url)
        if parsed_url.query:
            findings.extend(await self._test_query_params_ml(url, http_client))

        # Test form parameters with ML payloads
        if response.get('text'):
            findings.extend(await self._test_form_params_ml(url, response['text'], http_client))

        return findings

    async def _test_query_params_ml(self, url: str, http_client) -> List[Finding]:
        """Test XSS with ML-generated payloads in query parameters."""
        findings = []
        parsed_url = urlparse(url)

        if not parsed_url.query:
            return findings

        params = dict(parse_qsl(parsed_url.query))

        for param_name, param_value in params.items():
            param_key = f"ml_xss_{parsed_url.netloc}_{param_name}"

            if param_key in self.ml_tested_params:
                continue

            self.ml_tested_params.add(param_key)

            # Generate ML XSS payloads
            ml_payloads = self.ml_generator.generate_by_type('xss', 10, creativity=0.8)

            self.logger.info(f"Testing {len(ml_payloads)} ML-generated XSS payloads on parameter: {param_name}")

            for payload_info in ml_payloads:
                payload = payload_info['payload']

                test_params = params.copy()
                test_params[param_name] = payload

                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                if test_params:
                    test_url += "?" + urlencode(test_params)

                try:
                    response = await http_client.get(test_url)

                    if response and response.text:
                        # Use parent class's XSS detection method
                        if self._is_xss_detected(response.text, payload):
                            finding = self._create_ml_enhanced_finding(
                                test_url, param_name, payload, payload_info, is_form=False
                            )

                            findings.append(finding)
                            self.logger.info(f"ML-enhanced XSS found in parameter {param_name}")
                            break

                except Exception as e:
                    self.logger.error(f"Error testing ML XSS payload: {e}")
                    continue

                await asyncio.sleep(0.1)

        return findings

    async def _test_form_params_ml(self, url: str, html_content: str, http_client) -> List[Finding]:
        """Test XSS with ML payloads in form parameters."""
        findings = []

        # Use parent class's form detection
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

            for input_name in input_names:
                param_key = f"ml_xss_{urlparse(form_url).netloc}_form_{input_name}"

                if param_key in self.ml_tested_params:
                    continue

                self.ml_tested_params.add(param_key)

                ml_payloads = self.ml_generator.generate_by_type('xss', 6, creativity=0.7)

                for payload_info in ml_payloads:
                    payload = payload_info['payload']
                    form_data = {input_name: payload}

                    try:
                        response = await http_client.post(form_url, data=form_data)

                        if response and response.text:
                            if self._is_xss_detected(response.text, payload):
                                finding = self._create_ml_enhanced_finding(
                                    form_url, input_name, payload, payload_info, is_form=True
                                )

                                findings.append(finding)
                                self.logger.info(f"ML-enhanced XSS found in form field {input_name}")
                                break

                    except Exception as e:
                        self.logger.error(f"Error testing form ML XSS: {e}")
                        continue

                    await asyncio.sleep(0.1)

        return findings

    def _is_xss_detected(self, response_text: str, payload: str) -> bool:
        """Check if XSS payload was successful using parent class logic."""
        # Use your original XSS detection logic from ReflectedXSSCheck
        if payload in response_text:
            return True

        # Check for encoded versions
        encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded_payload in response_text:
            return True

        # Check for script execution indicators
        script_indicators = ['alert', 'prompt', 'confirm', 'javascript:']
        if any(indicator in response_text.lower() for indicator in script_indicators):
            return True

        return False

    def _create_ml_enhanced_finding(self, url: str, param: str, payload: str,
                                  payload_info: Dict, is_form: bool = False) -> Finding:
        """Create an enhanced XSS finding with ML context."""

        ml_tech = payload_info.get('technique', 'unknown')
        creativity = payload_info.get('creativity_level', 0.5)
        similarity = payload_info.get('base_similarity', 0.5)

        # Calculate ML-enhanced confidence
        base_confidence = 75  # Base confidence for XSS
        ml_confidence_boost = int(creativity * 15 + similarity * 10)
        enhanced_confidence = min(base_confidence + ml_confidence_boost, 90)

        return Finding(
            id="",
            target="",
            url=url,
            title=f"ML-Enhanced Reflected XSS ({ml_tech})",
            severity="Medium",
            description=(
                f"Cross-Site Scripting vulnerability detected using ML-generated payload. "
                f"ML Technique: {ml_tech}, Creativity: {creativity:.2f}, Similarity: {similarity:.2f}"
            ),
            evidence="XSS payload successfully injected and reflected",
            confidence=enhanced_confidence,
            cwe=79,
            param=param,
            payload=payload,
            request=f"{'POST' if is_form else 'GET'} {url}",
            response_snippet=f"Payload reflected in response: {payload}"
        )
