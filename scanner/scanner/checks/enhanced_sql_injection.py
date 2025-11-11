import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urlencode, parse_qsl, urlparse
from scanner.scanner.core import Finding
from checks.sql_injection import SQLInjectionCheck
try:
    from core.ml_payload_generator import ml_payload_generator
except Exception:
    # Fallback: load module directly from core folder so dynamic loaders
    # that don't have normal package discovery still work.
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

class EnhancedSQLInjectionCheck(SQLInjectionCheck):
    """Enhanced SQL injection check with ML payload generation."""

    name = "enhanced_sql_injection"

    def __init__(self):
        super().__init__()
        self.ml_generator = ml_payload_generator
        self.ml_tested_params = set()

    async def run(self, url: str, response: Dict[str, Any], http_client) -> List[Finding]:
        """Run both original and ML-enhanced SQL injection checks."""
        findings = []

        try:
            # First run the original SQL injection check
            original_findings = await super().run(url, response, http_client)
            findings.extend(original_findings)

            # Then run ML-enhanced checks
            ml_findings = await self._run_ml_checks(url, response, http_client)
            findings.extend(ml_findings)

        except Exception as e:
            self.logger.error(f"Error in enhanced SQL injection check for {url}: {e}")

        return findings

    async def _run_ml_checks(self, url: str, response: Dict[str, Any], http_client) -> List[Finding]:
        """Run ML-enhanced SQL injection tests."""
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
        """Test SQL injection with ML-generated payloads in query parameters."""
        findings = []
        parsed_url = urlparse(url)

        if not parsed_url.query:
            return findings

        params = dict(parse_qsl(parsed_url.query))

        for param_name, param_value in params.items():
            param_key = f"ml_{parsed_url.netloc}_{param_name}"

            if param_key in self.ml_tested_params:
                continue

            self.ml_tested_params.add(param_key)

            # Generate ML payloads for this parameter
            ml_payloads = self.ml_generator.generate_by_type('sqli', 12, creativity=0.7)

            self.logger.info(f"Testing {len(ml_payloads)} ML-generated SQLi payloads on parameter: {param_name}")

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
                        # Use parent class's analysis method
                        vulnerability = self._analyze_response_for_sqli(
                            response, payload, url, param_name
                        )

                        if vulnerability:
                            # Enhance the finding with ML context
                            finding = self._create_ml_enhanced_finding(
                                vulnerability, test_url, param_name, payload, payload_info
                            )

                            findings.append(finding)
                            self.logger.info(f"ML-enhanced SQL injection found in parameter {param_name}")
                            break

                except Exception as e:
                    self.logger.error(f"Error testing ML SQL injection payload: {e}")
                    continue

                await asyncio.sleep(0.1)

        return findings

    async def _test_form_params_ml(self, url: str, html_content: str, http_client) -> List[Finding]:
        """Test SQL injection with ML payloads in form parameters."""
        findings = []

        # Use parent class's form detection logic
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
                param_key = f"ml_{urlparse(form_url).netloc}_form_{input_name}"

                if param_key in self.ml_tested_params:
                    continue

                self.ml_tested_params.add(param_key)

                # Generate ML payloads for forms
                ml_payloads = self.ml_generator.generate_by_type('sqli', 8, creativity=0.6)

                for payload_info in ml_payloads:
                    payload = payload_info['payload']
                    form_data = {input_name: payload}

                    try:
                        response = await http_client.post(form_url, data=form_data)

                        if response and response.text:
                            vulnerability = self._analyze_response_for_sqli(
                                response, payload, form_url, input_name
                            )

                            if vulnerability:
                                finding = self._create_ml_enhanced_finding(
                                    vulnerability, form_url, input_name, payload, payload_info, is_form=True
                                )

                                findings.append(finding)
                                self.logger.info(f"ML-enhanced SQL injection found in form field {input_name}")
                                break

                    except Exception as e:
                        self.logger.error(f"Error testing form ML SQL injection: {e}")
                        continue

                    await asyncio.sleep(0.1)

        return findings

    def _create_ml_enhanced_finding(self, vulnerability: Dict, url: str, param: str,
                                  payload: str, payload_info: Dict, is_form: bool = False) -> Finding:
        """Create an enhanced finding with ML context."""

        # Adjust confidence based on ML factors
        ml_confidence_boost = int(payload_info.get('creativity_level', 0.5) * 10 +
                                payload_info.get('base_similarity', 0.5) * 5)
        enhanced_confidence = min(vulnerability['confidence'] + ml_confidence_boost, 99)

        # Enhanced title and description
        ml_tech = payload_info.get('technique', 'unknown')
        enhanced_title = f"ML-Enhanced {vulnerability['type'].replace('_', ' ').title()} SQL Injection"

        enhanced_description = (
            f"{vulnerability['description']}\n\n"
            f"ML Context: Technique={ml_tech}, "
            f"Creativity={payload_info.get('creativity_level', 0.5):.2f}, "
            f"Similarity={payload_info.get('base_similarity', 0.5):.2f}"
        )

        return Finding(
            id="",
            target="",
            url=url,
            title=enhanced_title,
            severity=vulnerability['severity'],
            description=enhanced_description,
            evidence=vulnerability['evidence'],
            confidence=enhanced_confidence,
            cwe=89,
            param=param,
            payload=payload,
            request=f"{'POST' if is_form else 'GET'} {url}",
            response_snippet=vulnerability['snippet']
        )
