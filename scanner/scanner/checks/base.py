import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from core import Finding


class BaseCheck(ABC):
    """Base class for all security checks."""
    
    name: str = ""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    async def run(self, url: str, response: Dict[str, Any], http_client) -> List[Finding]:
        """Run the security check and return findings."""
        pass


def get_available_checks():
    """Get all available security checks."""
    import os
    import sys
    import importlib.util
    import logging
    
    logger = logging.getLogger(__name__)
    
    # Get the checks directory and scanner root
    checks_dir = os.path.dirname(os.path.abspath(__file__))
    scanner_root = os.path.dirname(checks_dir)
    
    # Make sure core module is available in the right context
    # If 'core' in sys.modules doesn't have Finding, we need to fix it
    if 'core' not in sys.modules or not hasattr(sys.modules.get('core'), 'Finding'):
        logger.warning("Core module not properly loaded, attempting to fix...")
        core_path = os.path.join(scanner_root, 'core', '__init__.py')
        if os.path.exists(core_path):
            try:
                spec = importlib.util.spec_from_file_location("core", core_path)
                if spec and spec.loader:
                    core_module = importlib.util.module_from_spec(spec)
                    sys.modules['core'] = core_module
                    spec.loader.exec_module(core_module)
                    logger.info("Successfully loaded core module for checks")
            except Exception as e:
                logger.error(f"Failed to load core module: {e}")
    
    # Also ensure checks.base is available for imports
    if 'checks.base' not in sys.modules:
        sys.modules['checks.base'] = sys.modules[__name__]
    
    checks = []
    check_files = [
        ('reflected_xss', 'ReflectedXSSCheck'),
        ('sql_injection', 'SQLInjectionCheck'),
        ('security_headers', 'SecurityHeadersCheck'),
        ('open_redirect', 'OpenRedirectCheck'),
        ('directory_traversal', 'DirectoryTraversalCheck'),
        ('ssrf', 'SSRFCheck'),
        ('broken_access_control', 'BrokenAccessControlCheck'),
        ('authentication_bypass', 'AuthenticationBypassCheck'),
        ('information_disclosure', 'InformationDisclosureCheck'),
        ('security_misconfiguration', 'SecurityMisconfigurationCheck'),
    ]
    
    for module_name, class_name in check_files:
        try:
            module_path = os.path.join(checks_dir, f"{module_name}.py")
            if not os.path.exists(module_path):
                logger.warning(f"Check file not found: {module_path}")
                continue
            
            spec = importlib.util.spec_from_file_location(f"checks.{module_name}", module_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[f"checks.{module_name}"] = module
                spec.loader.exec_module(module)
                
                check_class = getattr(module, class_name)
                check_instance = check_class()
                checks.append(check_instance)
                logger.info(f"Loaded security check: {class_name}")
        except Exception as e:
            logger.warning(f"Could not load check {module_name}: {e}")
            continue
    
    if not checks:
        logger.warning("No security checks were loaded")
    else:
        logger.info(f"Successfully loaded {len(checks)} security checks")
    
    return checks
    
    return [
        ReflectedXSSCheck(),
        SQLInjectionCheck(),
        SecurityHeadersCheck(),
        OpenRedirectCheck(),
        DirectoryTraversalCheck(),
        SSRFCheck(),
        BrokenAccessControlCheck(),
        AuthenticationBypassCheck(),
        InformationDisclosureCheck(),
        SecurityMisconfigurationCheck(),
    ]