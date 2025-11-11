import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from scanner.scanner.core import Finding


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
    project_root = os.path.dirname(scanner_root)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
        logger.info(f"Added project root to path: {project_root}")


    # Make sure core module is available in the right context.
    # First try a standard import (preferred). If that fails, load the
    # package from the scanner's core folder and ensure __path__ is set
    # so submodule imports like `core.ml_payload_generator` work.
    if 'core' not in sys.modules or not hasattr(sys.modules.get('core'), 'Finding'):
        logger.warning("Core module not properly loaded, attempting to fix...")
        try:
            # Preferred: let import machinery load the package normally
            import importlib
            core_module = importlib.import_module('core')
            sys.modules['core'] = core_module
            logger.info("Imported core module via importlib.import_module('core')")
        except Exception:
            # Fallback: load package from scanner_root/core/__init__.py and set __path__
            core_init_path = os.path.join(scanner_root, 'core', '__init__.py')
            core_pkg_dir = os.path.join(scanner_root, 'core')
            if os.path.exists(core_init_path):
                try:
                    spec = importlib.util.spec_from_file_location("core", core_init_path)
                    if spec and spec.loader:
                        core_module = importlib.util.module_from_spec(spec)
                        # ensure package submodule lookups succeed
                        core_module.__path__ = [core_pkg_dir]
                        sys.modules['core'] = core_module
                        spec.loader.exec_module(core_module)
                        logger.info("Successfully loaded core module for checks (fallback)")
                except Exception as e:
                    logger.error(f"Failed to load core module: {e}")

    # Ensure core.ml_payload_generator submodule is importable. Some
    # dynamic loaders execute check modules in an import context where
    # automatic submodule discovery may not occur, so load it explicitly
    # from the core folder if needed.
    try:
        import importlib
        importlib.import_module('core.ml_payload_generator')
        logger.info("core.ml_payload_generator is importable")
    except Exception:
        # Fallback: load the file directly into sys.modules
        ml_path = os.path.join(scanner_root, 'core', 'ml_payload_generator.py')
        if os.path.exists(ml_path):
            try:
                spec = importlib.util.spec_from_file_location('core.ml_payload_generator', ml_path)
                if spec and spec.loader:
                    ml_mod = importlib.util.module_from_spec(spec)
                    sys.modules['core.ml_payload_generator'] = ml_mod
                    spec.loader.exec_module(ml_mod)
                    logger.info('Loaded core.ml_payload_generator (fallback)')
            except Exception as e:
                logger.error(f'Failed to load core.ml_payload_generator: {e}')

    # Also ensure checks.base is available for imports
    if 'checks.base' not in sys.modules:
        sys.modules['checks.base'] = sys.modules[__name__]

    checks = [ ]
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
        ('enhanced_sql_injection', 'EnhancedSQLInjectionCheck'),
        ('enhanced_reflected_xss', 'EnhancedReflectedXSSCheck'),
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
            # Log full traceback to aid debugging of import failures
            logger.exception(f"Could not load check {module_name}: {e}")
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
