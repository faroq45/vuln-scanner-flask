"""
OWASP Scanner Wrapper
Handles import conflicts between main app core and scanner core modules
"""
import sys
import os
import importlib.util
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Global variables to store loaded modules
_scanner_modules = {}
_scanner_available = False

def _load_scanner_module(module_name: str, file_path: str):
    """Load a scanner module with a unique name to avoid conflicts."""
    try:
        logger.info(f"Loading scanner module {module_name} from {file_path}")
        
        if not os.path.exists(file_path):
            logger.error(f"Module file not found: {file_path}")
            return None
        
        spec = importlib.util.spec_from_file_location(f"owasp_{module_name}", file_path)
        if spec is None:
            logger.error(f"Failed to create spec for {module_name}")
            return None
        
        module = importlib.util.module_from_spec(spec)
        
        # Add to sys.modules with unique name
        sys.modules[f"owasp_{module_name}"] = module
        spec.loader.exec_module(module)
        
        _scanner_modules[module_name] = module
        logger.info(f"Successfully loaded {module_name}")
        return module
    except Exception as e:
        logger.error(f"Failed to load {module_name}: {e}", exc_info=True)
        return None

def initialize_owasp_scanner():
    """Initialize the OWASP scanner modules."""
    global _scanner_available
    
    try:
        # Get scanner path
        scanner_path = os.path.join(os.path.dirname(__file__), '..', 'scanner', 'scanner')
        scanner_path = os.path.abspath(scanner_path)
        
        if not os.path.exists(scanner_path):
            logger.error(f"Scanner path does not exist: {scanner_path}")
            return False
        
        # Backup the existing 'core' module if it exists (our app core)
        app_core_backup = sys.modules.get('core')
        
        # Load core module first and register it properly
        core_init_path = os.path.join(scanner_path, 'core', '__init__.py')
        scanner_core = _load_scanner_module('core', core_init_path)
        if not scanner_core:
            return False
        
        # Temporarily register the scanner core module as 'core' in sys.modules so imports work
        sys.modules['core'] = scanner_core
        
        # Load http_client module
        http_client_path = os.path.join(scanner_path, 'core', 'http_client.py')
        scanner_http = _load_scanner_module('http_client', http_client_path)
        if not scanner_http:
            return False
        
        # Register http_client in core namespace
        sys.modules['core.http_client'] = scanner_http
        
        # Load checks base module (now that core is available)
        checks_base_path = os.path.join(scanner_path, 'checks', 'base.py')
        scanner_checks = _load_scanner_module('checks_base', checks_base_path)
        if not scanner_checks:
            return False
        
        # Create a proper checks module structure
        import types
        checks_module = types.ModuleType('checks')
        checks_module.base = scanner_checks
        checks_module.BaseCheck = scanner_checks.BaseCheck
        checks_module.get_available_checks = scanner_checks.get_available_checks
        sys.modules['checks'] = checks_module
        sys.modules['checks.base'] = scanner_checks
        
        # Load the real scanner engine
        scanner_engine_path = os.path.join(scanner_path, 'core', 'scanner_engine.py')
        
        # Temporarily add scanner path to sys.path for proper imports
        original_sys_path = sys.path.copy()
        sys.path.insert(0, scanner_path)
        
        try:
            scanner_engine = _load_scanner_module('scanner_engine', scanner_engine_path)
            if not scanner_engine:
                logger.error("Failed to load scanner engine")
                return False
            
            _scanner_modules['engine'] = scanner_engine
            
            _scanner_available = True
            logger.info("OWASP scanner initialized successfully")
            return True
        finally:
            # Restore original sys.path
            sys.path = original_sys_path
            
            # Restore the app's core module if it was backed up
            if app_core_backup is not None:
                sys.modules['core'] = app_core_backup
            elif 'core' in sys.modules and sys.modules['core'] == scanner_core:
                # Remove scanner core from global namespace if no app core existed
                # Keep it only in _scanner_modules
                pass  # Leave it for now as other parts may need it
        
    except Exception as e:
        logger.error(f"Failed to initialize OWASP scanner: {e}")
        _scanner_available = False
        return False

def get_scan_config():
    """Get ScanConfig class."""
    if not _scanner_available:
        return None
    return _scanner_modules.get('core', {}).ScanConfig

def get_scan_manager():
    """Get scan manager instance."""
    if not _scanner_available:
        return None
    
    engine_module = _scanner_modules.get('engine')
    if engine_module and hasattr(engine_module, 'ScanManager'):
        # Create and return a singleton instance
        if not hasattr(get_scan_manager, '_instance'):
            get_scan_manager._instance = engine_module.ScanManager()
        return get_scan_manager._instance
    elif engine_module and hasattr(engine_module, 'scan_manager'):
        return engine_module.scan_manager
    return None

def is_scanner_available():
    """Check if scanner is available."""
    return _scanner_available