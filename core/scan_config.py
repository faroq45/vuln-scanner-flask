import copy
import config
from flask import session


def get_default_scan_config():
    """
    Get default scan configuration with current logged-in user as engineer.
    If no user is logged in, use 'Unknown User' as fallback.
    """
    scan = copy.deepcopy(config.DEFAULT_SCAN)
    
    # Get the current logged-in user from session
    current_user = session.get('session', 'Unknown User')
    scan['config']['engineer'] = current_user
    
    return scan


def update_scan_config_with_user(scan_config):
    """
    Update a scan configuration to use the current logged-in user as engineer.
    """
    if not isinstance(scan_config, dict):
        return scan_config
    
    current_user = session.get('session', 'Unknown User')
    
    if 'config' not in scan_config:
        scan_config['config'] = {}
    
    scan_config['config']['engineer'] = current_user
    
    return scan_config