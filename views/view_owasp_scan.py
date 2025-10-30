import asyncio
import json
import uuid
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for

from core.redis import rds
from core.logging import logger

# Import the OWASP scanner using wrapper to avoid import conflicts
from core.owasp_wrapper import initialize_owasp_scanner, get_scan_config, get_scan_manager, is_scanner_available

# Initialize the scanner
OWASP_SCANNER_AVAILABLE = initialize_owasp_scanner()
if OWASP_SCANNER_AVAILABLE:
    ScanConfig = get_scan_config()
    scan_manager = get_scan_manager()
else:
    ScanConfig = None
    scan_manager = None

owasp_scan = Blueprint('owasp_scan', __name__)

@owasp_scan.route('/owasp-scan')
def owasp_scan_index():
    """Main OWASP Top 10 scanner page."""
    return render_template('owasp_scan.html', scanner_available=OWASP_SCANNER_AVAILABLE)

@owasp_scan.route('/api/owasp/start', methods=['POST'])
def start_owasp_scan():
    """Start a new OWASP Top 10 vulnerability scan."""
    
    if not OWASP_SCANNER_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'OWASP scanner not available. Please check installation.'
        }), 503
    
    try:
        data = request.get_json()
        
        if not data or 'target' not in data:
            return jsonify({
                'success': False,
                'error': 'Target URL is required'
            }), 400
        
        # Validate target URL
        target = data['target'].strip()
        if not target.startswith(('http://', 'https://')):
            return jsonify({
                'success': False,
                'error': 'Target must be a valid HTTP/HTTPS URL'
            }), 400
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan configuration
        config = ScanConfig(
            target=target,
            max_pages=data.get('maxPages', 20),
            concurrency=data.get('concurrency', 3),
            timeout=data.get('timeout', 10),
            user_agent=data.get('userAgent', 'OWASP-Scanner/1.0'),
            respect_robots=data.get('respectRobots', True),
            max_depth=data.get('maxDepth', 3),
            follow_redirects=data.get('followRedirects', True),
            max_redirects=data.get('maxRedirects', 5),
            rate_limit_delay=data.get('rateLimitDelay', 0.1),
            checks=data.get('checks', [])
        )
        
        # Store scan info in Redis for session management
        scan_info = {
            'id': scan_id,
            'target': target,
            'status': 'starting',
            'start_time': datetime.now().isoformat(),
            'config': {
                'max_pages': config.max_pages,
                'checks': config.checks,
                'concurrency': config.concurrency
            }
        }
        
        rds.set(f"owasp_scan:{scan_id}", json.dumps(scan_info))
        
        # Start the scan
        try:
            scan_manager.start_scan(scan_id, config)
            
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'message': 'OWASP Top 10 scan started successfully'
            })
        
        except Exception as e:
            logger.error(f"Failed to start OWASP scan: {e}")
            return jsonify({
                'success': False,
                'error': f'Failed to start scan: {str(e)}'
            }), 500
    
    except Exception as e:
        logger.error(f"Error in start_owasp_scan: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@owasp_scan.route('/api/owasp/status/<scan_id>')
def get_owasp_scan_status(scan_id):
    """Get status of an OWASP scan."""
    
    if not OWASP_SCANNER_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'OWASP scanner not available'
        }), 503
    
    try:
        # Get status from scan manager
        status = scan_manager.get_scan_status(scan_id)
        
        if status is None:
            # Try to get from Redis
            scan_info_json = rds.get(f"owasp_scan:{scan_id}")
            if scan_info_json:
                scan_info = json.loads(scan_info_json)
                return jsonify({
                    'success': True,
                    'status': scan_info.get('status', 'unknown'),
                    'progress': 0,
                    'findings_count': 0
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Scan not found'
                }), 404
        
        return jsonify({
            'success': True,
            **status
        })
    
    except Exception as e:
        logger.error(f"Error getting OWASP scan status: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@owasp_scan.route('/api/owasp/results/<scan_id>')
def get_owasp_scan_results(scan_id):
    """Get results of a completed OWASP scan."""
    
    if not OWASP_SCANNER_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'OWASP scanner not available'
        }), 503
    
    try:
        # Get results from scan manager
        results = scan_manager.get_scan_results(scan_id)
        
        if results is None:
            return jsonify({
                'success': False,
                'error': 'Scan results not found or scan still running'
            }), 404
        
        # Store results in Redis for persistence
        rds.set(f"owasp_results:{scan_id}", json.dumps(results), ex=86400)  # 24 hour expiry
        
        return jsonify({
            'success': True,
            'results': results
        })
    
    except Exception as e:
        logger.error(f"Error getting OWASP scan results: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@owasp_scan.route('/api/owasp/cancel/<scan_id>', methods=['POST'])
def cancel_owasp_scan(scan_id):
    """Cancel a running OWASP scan."""
    
    if not OWASP_SCANNER_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'OWASP scanner not available'
        }), 503
    
    try:
        success = scan_manager.cancel_scan(scan_id)
        
        if success:
            # Update Redis
            scan_info_json = rds.get(f"owasp_scan:{scan_id}")
            if scan_info_json:
                scan_info = json.loads(scan_info_json)
                scan_info['status'] = 'cancelled'
                rds.set(f"owasp_scan:{scan_id}", json.dumps(scan_info))
            
            return jsonify({
                'success': True,
                'message': 'Scan cancelled successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Scan not found or already completed'
            }), 404
    
    except Exception as e:
        logger.error(f"Error cancelling OWASP scan: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@owasp_scan.route('/api/owasp/checks')
def get_available_checks():
    """Get list of available OWASP security checks."""
    
    if not OWASP_SCANNER_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'OWASP scanner not available'
        }), 503
    
    try:
        # Return a list of available OWASP Top 10 checks
        check_info = [
            {
                'id': 'reflected_xss',
                'name': 'Reflected XSS',
                'description': 'Check for reflected cross-site scripting vulnerabilities'
            },
            {
                'id': 'sql_injection',
                'name': 'SQL Injection',
                'description': 'Check for SQL injection vulnerabilities'
            },
            {
                'id': 'security_headers',
                'name': 'Security Headers',
                'description': 'Check for missing security headers'
            },
            {
                'id': 'open_redirect',
                'name': 'Open Redirect',
                'description': 'Check for open redirect vulnerabilities'
            },
            {
                'id': 'directory_traversal',
                'name': 'Directory Traversal',
                'description': 'Check for directory traversal vulnerabilities'
            },
            {
                'id': 'ssrf',
                'name': 'Server-Side Request Forgery',
                'description': 'Check for SSRF vulnerabilities'
            }
        ]
        
        return jsonify({
            'success': True,
            'checks': check_info
        })
    
    except Exception as e:
        logger.error(f"Error getting available checks: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@owasp_scan.route('/owasp-results/<scan_id>')
def view_owasp_results(scan_id):
    """View OWASP scan results page."""
    
    # Try to get results from Redis first
    results_json = rds.get(f"owasp_results:{scan_id}")
    if results_json:
        results = json.loads(results_json)
        return render_template('owasp_results.html', 
                             results=results, 
                             scan_id=scan_id,
                             scanner_available=OWASP_SCANNER_AVAILABLE)
    
    # If OWASP scanner is available, try to get live results
    if OWASP_SCANNER_AVAILABLE and scan_manager:
        results = scan_manager.get_scan_results(scan_id)
        if results:
            return render_template('owasp_results.html', 
                                 results=results, 
                                 scan_id=scan_id,
                                 scanner_available=True)
    
    # Show loading page or error
    return render_template('owasp_results.html', 
                         results=None, 
                         scan_id=scan_id,
                         scanner_available=OWASP_SCANNER_AVAILABLE)