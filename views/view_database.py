"""
Database management views for PostgreSQL integration
"""
import json
from datetime import datetime, timedelta
from flask import Blueprint, render_template, jsonify, request, flash, redirect, url_for

from core.security import session_required
from core.logging import logger

# Import database manager
try:
    from core.database import db_manager, DATABASE_AVAILABLE
except ImportError:
    DATABASE_AVAILABLE = False
    db_manager = None

database = Blueprint('database', __name__, template_folder='templates')

@database.route('/database')
@session_required
def view_database():
    """Database management page"""
    if not DATABASE_AVAILABLE or not db_manager:
        flash('Database functionality not available', 'error')
        return redirect(url_for('dashboard.view_dashboard'))
    
    # Get database statistics
    stats = db_manager.get_scan_statistics()
    
    # Get recent vulnerabilities
    recent_vulns = db_manager.get_vulnerabilities(limit=10)
    
    # Get connection status
    connection_status = {
        'connected': db_manager.connected,
        'database_name': db_manager.engine.url.database if db_manager.connected else None,
        'host': db_manager.engine.url.host if db_manager.connected else None,
        'port': db_manager.engine.url.port if db_manager.connected else None
    }
    
    return render_template('database.html', 
                         stats=stats,
                         recent_vulns=recent_vulns,
                         connection_status=connection_status)

@database.route('/api/database/vulnerabilities')
@session_required
def api_get_vulnerabilities():
    """API endpoint to get vulnerabilities from database"""
    if not DATABASE_AVAILABLE or not db_manager or not db_manager.connected:
        return jsonify({'success': False, 'error': 'Database not available'}), 503
    
    try:
        # Get query parameters
        limit = request.args.get('limit', 50, type=int)
        session_id = request.args.get('session_id')
        severity = request.args.get('severity', type=int)
        
        # Get vulnerabilities
        vulns = db_manager.get_vulnerabilities(session_id=session_id, limit=limit)
        
        # Filter by severity if specified
        if severity is not None:
            vulns = [v for v in vulns if v['severity'] == severity]
        
        return jsonify({
            'success': True,
            'vulnerabilities': vulns,
            'total': len(vulns)
        })
        
    except Exception as e:
        logger.error(f"Error getting vulnerabilities from database: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@database.route('/api/database/statistics')
@session_required
def api_get_statistics():
    """API endpoint to get database statistics"""
    if not DATABASE_AVAILABLE or not db_manager or not db_manager.connected:
        return jsonify({'success': False, 'error': 'Database not available'}), 503
    
    try:
        stats = db_manager.get_scan_statistics()
        
        # Get additional metrics
        with db_manager.get_session() as session:
            from core.database import ScanSession, Vulnerability, Target
            
            # Recent activity (last 24 hours)
            recent_cutoff = datetime.utcnow() - timedelta(hours=24)
            recent_vulns = session.query(Vulnerability).filter(
                Vulnerability.discovered_at > recent_cutoff
            ).count()
            
            recent_sessions = session.query(ScanSession).filter(
                ScanSession.start_time > recent_cutoff
            ).count()
            
            # Top vulnerability types
            vuln_types = session.query(
                Vulnerability.rule_id,
                Vulnerability.rule_name,
                session.query().filter(
                    Vulnerability.rule_id == Vulnerability.rule_id
                ).count().label('count')
            ).group_by(Vulnerability.rule_id, Vulnerability.rule_name).order_by('count DESC').limit(5).all()
            
            stats.update({
                'recent_vulnerabilities_24h': recent_vulns,
                'recent_sessions_24h': recent_sessions,
                'top_vulnerability_types': [
                    {'rule_id': vt[0], 'rule_name': vt[1], 'count': vt[2]}
                    for vt in vuln_types
                ]
            })
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"Error getting database statistics: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@database.route('/api/database/sessions')
@session_required  
def api_get_sessions():
    """API endpoint to get scan sessions from database"""
    if not DATABASE_AVAILABLE or not db_manager or not db_manager.connected:
        return jsonify({'success': False, 'error': 'Database not available'}), 503
    
    try:
        limit = request.args.get('limit', 20, type=int)
        
        with db_manager.get_session() as session:
            from core.database import ScanSession
            
            sessions = session.query(ScanSession).order_by(
                ScanSession.start_time.desc()
            ).limit(limit).all()
            
            session_data = []
            for s in sessions:
                session_data.append({
                    'id': s.id,
                    'session_id': s.session_id,
                    'status': s.status,
                    'start_time': s.start_time.isoformat() if s.start_time else None,
                    'end_time': s.end_time.isoformat() if s.end_time else None,
                    'scan_type': s.scan_type,
                    'engineer': s.engineer,
                    'description': s.description,
                    'vulnerability_count': len(s.vulnerabilities),
                    'target_count': len(s.targets)
                })
        
        return jsonify({
            'success': True,
            'sessions': session_data
        })
        
    except Exception as e:
        logger.error(f"Error getting scan sessions: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@database.route('/api/database/vulnerability/<int:vuln_id>')
@session_required
def api_get_vulnerability_details(vuln_id):
    """API endpoint to get detailed vulnerability information"""
    if not DATABASE_AVAILABLE or not db_manager or not db_manager.connected:
        return jsonify({'success': False, 'error': 'Database not available'}), 503
    
    try:
        with db_manager.get_session() as session:
            from core.database import Vulnerability
            
            vuln = session.query(Vulnerability).filter_by(id=vuln_id).first()
            
            if not vuln:
                return jsonify({'success': False, 'error': 'Vulnerability not found'}), 404
            
            vuln_data = {
                'id': vuln.id,
                'session_id': vuln.session_id,
                'rule_id': vuln.rule_id,
                'rule_name': vuln.rule_name,
                'rule_description': vuln.rule_description,
                'rule_details': vuln.rule_details,
                'rule_mitigation': vuln.rule_mitigation,
                'severity': vuln.severity,
                'severity_text': vuln.severity_text,
                'confidence': vuln.confidence,
                'ip_address': vuln.ip_address,
                'port': vuln.port,
                'protocol': vuln.protocol,
                'service': vuln.service,
                'url': vuln.url,
                'evidence': vuln.evidence,
                'proof_of_concept': vuln.proof_of_concept,
                'raw_output': vuln.raw_output,
                'owasp_category': vuln.owasp_category,
                'cve_ids': vuln.cve_ids,
                'cwe_id': vuln.cwe_id,
                'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None,
                'verified_at': vuln.verified_at.isoformat() if vuln.verified_at else None,
                'false_positive': vuln.false_positive,
                'remediated': vuln.remediated,
                'notes': vuln.notes
            }
            
            return jsonify({
                'success': True,
                'vulnerability': vuln_data
            })
        
    except Exception as e:
        logger.error(f"Error getting vulnerability details: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@database.route('/api/database/export/vulnerabilities')
@session_required
def api_export_vulnerabilities():
    """API endpoint to export vulnerabilities as JSON"""
    if not DATABASE_AVAILABLE or not db_manager or not db_manager.connected:
        return jsonify({'success': False, 'error': 'Database not available'}), 503
    
    try:
        session_id = request.args.get('session_id')
        severity = request.args.get('severity', type=int)
        
        vulns = db_manager.get_vulnerabilities(session_id=session_id)
        
        # Filter by severity if specified
        if severity is not None:
            vulns = [v for v in vulns if v['severity'] == severity]
        
        export_data = {
            'export_timestamp': datetime.utcnow().isoformat(),
            'session_id': session_id,
            'total_vulnerabilities': len(vulns),
            'vulnerabilities': vulns
        }
        
        return jsonify({
            'success': True,
            'export_data': export_data
        })
        
    except Exception as e:
        logger.error(f"Error exporting vulnerabilities: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@database.route('/database/test')
@session_required
def test_database_connection():
    """Test database connection and operations"""
    if not DATABASE_AVAILABLE or not db_manager:
        flash('Database functionality not available', 'error')
        return redirect(url_for('dashboard.view_dashboard'))
    
    try:
        if not db_manager.connected:
            flash('Database connection failed', 'error')
            return redirect(url_for('database.view_database'))
        
        # Test basic operations
        with db_manager.get_session() as session:
            from core.database import ScanSession, Vulnerability, Target
            
            # Count records
            session_count = session.query(ScanSession).count()
            vuln_count = session.query(Vulnerability).count()
            target_count = session.query(Target).count()
            
            flash(f'Database test successful! Sessions: {session_count}, Vulnerabilities: {vuln_count}, Targets: {target_count}', 'success')
            
    except Exception as e:
        logger.error(f"Database test failed: {e}")
        flash(f'Database test failed: {str(e)}', 'error')
    
    return redirect(url_for('database.view_database'))