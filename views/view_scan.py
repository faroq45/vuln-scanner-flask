from core.security import session_required
from core.register import Register
from core.parser   import SchemaParser
from core.scan_config import update_scan_config_with_user
from core.database import db_manager

from flask import Blueprint, request, session

scan = Blueprint('scan', __name__,
                  template_folder='templates')

@scan.route('/scan',  methods=["POST"])
@session_required
def view_scan():
  register = Register()
  scan = request.get_json()
  username = session.get('session')
  
  if scan and isinstance(scan, dict):
    # Update scan configuration with current logged-in user
    scan = update_scan_config_with_user(scan)
    schema = SchemaParser(scan, request)
    vfd, msg, scan = schema.verify()

    if not vfd:
      # Log failed scan initiation
      db_manager.log_user_activity(
        username=username,
        action='SCAN_INITIATION_FAILED',
        details={'error': msg, 'scan_data': scan},
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
      )
      return {'status':'Error: ' + msg }, 400
  else:
    return {'status':'Malformed Scan Data'}, 400
  
  res, code, msg = register.scan(scan)
  
  # Log scan initiation
  db_manager.log_user_activity(
    username=username,
    action='SCAN_INITIATED',
    details={
      'scan_type': scan.get('config', {}).get('name', 'Unknown'),
      'targets': {
        'networks': len(scan.get('targets', {}).get('networks', [])),
        'domains': len(scan.get('targets', {}).get('domains', [])),
        'urls': len(scan.get('targets', {}).get('urls', []))
      },
      'result': msg
    },
    ip_address=request.remote_addr,
    user_agent=request.headers.get('User-Agent')
  )

  return {'status': msg}, code
