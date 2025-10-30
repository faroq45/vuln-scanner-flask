import config

from core.redis  import rds
from core.user_manager import UserManager
from core.database import db_manager
from flask import session, redirect, request
from flask_httpauth import HTTPBasicAuth
from functools      import wraps

from werkzeug.security import (
  generate_password_hash, 
  check_password_hash
)

auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
  if rds.is_ip_blocked(request.remote_addr):
    # Log blocked attempt
    db_manager.log_user_activity(
      username=username,
      action='LOGIN_BLOCKED',
      details={'reason': 'IP blocked due to multiple failed attempts'},
      ip_address=request.remote_addr,
      user_agent=request.headers.get('User-Agent')
    )
    return False
  
  # First check config-based auth for backward compatibility
  if username == config.WEB_USER and \
    check_password_hash(generate_password_hash(config.WEB_PASSW), password):
    db_manager.log_user_activity(
      username=username,
      action='LOGIN_SUCCESS',
      details={'method': 'config_auth'},
      ip_address=request.remote_addr,
      user_agent=request.headers.get('User-Agent')
    )
    return True
  
  # Then check user database
  user_manager = UserManager()
  if user_manager.authenticate_user(username, password):
    db_manager.log_user_activity(
      username=username,
      action='LOGIN_SUCCESS',
      details={'method': 'user_database'},
      ip_address=request.remote_addr,
      user_agent=request.headers.get('User-Agent')
    )
    return True
  
  # Log failed attempt
  db_manager.log_user_activity(
    username=username,
    action='LOGIN_FAILED',
    details={'reason': 'Invalid credentials'},
    ip_address=request.remote_addr,
    user_agent=request.headers.get('User-Agent')
  )
  rds.log_attempt(request.remote_addr)
  return False

def session_required(function_to_protect):
  @wraps(function_to_protect)
  def wrapper(*args, **kwargs):
    if not session.get('session'):
      return redirect('/login', 307)
    
    return function_to_protect(*args, **kwargs)
  return wrapper
  