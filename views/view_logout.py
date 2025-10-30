from core.security import session_required
from core.database import db_manager
from flask import (
  Blueprint,   
  redirect,
  flash,
  session,
  request
)

logout = Blueprint('logout', __name__,
                    template_folder='templates')

@logout.route('/logout')
@session_required
def view_logout():
  username = session.get('session')
  
  if username:
    # Log logout activity
    db_manager.log_user_activity(
      username=username,
      action='LOGOUT',
      details={'method': 'manual_logout'},
      ip_address=request.remote_addr,
      user_agent=request.headers.get('User-Agent')
    )
    session.pop('session')

  flash('Logged out successfully', 'success')

  return redirect('/login')
