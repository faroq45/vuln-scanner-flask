from core.security import session_required
from core.database import db_manager, UserActivity
from core.user_manager import UserManager

from flask import (
  Blueprint, 
  render_template, 
  request,
  session,
  jsonify
)

activity = Blueprint('activity', __name__,
                     template_folder='templates')

@activity.route('/activity')
@session_required
def view_activity():
    """Display user activity logs"""
    # Check if user is admin
    user_manager = UserManager()
    current_user = user_manager.get_user(session.get('session'))
    
    is_admin = current_user and current_user.get('role') == 'admin'
    
    return render_template('activity.html', is_admin=is_admin)

@activity.route('/api/activity', methods=['GET'])
@session_required
def api_get_activity():
    """API endpoint to fetch user activity logs"""
    # Check if user is admin
    user_manager = UserManager()
    current_user = user_manager.get_user(session.get('session'))
    current_username = session.get('session')
    
    is_admin = current_user and current_user.get('role') == 'admin'
    
    # Get query parameters
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    username_filter = request.args.get('username', None)
    action_filter = request.args.get('action', None)
    
    if not db_manager.connected:
        return jsonify({'error': 'Database not connected'}), 503
    
    try:
        with db_manager.get_session() as db_session:
            # Build query
            query = db_session.query(UserActivity)
            
            # If not admin, only show their own activities
            if not is_admin:
                query = query.filter_by(username=current_username)
            elif username_filter:
                query = query.filter_by(username=username_filter)
            
            # Filter by action if specified
            if action_filter:
                query = query.filter(UserActivity.action.like(f'%{action_filter}%'))
            
            # Order by most recent first
            query = query.order_by(UserActivity.timestamp.desc())
            
            # Get total count
            total_count = query.count()
            
            # Apply pagination
            activities = query.offset(offset).limit(limit).all()
            
            # Convert to dict
            activity_list = []
            for act in activities:
                activity_list.append({
                    'id': act.id,
                    'username': act.username,
                    'action': act.action,
                    'details': act.details,
                    'ip_address': act.ip_address,
                    'user_agent': act.user_agent,
                    'timestamp': act.timestamp.isoformat() if act.timestamp else None
                })
            
            return jsonify({
                'activities': activity_list,
                'total': total_count,
                'limit': limit,
                'offset': offset
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@activity.route('/api/activity/stats', methods=['GET'])
@session_required
def api_activity_stats():
    """API endpoint to get activity statistics"""
    # Check if user is admin
    user_manager = UserManager()
    current_user = user_manager.get_user(session.get('session'))
    current_username = session.get('session')
    
    is_admin = current_user and current_user.get('role') == 'admin'
    
    if not db_manager.connected:
        return jsonify({'error': 'Database not connected'}), 503
    
    try:
        with db_manager.get_session() as db_session:
            from sqlalchemy import func, distinct
            
            # Base query
            if is_admin:
                base_query = db_session.query(UserActivity)
            else:
                base_query = db_session.query(UserActivity).filter_by(username=current_username)
            
            # Get statistics
            total_activities = base_query.count()
            unique_users = db_session.query(distinct(UserActivity.username)).count() if is_admin else 1
            
            # Get action counts
            action_counts = db_session.query(
                UserActivity.action,
                func.count(UserActivity.id).label('count')
            )
            
            if not is_admin:
                action_counts = action_counts.filter_by(username=current_username)
            
            action_counts = action_counts.group_by(UserActivity.action).order_by(
                func.count(UserActivity.id).desc()
            ).limit(10).all()
            
            action_stats = [{'action': action, 'count': count} for action, count in action_counts]
            
            # Get recent login count (last 24 hours)
            from datetime import datetime, timedelta
            yesterday = datetime.utcnow() - timedelta(days=1)
            
            recent_logins_query = db_session.query(UserActivity).filter(
                UserActivity.action.in_(['LOGIN', 'LOGIN_SUCCESS']),
                UserActivity.timestamp >= yesterday
            )
            
            if not is_admin:
                recent_logins_query = recent_logins_query.filter_by(username=current_username)
            
            recent_logins = recent_logins_query.count()
            
            return jsonify({
                'total_activities': total_activities,
                'unique_users': unique_users,
                'recent_logins_24h': recent_logins,
                'top_actions': action_stats
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500
