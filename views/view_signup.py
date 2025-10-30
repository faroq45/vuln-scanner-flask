from core.user_manager import UserManager
from core.logging import logger

from flask import (
  Blueprint, 
  render_template, 
  request,
  session,
  redirect,
  flash,
  jsonify
)

signup = Blueprint('signup', __name__,
                   template_folder='templates')

@signup.route('/signup', methods=['GET', 'POST'])
def view_signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = request.form.get('email', '').strip()
        
        # Validate input
        if not username or not password or not email:
            return render_template('signup.html', err='All fields are required.')
        
        if password != confirm_password:
            return render_template('signup.html', err='Passwords do not match.')
        
        # Create user
        user_manager = UserManager()
        success, message = user_manager.create_user(username, password, email)
        
        if success:
            logger.info(f'New user registered: {username}')
            flash('Account created successfully! You can now log in.', 'success')
            return redirect('/login')
        else:
            return render_template('signup.html', err=message)
    
    return render_template('signup.html')

@signup.route('/api/users', methods=['GET'])
def api_list_users():
    """API endpoint to list users (admin only)."""
    # Check if user is logged in
    if not session.get('session'):
        return jsonify({'error': 'Authentication required'}), 401
    
    # Check if user has admin privileges
    user_manager = UserManager()
    current_user = user_manager.get_user(session.get('session'))
    
    if not current_user or current_user.get('role') != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    
    users = user_manager.list_users()
    return jsonify({'users': users})

@signup.route('/api/users/<username>/deactivate', methods=['POST'])
def api_deactivate_user(username):
    """API endpoint to deactivate a user (admin only)."""
    # Check if user is logged in
    if not session.get('session'):
        return jsonify({'error': 'Authentication required'}), 401
    
    # Check if user has admin privileges
    user_manager = UserManager()
    current_user = user_manager.get_user(session.get('session'))
    
    if not current_user or current_user.get('role') != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    
    if user_manager.deactivate_user(username):
        return jsonify({'message': f'User {username} deactivated successfully'})
    else:
        return jsonify({'error': 'Failed to deactivate user'}), 400

@signup.route('/api/users/<username>/activate', methods=['POST'])
def api_activate_user(username):
    """API endpoint to activate a user (admin only)."""
    # Check if user is logged in
    if not session.get('session'):
        return jsonify({'error': 'Authentication required'}), 401
    
    # Check if user has admin privileges
    user_manager = UserManager()
    current_user = user_manager.get_user(session.get('session'))
    
    if not current_user or current_user.get('role') != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    
    if user_manager.activate_user(username):
        return jsonify({'message': f'User {username} activated successfully'})
    else:
        return jsonify({'error': 'Failed to activate user'}), 400