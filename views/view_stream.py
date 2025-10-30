import time
import os

from core.security import session_required
from flask import Blueprint, Response, stream_with_context
import config

stream = Blueprint('stream', __name__,
                    template_folder='templates')

@stream.route('/log')
@session_required
def view_stream():
  def generate():
    log_path = os.path.join('logs', config.WEB_LOG)
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
      os.makedirs('logs')
    
    # Create log file if it doesn't exist
    if not os.path.exists(log_path):
      with open(log_path, 'w') as f:
        f.write('Log file initialized\n')
    
    try:
      with open(log_path, 'r') as f:
        # Read existing content first
        content = f.read()
        if content:
          yield content
        
        # Continue streaming new content
        while True:
          new_content = f.read()
          if new_content:
            yield new_content
          time.sleep(1)
    except Exception as e:
      yield f'Error reading log file: {str(e)}\n'
  
  return Response(stream_with_context(generate()), mimetype='text/plain')
