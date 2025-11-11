import sys
import os
import logging

# Set up logging to see all messages
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(message)s')

# Add the project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

try:
    from scanner.scanner.checks.base import get_available_checks

    print("Loading checks...")
    checks = get_available_checks()
    print(f"Loaded {len(checks)} checks:")

    for i, check in enumerate(checks):
        print(f"   {i+1}. {check.name} ({check.__class__.__name__})")

except Exception as e:
    print(f" Error: {e}")
    import traceback
    traceback.print_exc()
