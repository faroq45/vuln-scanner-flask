"""
scanner package initializer.

This file ensures the project root is on sys.path so top-level modules
like `core` can be imported reliably when this package is used from
different entrypoints.
"""
import os
import sys

# Add the repository root to sys.path (two levels up from this file)
# This makes `import core.ml_payload_generator` work even when the
# package is imported from nested contexts or when Python's cwd is
# different.
try:
	_THIS_DIR = os.path.dirname(__file__)
	_SCANNER_PKG_DIR = os.path.abspath(_THIS_DIR)
	_PROJECT_ROOT = os.path.abspath(os.path.join(_THIS_DIR, '..', '..'))

	# Ensure the scanner package directory is first so its subpackages
	# (like `checks`, `core` when referenced as top-level names) can be
	# imported directly (e.g., `import checks.sql_injection`).
	if _SCANNER_PKG_DIR not in sys.path:
		sys.path.insert(0, _SCANNER_PKG_DIR)

	# Also ensure repository root is available for other top-level modules
	if _PROJECT_ROOT not in sys.path:
		sys.path.insert(0, _PROJECT_ROOT)
except Exception:
	# Best-effort only; if this fails, normal import errors will surface
	pass

