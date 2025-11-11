import os
from setuptools import setup, find_packages

# Read requirements if available
reqs = []
req_file = os.path.join(os.path.dirname(__file__), 'requirements.txt')
if os.path.exists(req_file):
    with open(req_file, 'r', encoding='utf-8') as f:
        reqs = [r.strip() for r in f.readlines() if r.strip() and not r.strip().startswith('#')]

setup(
    name='vuln-scanner-flask',
    version='0.1.0',
    description='Vuln Scanner Flask application',
    packages=find_packages(where='.'),
    include_package_data=True,
    install_requires=reqs,
    python_requires='>=3.8',
)
