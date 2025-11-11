# attacker_verbose.py — one-off verbose attacker runner
import logging
import os
# make sure loggers are verbose
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(process)d - %(message)s")
root = logging.getLogger()
root.setLevel(logging.DEBUG)
# be explicit for the app logger name used in your project
logging.getLogger('vulscanner').setLevel(logging.DEBUG)

# run the attacker loop
from bin.attacker import attacker

if __name__ == "__main__":
    print("Starting attacker_verbose (DEBUG). Press Ctrl+C to stop.")
    attacker()
