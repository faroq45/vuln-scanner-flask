from core.workers import start_workers
import logging, time
logging.basicConfig(level=logging.DEBUG)
start_workers()
print("Workers started; sleeping 60s to observe logs")
time.sleep(60)
