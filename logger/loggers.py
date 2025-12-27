import logging ##Using Python's built-in logging module
import os
from logging.handlers import TimedRotatingFileHandler

LOG_DIR = "logs"
LOG_FILE = "ids.log"

os.makedirs(LOG_DIR, exist_ok=True)

log_path = os.path.join(LOG_DIR, LOG_FILE)

file_handler = TimedRotatingFileHandler(
    log_path,
    when="midnight",     # rotate at midnight
    interval=1,          # every 1 day
    backupCount=7        # keep last 7 days
)


console_handler = logging.StreamHandler()

formatter = logging.Formatter(
    '[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)


logging.basicConfig(
    level=logging.INFO,
    handlers=[file_handler, console_handler]
)

logger = logging.getLogger("NetworkIDS")