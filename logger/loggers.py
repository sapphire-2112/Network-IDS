import logging
import os
from logging.handlers import TimedRotatingFileHandler

LOG_DIR = "logs"
LOG_FILE = "ids.log"

os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, LOG_FILE)

logger = logging.getLogger("NetworkIDS")
logger.setLevel(logging.INFO)
logger.propagate = False   # 🔥 VERY IMPORTANT

# Prevent duplicate handlers
if not logger.handlers:

    file_handler = TimedRotatingFileHandler(
        log_path,
        when="midnight",
        interval=1,
        backupCount=7,
        encoding="utf-8",
        utc=False
    )

    file_handler.suffix = "%Y-%m-%d"

    console_handler = logging.StreamHandler()

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
