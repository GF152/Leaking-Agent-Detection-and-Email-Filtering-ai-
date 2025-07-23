"""
Logging Utility Module
"""
import logging
import logging.handlers
import os

def setup_logger(name=None, log_file="logs/system.log", level=logging.INFO):
    """Setup logger with file and console handlers"""

    logger = logging.getLogger(name or 'LeakingAgentDetectionSystem')
    logger.setLevel(level)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=100*1024*1024, backupCount=5
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
