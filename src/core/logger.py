"""Sozo Enterprise Logger (E1). Replaces raw print() statements."""
import logging
import sys

def get_logger(name: str):
    """Returns a configured logger for a specific Sozo module."""
    logger = logging.getLogger(f"sozo.{name}")
    
    # Prevent adding multiple handlers if called multiple times
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        
        # Format: [HH:MM:SS] [LEVEL] [module] message
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
            datefmt='%H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
    return logger
