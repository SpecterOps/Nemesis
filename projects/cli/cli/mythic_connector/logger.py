import logging


def get_logger(name):
    logger = logging.getLogger(name)
    # This will only set the level if it hasn't been set already
    if not logger.level:
        logger.setLevel(logging.getLogger("mythic_connector").level)
    return logger
