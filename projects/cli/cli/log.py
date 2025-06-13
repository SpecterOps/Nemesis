import logging


def setup_logging(debug: bool = False):
    """Configure logging with the specified level"""
    log_level = logging.DEBUG if debug else logging.INFO
    # logging.basicConfig(level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    logging.basicConfig(level=log_level, format="%(levelname)s - %(name)s - %(message)s")
    return logging.getLogger(__name__)
