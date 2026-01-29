import logging
from pythonjsonlogger import jsonlogger


def setup_logging(level: str) -> None:
    logger = logging.getLogger()
    logger.setLevel(level)

    # Remove default handlers to avoid duplicate logs
    while logger.handlers:
        logger.handlers.pop()

    handler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s %(request_id)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
