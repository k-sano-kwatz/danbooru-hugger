import logging

from config import settings

logger = logging.getLogger('uvicorn.error')
logger.setLevel(settings.logging.level)
