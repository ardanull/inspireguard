from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from app.core.config import get_settings
from app.stream.manager import manager

logger = logging.getLogger(__name__)
settings = get_settings()


class NotificationService:
    def _publish(self, channel: str, payload: dict[str, Any]):
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(manager.broadcast(channel, payload))
        except RuntimeError:
            logger.info('No running loop for websocket publication on %s: %s', channel, json.dumps(payload)[:200])

    def publish_alert(self, payload: dict[str, Any]):
        self._publish(settings.websocket_channel, payload)

    def publish_incident(self, payload: dict[str, Any]):
        self._publish('incidents', payload)
