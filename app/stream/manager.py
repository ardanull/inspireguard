from __future__ import annotations
import asyncio, json, logging
from collections import defaultdict
from typing import Any
from fastapi import WebSocket
from app.core.config import get_settings
try:
    from redis.asyncio import Redis
except Exception:
    Redis = None
logger = logging.getLogger(__name__)
settings = get_settings()
class WebSocketManager:
    def __init__(self):
        self.connections: dict[str, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()
        self.redis = None
        self.listener_task = None
    async def connect(self, channel: str, websocket: WebSocket):
        await websocket.accept();
        async with self._lock: self.connections[channel].add(websocket)
    async def disconnect(self, channel: str, websocket: WebSocket):
        async with self._lock: self.connections[channel].discard(websocket)
    async def start(self):
        if Redis is None or self.listener_task is not None: return
        try:
            self.redis = Redis.from_url(settings.redis_url, decode_responses=True)
            pubsub = self.redis.pubsub(); await pubsub.subscribe(settings.redis_fanout_channel)
            self.listener_task = asyncio.create_task(self._listen(pubsub))
        except Exception as exc:
            logger.warning('Redis pubsub disabled: %s', exc); self.redis = None
    async def _listen(self, pubsub):
        async for message in pubsub.listen():
            if message.get('type') != 'message': continue
            data = json.loads(message['data'])
            await self._broadcast_local(data.get('channel', 'alerts'), data.get('payload', {}))
    async def broadcast(self, channel: str, payload: dict[str, Any]):
        await self._broadcast_local(channel, payload)
        if self.redis is not None:
            try: await self.redis.publish(settings.redis_fanout_channel, json.dumps({'channel': channel, 'payload': payload}, ensure_ascii=False))
            except Exception as exc: logger.warning('Redis publish failed: %s', exc)
    async def _broadcast_local(self, channel: str, payload: dict[str, Any]):
        dead = []
        for ws in list(self.connections[channel]):
            try: await ws.send_text(json.dumps(payload, ensure_ascii=False))
            except Exception: dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead: self.connections[channel].discard(ws)
manager = WebSocketManager()
