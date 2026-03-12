from __future__ import annotations

from collections import deque
from time import time
from typing import Deque, Generic, Iterable, TypeVar

T = TypeVar("T")


class SlidingWindow(Generic[T]):
    def __init__(self, window_seconds: int | float):
        self.window_seconds = window_seconds
        self.events: Deque[tuple[float, T]] = deque()

    def add(self, value: T, timestamp: float | None = None) -> None:
        ts = timestamp if timestamp is not None else time()
        self.events.append((ts, value))
        self.prune(ts)

    def prune(self, now: float | None = None) -> None:
        current = now if now is not None else time()
        while self.events and current - self.events[0][0] > self.window_seconds:
            self.events.popleft()

    def values(self) -> Iterable[T]:
        return (value for _, value in self.events)

    def count(self) -> int:
        return len(self.events)
