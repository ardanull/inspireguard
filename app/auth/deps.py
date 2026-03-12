from __future__ import annotations

import json
from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.security import decode_token
from app.models.user import User


def get_current_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='Missing bearer token')
    token = authorization.split(' ', 1)[1].strip()
    try:
        payload = decode_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    user = db.get(User, int(payload['sub']))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail='User inactive')
    return user


def require_role(*roles: str):
    def _checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail='Forbidden')
        return user
    return _checker


def require_permission(*permissions: str):
    def _checker(user: User = Depends(get_current_user)) -> User:
        current = set(json.loads(user.permissions_json or '[]'))
        if not set(permissions).issubset(current):
            raise HTTPException(status_code=403, detail='Missing permission')
        return user
    return _checker
