from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset


class AssetService:
    def __init__(self, db: Session):
        self.db = db

    def upsert_ip(self, ip_address: str | None) -> Asset | None:
        if not ip_address:
            return None
        asset = self.db.scalar(select(Asset).where(Asset.ip_address == ip_address))
        if asset:
            return asset
        asset = Asset(ip_address=ip_address, tags_json=json.dumps(["observed"]))
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)
        return asset

    def list_assets(self, limit: int = 100) -> list[Asset]:
        return list(self.db.scalars(select(Asset).limit(limit)))
