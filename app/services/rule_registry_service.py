from __future__ import annotations

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.rule_definition import RuleDefinition


class RuleRegistryService:
    def __init__(self, db: Session):
        self.db = db

    def create_version(self, rule_id: str, title: str, level: str, rule_yaml: str, tenant_id: int | None = None, notes: str = '', status: str = 'draft') -> RuleDefinition:
        current = self.db.scalar(select(RuleDefinition).where(RuleDefinition.rule_id == rule_id).order_by(desc(RuleDefinition.version)))
        version = 1 if current is None else current.version + 1
        row = RuleDefinition(rule_id=rule_id, title=title, version=version, level=level, rule_yaml=rule_yaml, tenant_id=tenant_id, notes=notes, status=status, is_active=False)
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def promote(self, rule_id: str, version: int) -> RuleDefinition:
        rows = list(self.db.scalars(select(RuleDefinition).where(RuleDefinition.rule_id == rule_id)))
        target = None
        for row in rows:
            row.is_active = False
            if row.version == version:
                target = row
        if target is None:
            raise ValueError('Rule version not found')
        target.is_active = True
        target.status = 'active'
        self.db.commit()
        self.db.refresh(target)
        return target

    def list_rules(self) -> list[RuleDefinition]:
        return list(self.db.scalars(select(RuleDefinition).order_by(RuleDefinition.rule_id.asc(), RuleDefinition.version.desc())))
