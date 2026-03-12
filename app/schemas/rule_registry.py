from pydantic import BaseModel


class RuleVersionCreate(BaseModel):
    rule_id: str
    title: str
    level: str = 'medium'
    rule_yaml: str
    notes: str = ''


class RulePromoteRequest(BaseModel):
    version: int
