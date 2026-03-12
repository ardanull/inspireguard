from __future__ import annotations
import base64, json, secrets, urllib.parse
from datetime import datetime, timedelta
from app.core.config import get_settings
class OIDCProtocolService:
    def __init__(self): self.settings = get_settings()
    def build_authorization_url(self, provider: dict, redirect_uri: str | None = None, scope: str = 'openid profile email'):
        state = secrets.token_urlsafe(24); nonce = secrets.token_urlsafe(24)
        params = {'client_id': provider['client_id'], 'response_type': 'code', 'redirect_uri': redirect_uri or self.settings.sso_default_redirect_uri, 'scope': scope, 'state': state, 'nonce': nonce}
        return {'authorization_url': provider['authorize_url'] + '?' + urllib.parse.urlencode(params), 'state': state, 'nonce': nonce}
class SAMLProtocolService:
    def build_authn_request(self, provider: dict, acs_url: str):
        request = {'id': secrets.token_hex(12), 'issue_instant': datetime.utcnow().isoformat() + 'Z', 'destination': provider['sso_url'], 'entity_id': provider['entity_id'], 'assertion_consumer_service_url': acs_url}
        return {'binding': 'HTTP-Redirect', 'request': base64.b64encode(json.dumps(request).encode('utf-8')).decode('ascii')}
    def mock_assertion(self, email: str, full_name: str, valid_minutes: int = 5):
        assertion = {'email': email, 'full_name': full_name, 'exp': (datetime.utcnow() + timedelta(minutes=valid_minutes)).isoformat() + 'Z'}
        return base64.b64encode(json.dumps(assertion).encode('utf-8')).decode('ascii')
