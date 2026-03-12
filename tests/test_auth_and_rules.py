from app.auth.security import create_token, decode_token, hash_password, verify_password
from app.detectors.base import PacketEvent
from app.services.rule_service import SigmaLikeRuleEngine


def test_password_hash_roundtrip():
    digest = hash_password("hunter2")
    assert verify_password("hunter2", digest)
    assert not verify_password("wrong", digest)


def test_token_roundtrip():
    token = create_token("1", "admin", 10)
    payload = decode_token(token)
    assert payload["sub"] == "1"
    assert payload["role"] == "admin"


def test_sigma_like_rule_engine_matches_ssh_event():
    engine = SigmaLikeRuleEngine("rules")
    matches = engine.evaluate(PacketEvent(protocol="TCP", src_ip="10.0.0.5", dst_ip="10.0.0.10", dst_port=22, tcp_flags="S"))
    assert matches
    assert matches[0].detector.startswith("sigma_")
