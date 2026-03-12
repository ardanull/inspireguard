from __future__ import annotations
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from app.core.config import get_settings
class PKIService:
    def __init__(self):
        self.settings = get_settings()
        self.base_dir = Path(self.settings.pki_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.ca_key_path = self.base_dir / 'root_ca.key.pem'
        self.ca_cert_path = self.base_dir / 'root_ca.crt.pem'
    def ensure_ca(self):
        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            return self.ca_key_path, self.ca_cert_path
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'TR'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.settings.mtls_ca_name),
            x509.NameAttribute(NameOID.COMMON_NAME, self.settings.mtls_ca_common_name),
        ])
        now = datetime.now(timezone.utc)
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256())
        self.ca_key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return self.ca_key_path, self.ca_cert_path
    def issue_agent_certificate(self, agent_id: str, validity_days: int = 90):
        self.ensure_ca()
        ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'SentinelGuard Agents'),
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        ])
        now = datetime.now(timezone.utc)
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=validity_days)).add_extension(x509.SubjectAlternativeName([x509.DNSName(agent_id)]), critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False).sign(ca_key, hashes.SHA256())
        return str(cert.serial_number), cert.fingerprint(hashes.SHA256()).hex(), cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'), key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode('utf-8'), self.ca_cert_path.read_text(encoding='utf-8')
