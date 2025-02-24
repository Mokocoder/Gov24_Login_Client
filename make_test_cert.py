import random

from cryptography import x509
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"CA131100001"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"GPKI"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Government of Korea"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"KR"),
])

subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"SVR1741597001"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Group of Server"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Government of Korea"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"KR"),
])

now = datetime.now(timezone.utc)
not_before = now - timedelta(days=1)
not_after  = now + timedelta(days=365*2)

serial_number = random.getrandbits(159)

builder = x509.CertificateBuilder()\
    .subject_name(subject)\
    .issuer_name(issuer)\
    .public_key(public_key)\
    .serial_number(serial_number)\
    .not_valid_before(not_before)\
    .not_valid_after(not_after)

builder = builder.add_extension(
    x509.BasicConstraints(ca=False, path_length=None), critical=True
)

builder = builder.add_extension(
    x509.KeyUsage(
        digital_signature=True,
        key_encipherment=True,
        data_encipherment=True,
        key_cert_sign=False,
        crl_sign=False,
        key_agreement=False,
        content_commitment=False,
        encipher_only=False,
        decipher_only=False
    ),
    critical=True
)

builder = builder.add_extension(
    x509.SubjectKeyIdentifier.from_public_key(public_key),
    critical=False
)

builder = builder.add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
    critical=False
)

builder = builder.add_extension(
    x509.CertificatePolicies([
        x509.PolicyInformation(
            x509.ObjectIdentifier("1.2.410.100001.2.1.2"),
            []
        )
    ]),
    critical=False
)

crl_dp = x509.DistributionPoint(
    full_name=[x509.UniformResourceIdentifier(
        u"ldap://cen.dir.go.kr:389/cn=crl1p1dp8335,cn=CA131100001,ou=GPKI,o=Government of Korea,c=KR?certificateRevocationList;binary"
    )],
    relative_name=None,
    reasons=None,
    crl_issuer=None
)
builder = builder.add_extension(
    x509.CRLDistributionPoints([crl_dp]),
    critical=False
)

aia = x509.AuthorityInformationAccess([
    x509.AccessDescription(
        AuthorityInformationAccessOID.OCSP,
        x509.UniformResourceIdentifier(u"http://gva.gpki.go.kr:8000")
    )
])
builder = builder.add_extension(aia, critical=False)

certificate = builder.sign(
    private_key=private_key,
    algorithm=hashes.SHA256(),
    backend=default_backend()
)

cert_der = certificate.public_bytes(serialization.Encoding.DER)
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.BestAvailableEncryption(b"q1w2e3")
)

with open("./테스트_인증서/test.der", "wb") as cert_file:
    cert_file.write(cert_der)

with open("./테스트_인증서/test.pem", "wb") as key_file:
    key_file.write(private_key_pem)