"""Shared pytest fixtures for k8s-piper tests.

All certificate generation uses the cryptography library so that tests work
on Python 3.6+ without embedding enormous PEM blobs in source files.
"""

import base64
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import ipaddress


# ---------------------------------------------------------------------------
# Helper to build a certificate
# ---------------------------------------------------------------------------

_NOW = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
_SERIAL = 0x01020304050607


def _build_cert(
    key,
    subject_name,
    issuer_name=None,
    issuer_key=None,
    is_ca=False,
    sans=None,
    not_before=None,
    not_after=None,
    add_aia=True,
    add_ocsp_staple=False,
):
    """Build and return a PEM-encoded certificate string."""
    if issuer_name is None:
        issuer_name = subject_name
    if issuer_key is None:
        issuer_key = key
    if not_before is None:
        not_before = _NOW
    if not_after is None:
        not_after = _NOW + datetime.timedelta(days=365)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(_SERIAL)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None), critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    )

    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False
        )

    if add_aia:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        x509.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("http://ocsp.example.com"),
                    ),
                    x509.AccessDescription(
                        x509.AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(
                            "http://ca.example.com/ca.crt"
                        ),
                    ),
                ]
            ),
            critical=False,
        )
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(
                                "http://crl.example.com/crl.pem"
                            )
                        ],
                        relative_name=None,
                        crl_issuer=None,
                        reasons=None,
                    )
                ]
            ),
            critical=False,
        )

    if add_ocsp_staple:
        builder = builder.add_extension(
            x509.TLSFeature([x509.TLSFeatureType.status_request]),
            critical=False,
        )

    if not is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )

    cert = builder.sign(issuer_key, hashes.SHA256(), default_backend())
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ---------------------------------------------------------------------------
# Session-scoped fixtures (expensive key generation done once)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def leaf_pem():
    """RSA leaf certificate with SANs, AIA, EKU, and OCSP must-staple."""
    key = rsa.generate_private_key(65537, 2048, default_backend())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp Ltd"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )
    return _build_cert(
        key,
        subject,
        sans=[
            x509.DNSName("test.example.com"),
            x509.DNSName("www.test.example.com"),
            x509.IPAddress(ipaddress.IPv4Address("10.0.0.1")),
        ],
        add_aia=True,
        add_ocsp_staple=True,
    )


@pytest.fixture(scope="session")
def ca_pem():
    """Self-signed RSA CA certificate."""
    key = rsa.generate_private_key(65537, 2048, default_backend())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp Ltd"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
        ]
    )
    return _build_cert(key, subject, is_ca=True, add_aia=False)


@pytest.fixture(scope="session")
def ec_pem():
    """EC (P-256) leaf certificate."""
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "ec.example.com")]
    )
    return _build_cert(
        key,
        subject,
        sans=[x509.DNSName("ec.example.com")],
        add_aia=False,
    )


@pytest.fixture(scope="session")
def expired_pem():
    """RSA certificate whose validity period is in the past."""
    key = rsa.generate_private_key(65537, 2048, default_backend())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "expired.example.com")]
    )
    return _build_cert(
        key,
        subject,
        not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc),
        add_aia=False,
        sans=[],
    )


@pytest.fixture(scope="session")
def leaf_b64(leaf_pem):
    """Base64-encoded leaf PEM (as stored in a K8s Secret)."""
    return base64.b64encode(leaf_pem.encode()).decode()


@pytest.fixture(scope="session")
def bundle_b64(leaf_pem, ca_pem):
    """Base64-encoded PEM bundle with two certificates."""
    return base64.b64encode((leaf_pem + "\n" + ca_pem).encode()).decode()
