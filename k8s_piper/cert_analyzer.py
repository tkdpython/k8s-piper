"""Extract and analyse X.509 certificates from Kubernetes manifests."""

import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    dh,
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
)
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

# Regex to extract PEM certificate blocks (handles CERTIFICATE and TRUSTED CERTIFICATE)
_PEM_CERT_RE = re.compile(
    r"-----BEGIN (?:TRUSTED )?CERTIFICATE-----"
    r"[\s\S]+?"
    r"-----END (?:TRUSTED )?CERTIFICATE-----",
    re.MULTILINE,
)

# Friendly names for Extended Key Usage OIDs
_EKU_NAMES = {
    ExtendedKeyUsageOID.SERVER_AUTH: "TLS Web Server Authentication",
    ExtendedKeyUsageOID.CLIENT_AUTH: "TLS Web Client Authentication",
    ExtendedKeyUsageOID.CODE_SIGNING: "Code Signing",
    ExtendedKeyUsageOID.EMAIL_PROTECTION: "E-mail Protection",
    ExtendedKeyUsageOID.TIME_STAMPING: "Time Stamping",
    ExtendedKeyUsageOID.OCSP_SIGNING: "OCSP Signing",
}

# Key Usage bit names
_KEY_USAGE_ATTRS = [
    ("digital_signature", "Digital Signature"),
    ("content_commitment", "Content Commitment (Non-Repudiation)"),
    ("key_encipherment", "Key Encipherment"),
    ("data_encipherment", "Data Encipherment"),
    ("key_agreement", "Key Agreement"),
    ("key_cert_sign", "Certificate Sign"),
    ("crl_sign", "CRL Sign"),
    ("encipher_only", "Encipher Only"),
    ("decipher_only", "Decipher Only"),
]

# Friendly names for common Subject/Issuer OIDs
_NAME_OID_MAP = {
    NameOID.COMMON_NAME: "CN",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.COUNTRY_NAME: "C",
    NameOID.STATE_OR_PROVINCE_NAME: "ST",
    NameOID.LOCALITY_NAME: "L",
    NameOID.EMAIL_ADDRESS: "emailAddress",
    NameOID.SERIAL_NUMBER: "serialNumber",
    NameOID.DOMAIN_COMPONENT: "DC",
    NameOID.USER_ID: "UID",
}


def _load_cert(pem_bytes):
    # type: (bytes) -> x509.Certificate
    """Load a PEM certificate, supporting both old and new cryptography APIs."""
    try:
        return x509.load_pem_x509_certificate(pem_bytes)
    except TypeError:
        # cryptography < 35 requires the backend argument
        from cryptography.hazmat.backends import default_backend  # noqa: F401
        return x509.load_pem_x509_certificate(pem_bytes, default_backend())


def extract_pem_certs(text):
    # type: (str) -> List[str]
    """Return a list of PEM certificate strings found in *text*."""
    return _PEM_CERT_RE.findall(text)


def _name_attrs(name):
    # type: (x509.Name) -> List[Tuple[str, str]]
    """Convert an x509.Name into an ordered list of (label, value) tuples."""
    result = []
    for attr in name:
        label = _NAME_OID_MAP.get(attr.oid, attr.oid.dotted_string)
        result.append((label, attr.value))
    return result


def _fingerprint(cert, algo):
    # type: (x509.Certificate, hashes.HashAlgorithm) -> str
    """Return colon-separated hex fingerprint."""
    raw = cert.fingerprint(algo)
    return ":".join("{:02X}".format(b) for b in raw)


def _serial_hex(serial):
    # type: (int) -> str
    """Format a serial number as colon-separated hex."""
    hex_str = "{:X}".format(serial)
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    return ":".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))


def _key_info(public_key):
    # type: (object) -> Tuple[str, Optional[int]]
    """Return (key_type, key_bits) for a public key."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC ({})".format(public_key.curve.name), public_key.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448
    if isinstance(public_key, dh.DHPublicKey):
        return "DH", public_key.key_size
    return type(public_key).__name__, None


def _utc_now():
    # type: () -> datetime
    """Return current UTC datetime with timezone info."""
    return datetime.now(timezone.utc)


def _ensure_utc(dt):
    # type: (datetime) -> datetime
    """Attach UTC timezone to a naive datetime (legacy cryptography returns naive datetimes)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def analyse_certificate(cert):
    # type: (x509.Certificate) -> dict
    """Extract all useful fields from an x509.Certificate into a plain dict."""
    now = _utc_now()
    not_before = _ensure_utc(cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before)
    not_after = _ensure_utc(cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after)
    delta = not_after - now
    days_remaining = delta.days

    public_key = cert.public_key()
    key_type, key_bits = _key_info(public_key)

    subject_attrs = _name_attrs(cert.subject)
    issuer_attrs = _name_attrs(cert.issuer)
    is_self_signed = cert.subject == cert.issuer

    # --- Subject Alternative Names ---
    sans = []  # type: List[Tuple[str, str]]
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(("DNS", name.value))
            elif isinstance(name, x509.IPAddress):
                sans.append(("IP", str(name.value)))
            elif isinstance(name, x509.RFC822Name):
                sans.append(("Email", name.value))
            elif isinstance(name, x509.UniformResourceIdentifier):
                sans.append(("URI", name.value))
            elif isinstance(name, x509.DirectoryName):
                sans.append(("DirName", str(name.value)))
            else:
                sans.append(("Other", str(name)))
    except x509.ExtensionNotFound:
        pass

    # --- Key Usage ---
    key_usage = []  # type: List[str]
    try:
        ku_ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
        for attr, label in _KEY_USAGE_ATTRS:
            try:
                if getattr(ku_ext.value, attr):
                    key_usage.append(label)
            except ValueError:
                # Some attributes raise ValueError when the bit is not applicable
                pass
    except x509.ExtensionNotFound:
        pass

    # --- Extended Key Usage ---
    extended_key_usage = []  # type: List[str]
    try:
        eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        for oid in eku_ext.value:
            extended_key_usage.append(_EKU_NAMES.get(oid, oid.dotted_string))
    except x509.ExtensionNotFound:
        pass

    # --- Basic Constraints ---
    is_ca = False
    path_length = None  # type: Optional[int]
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = bc.value.ca
        path_length = bc.value.path_length
    except x509.ExtensionNotFound:
        pass

    # --- Authority Information Access (OCSP / CA Issuers) ---
    ocsp_urls = []  # type: List[str]
    ca_issuer_urls = []  # type: List[str]
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for access in aia.value:
            if access.access_method == AuthorityInformationAccessOID.OCSP:
                ocsp_urls.append(access.access_location.value)
            elif access.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                ca_issuer_urls.append(access.access_location.value)
    except x509.ExtensionNotFound:
        pass

    # --- CRL Distribution Points ---
    crl_urls = []  # type: List[str]
    try:
        cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        for point in cdp.value:
            if point.full_name:
                for name in point.full_name:
                    if hasattr(name, "value"):
                        crl_urls.append(name.value)
    except x509.ExtensionNotFound:
        pass

    # --- OCSP Must-Staple (TLS Feature extension, RFC 7633) ---
    ocsp_must_staple = False
    try:
        tls_feature = cert.extensions.get_extension_for_class(x509.TLSFeature)
        ocsp_must_staple = x509.TLSFeatureType.status_request in tls_feature.value
    except x509.ExtensionNotFound:
        pass

    # --- Subject / Authority Key Identifiers ---
    subject_key_id = None  # type: Optional[str]
    try:
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        subject_key_id = ":".join("{:02X}".format(b) for b in ski.value.digest)
    except x509.ExtensionNotFound:
        pass

    authority_key_id = None  # type: Optional[str]
    try:
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        if aki.value.key_identifier:
            authority_key_id = ":".join(
                "{:02X}".format(b) for b in aki.value.key_identifier
            )
    except x509.ExtensionNotFound:
        pass

    # --- Signature algorithm ---
    try:
        sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    except Exception:
        sig_alg = "unknown"

    return {
        "subject": subject_attrs,
        "issuer": issuer_attrs,
        "serial": _serial_hex(cert.serial_number),
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days_remaining,
        "is_expired": days_remaining < 0,
        "key_type": key_type,
        "key_bits": key_bits,
        "signature_algorithm": sig_alg,
        "sans": sans,
        "key_usage": key_usage,
        "extended_key_usage": extended_key_usage,
        "is_ca": is_ca,
        "path_length": path_length,
        "ocsp_urls": ocsp_urls,
        "ca_issuer_urls": ca_issuer_urls,
        "crl_urls": crl_urls,
        "ocsp_must_staple": ocsp_must_staple,
        "fingerprint_sha256": _fingerprint(cert, hashes.SHA256()),
        "fingerprint_sha1": _fingerprint(cert, hashes.SHA1()),
        "is_self_signed": is_self_signed,
        "subject_key_id": subject_key_id,
        "authority_key_id": authority_key_id,
    }


class CertBundle:
    """A named collection of certificates extracted from one K8s data key."""

    def __init__(self, source_key, certs, errors=None):
        # type: (str, List[dict], Optional[List[str]]) -> None
        self.source_key = source_key
        self.certs = certs        # list of dicts from analyse_certificate()
        self.errors = errors or []  # parse errors for individual PEM blocks


def extract_cert_bundles(manifest):
    """Extract CertBundle objects from a parsed K8sManifest.

    Each data key that contains at least one PEM certificate becomes a bundle.
    """
    bundles = []  # type: List[CertBundle]
    for key, value in manifest.data.items():
        if not value:
            continue
        pem_blocks = extract_pem_certs(value)
        if not pem_blocks:
            continue

        certs = []
        errors = []
        for pem in pem_blocks:
            try:
                cert_obj = _load_cert(pem.encode("utf-8"))
                certs.append(analyse_certificate(cert_obj))
            except Exception as exc:
                errors.append("Failed to parse certificate: {0}".format(exc))

        if certs or errors:
            bundles.append(CertBundle(source_key=key, certs=certs, errors=errors))

    return bundles


def extract_non_cert_data(manifest):
    # type: (object) -> List[Tuple[str, str]]
    """Return data entries from a manifest that contain no PEM certificates.

    Returns a list of (key, value) pairs for every data entry whose value does
    not contain at least one PEM certificate block.  Values that are empty or
    None are skipped.
    """
    result = []
    for key, value in manifest.data.items():
        if not value:
            continue
        if not extract_pem_certs(value):
            result.append((key, value))
    return result
