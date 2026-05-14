"""Tests for k8s_piper.cert_analyzer."""

import pytest

from k8s_piper.cert_analyzer import (
    CertBundle,
    analyse_certificate,
    extract_cert_bundles,
    extract_non_cert_data,
    extract_pem_certs,
)
from k8s_piper.k8s_manifest import K8sManifest


# ---------------------------------------------------------------------------
# extract_pem_certs
# ---------------------------------------------------------------------------


class TestExtractPemCerts:
    def test_single_cert(self, leaf_pem):
        certs = extract_pem_certs(leaf_pem)
        assert len(certs) == 1
        assert "BEGIN CERTIFICATE" in certs[0]

    def test_bundle_of_two(self, leaf_pem, ca_pem):
        bundle = leaf_pem + "\n" + ca_pem
        certs = extract_pem_certs(bundle)
        assert len(certs) == 2

    def test_no_certs(self):
        assert extract_pem_certs("just some text, no certs here") == []

    def test_cert_embedded_in_yaml(self, leaf_pem):
        yaml_like = "data:\n  tls.crt: |\n    " + "\n    ".join(leaf_pem.splitlines())
        certs = extract_pem_certs(yaml_like)
        assert len(certs) == 1


# ---------------------------------------------------------------------------
# analyse_certificate – RSA leaf
# ---------------------------------------------------------------------------


class TestAnalyseCertificateLeaf:
    @pytest.fixture(autouse=True)
    def setup(self, leaf_pem):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert_obj = x509.load_pem_x509_certificate(leaf_pem.encode(), default_backend())
        self.info = analyse_certificate(cert_obj)

    def test_subject_cn(self):
        cn_values = [v for k, v in self.info["subject"] if k == "CN"]
        assert cn_values == ["test.example.com"]

    def test_subject_org(self):
        org_values = [v for k, v in self.info["subject"] if k == "O"]
        assert org_values == ["Test Corp Ltd"]

    def test_key_type_rsa(self):
        assert self.info["key_type"] == "RSA"
        assert self.info["key_bits"] == 2048

    def test_signature_algorithm(self):
        assert "sha256" in self.info["signature_algorithm"].lower()

    def test_not_self_signed(self):
        assert self.info["is_self_signed"] is True  # self-signed (no issuer CA in fixture)

    def test_is_not_ca(self):
        assert self.info["is_ca"] is False

    def test_sans_present(self):
        assert len(self.info["sans"]) == 3
        san_types = [t for t, _ in self.info["sans"]]
        assert "DNS" in san_types
        assert "IP" in san_types

    def test_ocsp_url(self):
        assert "http://ocsp.example.com" in self.info["ocsp_urls"]

    def test_ca_issuers_url(self):
        assert "http://ca.example.com/ca.crt" in self.info["ca_issuer_urls"]

    def test_crl_url(self):
        assert "http://crl.example.com/crl.pem" in self.info["crl_urls"]

    def test_ocsp_must_staple(self):
        assert self.info["ocsp_must_staple"] is True

    def test_key_usage(self):
        assert "Digital Signature" in self.info["key_usage"]
        assert "Key Encipherment" in self.info["key_usage"]

    def test_extended_key_usage(self):
        assert "TLS Web Server Authentication" in self.info["extended_key_usage"]
        assert "TLS Web Client Authentication" in self.info["extended_key_usage"]

    def test_fingerprints(self):
        # SHA-256 is 32 bytes = 95 chars in colon-hex (32*2 + 31 colons)
        assert len(self.info["fingerprint_sha256"]) == 95
        # SHA-1 is 20 bytes = 59 chars
        assert len(self.info["fingerprint_sha1"]) == 59

    def test_serial_hex(self):
        assert self.info["serial"] == "01:02:03:04:05:06:07"

    def test_validity_fields_present(self):
        assert self.info["not_before"] is not None
        assert self.info["not_after"] is not None
        assert isinstance(self.info["days_remaining"], int)


# ---------------------------------------------------------------------------
# analyse_certificate – CA cert
# ---------------------------------------------------------------------------


class TestAnalyseCertificateCA:
    @pytest.fixture(autouse=True)
    def setup(self, ca_pem):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert_obj = x509.load_pem_x509_certificate(ca_pem.encode(), default_backend())
        self.info = analyse_certificate(cert_obj)

    def test_is_ca(self):
        assert self.info["is_ca"] is True

    def test_is_self_signed(self):
        assert self.info["is_self_signed"] is True

    def test_no_sans(self):
        assert self.info["sans"] == []

    def test_no_ocsp_must_staple(self):
        assert self.info["ocsp_must_staple"] is False


# ---------------------------------------------------------------------------
# analyse_certificate – EC cert
# ---------------------------------------------------------------------------


class TestAnalyseCertificateEC:
    @pytest.fixture(autouse=True)
    def setup(self, ec_pem):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert_obj = x509.load_pem_x509_certificate(ec_pem.encode(), default_backend())
        self.info = analyse_certificate(cert_obj)

    def test_key_type_ec(self):
        assert "EC" in self.info["key_type"]

    def test_key_bits(self):
        assert self.info["key_bits"] == 256


# ---------------------------------------------------------------------------
# analyse_certificate – expired cert
# ---------------------------------------------------------------------------


class TestAnalyseCertificateExpired:
    @pytest.fixture(autouse=True)
    def setup(self, expired_pem):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert_obj = x509.load_pem_x509_certificate(expired_pem.encode(), default_backend())
        self.info = analyse_certificate(cert_obj)

    def test_is_expired(self):
        assert self.info["is_expired"] is True

    def test_negative_days_remaining(self):
        assert self.info["days_remaining"] < 0


# ---------------------------------------------------------------------------
# extract_cert_bundles – from K8s manifests
# ---------------------------------------------------------------------------


class TestExtractCertBundles:
    def _make_configmap(self, data):
        # type: (dict) -> str
        lines = ["apiVersion: v1", "kind: ConfigMap", "metadata:", "  name: mymap", "  namespace: default", "data:"]
        for key, value in data.items():
            lines.append("  {0}: |".format(key))
            for vline in value.splitlines():
                lines.append("    " + vline)
        return "\n".join(lines)

    def test_single_cert_configmap(self, leaf_pem):
        yaml_str = self._make_configmap({"ca.crt": leaf_pem})
        manifest = K8sManifest(yaml_str)
        bundles = extract_cert_bundles(manifest)
        assert len(bundles) == 1
        assert bundles[0].source_key == "ca.crt"
        assert len(bundles[0].certs) == 1

    def test_bundle_configmap(self, leaf_pem, ca_pem):
        bundle_pem = leaf_pem + "\n" + ca_pem
        yaml_str = self._make_configmap({"bundle.crt": bundle_pem})
        manifest = K8sManifest(yaml_str)
        bundles = extract_cert_bundles(manifest)
        assert len(bundles) == 1
        assert len(bundles[0].certs) == 2

    def test_multiple_keys(self, leaf_pem, ca_pem):
        yaml_str = self._make_configmap({"tls.crt": leaf_pem, "ca.crt": ca_pem})
        manifest = K8sManifest(yaml_str)
        bundles = extract_cert_bundles(manifest)
        assert len(bundles) == 2

    def test_no_certs_in_key(self):
        yaml_str = self._make_configmap({"config.yaml": "key: value"})
        manifest = K8sManifest(yaml_str)
        bundles = extract_cert_bundles(manifest)
        assert len(bundles) == 0

    def test_secret_with_b64_cert(self, leaf_b64):
        import yaml
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "mysecret", "namespace": "default"},
            "data": {"tls.crt": leaf_b64},
        }
        yaml_str = yaml.dump(secret)
        manifest = K8sManifest(yaml_str)
        bundles = extract_cert_bundles(manifest)
        assert len(bundles) == 1
        assert len(bundles[0].certs) == 1


# ---------------------------------------------------------------------------
# extract_non_cert_data
# ---------------------------------------------------------------------------


class TestExtractNonCertData:
    def _make_configmap(self, data):
        # type: (dict) -> str
        lines = ["apiVersion: v1", "kind: ConfigMap", "metadata:", "  name: mymap", "  namespace: default", "data:"]
        for key, value in data.items():
            lines.append("  {0}: |".format(key))
            for vline in value.splitlines():
                lines.append("    " + vline)
        return "\n".join(lines)

    def test_non_cert_key_returned(self):
        yaml_str = self._make_configmap({"config.yaml": "key: value\nother: data"})
        manifest = K8sManifest(yaml_str)
        result = extract_non_cert_data(manifest)
        assert len(result) == 1
        assert result[0][0] == "config.yaml"
        assert "key: value" in result[0][1]

    def test_cert_key_excluded(self, leaf_pem):
        yaml_str = self._make_configmap({"ca.crt": leaf_pem})
        manifest = K8sManifest(yaml_str)
        result = extract_non_cert_data(manifest)
        assert result == []

    def test_mixed_keys_only_non_cert_returned(self, leaf_pem):
        yaml_str = self._make_configmap({"ca.crt": leaf_pem, "app.conf": "host=localhost"})
        manifest = K8sManifest(yaml_str)
        result = extract_non_cert_data(manifest)
        assert len(result) == 1
        assert result[0][0] == "app.conf"

    def test_multiple_non_cert_keys(self):
        yaml_str = self._make_configmap({"a.txt": "hello", "b.json": '{"x": 1}'})
        manifest = K8sManifest(yaml_str)
        result = extract_non_cert_data(manifest)
        assert len(result) == 2
        keys = [k for k, _ in result]
        assert "a.txt" in keys
        assert "b.json" in keys

    def test_empty_data(self):
        yaml_str = "\n".join([
            "apiVersion: v1", "kind: ConfigMap",
            "metadata:", "  name: empty", "  namespace: default",
        ])
        manifest = K8sManifest(yaml_str)
        result = extract_non_cert_data(manifest)
        assert result == []

    def test_secret_non_cert_decoded(self):
        import base64
        import yaml
        encoded = base64.b64encode(b"mysecretpassword").decode()
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "mysecret", "namespace": "default"},
            "data": {"password": encoded},
        }
        manifest = K8sManifest(yaml.dump(secret))
        result = extract_non_cert_data(manifest)
        assert len(result) == 1
        assert result[0][0] == "password"
        assert result[0][1] == "mysecretpassword"
