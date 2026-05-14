"""Tests for k8s_piper.display — non-cert data display and pager context."""

import base64
import io

import pytest
import yaml

from rich.console import Console

from k8s_piper.cert_analyzer import extract_cert_bundles, extract_non_cert_data
from k8s_piper.display import display_certs, display_non_cert_data, pager_context
from k8s_piper.k8s_manifest import K8sManifest


def _make_configmap(data):
    # type: (dict) -> str
    lines = [
        "apiVersion: v1", "kind: ConfigMap",
        "metadata:", "  name: mymap", "  namespace: default", "data:",
    ]
    for key, value in data.items():
        lines.append("  {0}: |".format(key))
        for vline in value.splitlines():
            lines.append("    " + vline)
    return "\n".join(lines)


def _capture(fn, *args, **kwargs):
    """Run *fn* with all display output captured and return the string."""
    buf = io.StringIO()
    console = Console(file=buf, highlight=False, no_color=True)
    import k8s_piper.display as display_module
    orig = display_module._console
    display_module._console = console
    try:
        fn(*args, **kwargs)
    finally:
        display_module._console = orig
    return buf.getvalue()


# ---------------------------------------------------------------------------
# display_non_cert_data
# ---------------------------------------------------------------------------


class TestDisplayNonCertData:
    def test_no_output_when_empty(self):
        yaml_str = "\n".join([
            "apiVersion: v1", "kind: ConfigMap",
            "metadata:", "  name: empty", "  namespace: default",
        ])
        manifest = K8sManifest(yaml_str)
        out = _capture(display_non_cert_data, manifest, [])
        assert out == ""

    def test_key_shown_in_output(self):
        yaml_str = _make_configmap({"app.conf": "host=localhost\nport=8080"})
        manifest = K8sManifest(yaml_str)
        non_cert = extract_non_cert_data(manifest)
        out = _capture(display_non_cert_data, manifest, non_cert)
        assert "app.conf" in out
        assert "host=localhost" in out

    def test_multiple_keys_shown(self):
        yaml_str = _make_configmap({"a.txt": "hello", "b.txt": "world"})
        manifest = K8sManifest(yaml_str)
        non_cert = extract_non_cert_data(manifest)
        out = _capture(display_non_cert_data, manifest, non_cert)
        assert "a.txt" in out
        assert "b.txt" in out
        assert "hello" in out
        assert "world" in out

    def test_cert_keys_not_present(self, leaf_pem):
        yaml_str = _make_configmap({"ca.crt": leaf_pem, "config.yaml": "key: val"})
        manifest = K8sManifest(yaml_str)
        non_cert = extract_non_cert_data(manifest)
        out = _capture(display_non_cert_data, manifest, non_cert)
        # The non-cert key should appear, but certificate PEM should not
        assert "config.yaml" in out
        assert "BEGIN CERTIFICATE" not in out

    def test_secret_decoded_value_shown(self):
        encoded = base64.b64encode(b"supersecret").decode()
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "sec", "namespace": "default"},
            "data": {"token": encoded},
        }
        manifest = K8sManifest(yaml.dump(secret))
        non_cert = extract_non_cert_data(manifest)
        out = _capture(display_non_cert_data, manifest, non_cert)
        assert "token" in out
        assert "supersecret" in out

    def test_header_rule_shown(self):
        yaml_str = _make_configmap({"x": "y"})
        manifest = K8sManifest(yaml_str)
        non_cert = extract_non_cert_data(manifest)
        out = _capture(display_non_cert_data, manifest, non_cert)
        assert "Other Data Entries" in out


# ---------------------------------------------------------------------------
# display_certs with non-cert data integration
# ---------------------------------------------------------------------------


class TestDisplayCertsIntegration:
    def test_cert_only_configmap(self, leaf_pem):
        yaml_str = _make_configmap({"tls.crt": leaf_pem})
        manifest = K8sManifest(yaml_str)
        bundles = extract_cert_bundles(manifest)
        out = _capture(display_certs, manifest, bundles)
        assert "tls.crt" in out
        assert "Certificate" in out

    def test_no_cert_message_when_no_bundles(self):
        yaml_str = _make_configmap({"config.yaml": "key: val"})
        manifest = K8sManifest(yaml_str)
        bundles = extract_cert_bundles(manifest)
        out = _capture(display_certs, manifest, bundles)
        assert "No certificates found" in out


# ---------------------------------------------------------------------------
# pager_context
# ---------------------------------------------------------------------------


class TestPagerContext:
    def test_pager_context_is_context_manager(self):
        ctx = pager_context()
        assert hasattr(ctx, "__enter__")
        assert hasattr(ctx, "__exit__")
