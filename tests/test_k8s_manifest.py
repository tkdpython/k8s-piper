"""Tests for k8s_piper.k8s_manifest."""

import base64

import pytest
import yaml

from k8s_piper.k8s_manifest import K8sManifest, ParseError, parse_manifest


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------


def _configmap(name="mymap", namespace="default", data=None):
    # type: (str, str, dict) -> str
    doc = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": namespace},
        "data": data or {},
    }
    return yaml.dump(doc)


def _secret(name="mysecret", namespace="default", data=None, string_data=None):
    # type: (str, str, dict, dict) -> str
    doc = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": namespace},
    }
    if data:
        doc["data"] = data
    if string_data:
        doc["stringData"] = string_data
    return yaml.dump(doc)


# ---------------------------------------------------------------------------
# ConfigMap parsing
# ---------------------------------------------------------------------------


class TestConfigMapParsing:
    def test_kind_and_metadata(self):
        m = parse_manifest(_configmap(name="my-cm", namespace="kube-system"))
        assert m.kind == "ConfigMap"
        assert m.name == "my-cm"
        assert m.namespace == "kube-system"

    def test_data_plain_text(self):
        m = parse_manifest(_configmap(data={"key": "value", "other": "123"}))
        assert m.data["key"] == "value"
        assert m.data["other"] == "123"

    def test_source_label(self):
        m = parse_manifest(_configmap(name="cm1", namespace="ns1"))
        assert "ConfigMap" in m.source_label
        assert "cm1" in m.source_label
        assert "ns1" in m.source_label

    def test_empty_data(self):
        m = parse_manifest(_configmap(data={}))
        assert m.data == {}

    def test_null_data_field(self):
        doc = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "x"},
            "data": None,
        }
        m = parse_manifest(yaml.dump(doc))
        assert m.data == {}


# ---------------------------------------------------------------------------
# Secret parsing (base64 decoding)
# ---------------------------------------------------------------------------


class TestSecretParsing:
    def test_kind(self):
        m = parse_manifest(_secret())
        assert m.kind == "Secret"

    def test_base64_decoded(self):
        encoded = base64.b64encode(b"hello world").decode()
        m = parse_manifest(_secret(data={"token": encoded}))
        assert m.data["token"] == "hello world"

    def test_string_data_not_decoded(self):
        m = parse_manifest(_secret(string_data={"plain": "rawvalue"}))
        assert m.data["plain"] == "rawvalue"

    def test_string_data_overrides_data(self):
        encoded = base64.b64encode(b"from-data").decode()
        m = parse_manifest(
            _secret(
                data={"key": encoded},
                string_data={"key": "from-stringData"},
            )
        )
        assert m.data["key"] == "from-stringData"

    def test_binary_cert_roundtrip(self, leaf_pem):
        encoded = base64.b64encode(leaf_pem.encode()).decode()
        m = parse_manifest(_secret(data={"tls.crt": encoded}))
        assert "BEGIN CERTIFICATE" in m.data["tls.crt"]

    def test_invalid_base64_kept_as_raw(self):
        # Should not raise, just keep the raw value
        m = parse_manifest(_secret(data={"bad": "!!!not-valid-base64!!!"}))
        assert "bad" in m.data


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestParseErrors:
    def test_invalid_yaml(self):
        with pytest.raises(ParseError):
            parse_manifest("key: [unclosed bracket")

    def test_non_mapping_yaml(self):
        with pytest.raises(ParseError):
            parse_manifest("- item1\n- item2\n")

    def test_empty_string(self):
        # yaml.safe_load of empty string returns None → not a dict
        with pytest.raises(ParseError):
            parse_manifest("")

    def test_missing_kind_defaults(self):
        doc = {"metadata": {"name": "x"}, "data": {}}
        m = parse_manifest(yaml.dump(doc))
        assert m.kind == "Unknown"

    def test_missing_namespace_defaults(self):
        doc = {"kind": "ConfigMap", "metadata": {"name": "x"}, "data": {}}
        m = parse_manifest(yaml.dump(doc))
        assert m.namespace == "default"
