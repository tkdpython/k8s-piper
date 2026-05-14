"""Parse Kubernetes YAML manifests and extract data fields."""

import base64
from typing import Dict, Optional

import yaml


class ParseError(Exception):
    """Raised when a manifest cannot be parsed."""


class K8sManifest:
    """Represents a parsed Kubernetes manifest with decoded data fields."""

    def __init__(self, raw_yaml):
        # type: (str) -> None
        self.raw = raw_yaml
        self.kind = "Unknown"
        self.name = "unknown"
        self.namespace = "default"
        self.api_version = ""
        self.data = {}  # type: Dict[str, str]
        self._parse()

    def _parse(self):
        # type: () -> None
        try:
            doc = yaml.safe_load(self.raw)
        except yaml.YAMLError as exc:
            raise ParseError("Failed to parse YAML: {0}".format(exc))

        if not isinstance(doc, dict):
            raise ParseError(
                "Expected a Kubernetes manifest (YAML mapping), got {0}".format(
                    type(doc).__name__
                )
            )

        self._doc = doc
        self.kind = doc.get("kind", "Unknown")
        self.api_version = doc.get("apiVersion", "")
        metadata = doc.get("metadata") or {}
        self.name = metadata.get("name", "unknown")
        self.namespace = metadata.get("namespace", "default")

        if self.kind == "Secret":
            self._extract_secret_data(doc)
        else:
            raw_data = doc.get("data") or {}
            self.data = {k: str(v) for k, v in raw_data.items() if v is not None}

    def _extract_secret_data(self, doc):
        # type: (dict) -> None
        """Extract and base64-decode Secret data fields."""
        encoded_data = doc.get("data") or {}
        string_data = doc.get("stringData") or {}

        self.data = {}
        for key, value in encoded_data.items():
            if value is None:
                continue
            try:
                decoded = base64.b64decode(value).decode("utf-8", errors="replace")
                self.data[key] = decoded
            except Exception:
                # Keep raw value if base64 decode fails
                self.data[key] = str(value)

        # stringData overrides encoded data (K8s merging behaviour)
        for key, value in string_data.items():
            if value is not None:
                self.data[key] = str(value)

    @property
    def doc(self):
        # type: () -> dict
        """The full parsed YAML document as a dict."""
        return self._doc

    @property
    def source_label(self):
        # type: () -> str
        """Human-readable label for this manifest source."""
        return "{kind}/{name} (namespace: {ns})".format(
            kind=self.kind,
            name=self.name,
            ns=self.namespace,
        )


def parse_manifest(raw_yaml):
    # type: (str) -> K8sManifest
    """Parse a Kubernetes YAML manifest string."""
    return K8sManifest(raw_yaml)
