"""Tests for k8s_piper.cli — argument parsing and routing."""

import base64
import io
import sys

import pytest
import yaml

from k8s_piper.cli import _build_parser, main


def _make_configmap_yaml(data):
    # type: (dict) -> str
    lines = [
        "apiVersion: v1", "kind: ConfigMap",
        "metadata:", "  name: mymap", "  namespace: default", "data:",
    ]
    for key, value in data.items():
        lines.append("  {0}: |".format(key))
        for vline in str(value).splitlines():
            lines.append("    " + vline)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# _build_parser — --more argument
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_more_flag_absent_defaults_to_false(self):
        parser = _build_parser()
        args = parser.parse_args([])
        assert args.more is False

    def test_more_flag_present(self):
        parser = _build_parser()
        args = parser.parse_args(["--more"])
        assert args.more is True


# ---------------------------------------------------------------------------
# main() — non-cert data displayed after certs
# ---------------------------------------------------------------------------


class TestMainNonCertOutput:
    def _run_main(self, stdin_text, args=None):
        # type: (str, list) -> str
        """Run main() with *stdin_text* as stdin; return stdout as a string."""
        import k8s_piper.display as display_module
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, highlight=False, no_color=True)
        orig_console = display_module._console
        display_module._console = console

        orig_stdin = sys.stdin
        orig_argv = sys.argv

        sys.stdin = io.StringIO(stdin_text)
        sys.argv = ["k8s-piper"] + (args or [])

        try:
            main()
        except SystemExit:
            pass
        finally:
            display_module._console = orig_console
            sys.stdin = orig_stdin
            sys.argv = orig_argv

        return buf.getvalue()

    def test_non_cert_entry_shown_after_certs(self, leaf_pem):
        cm_yaml = _make_configmap_yaml({"tls.crt": leaf_pem, "extra.conf": "setting=value"})
        out = self._run_main(cm_yaml)
        assert "tls.crt" in out
        assert "extra.conf" in out
        assert "setting=value" in out
        # Cert section should appear before non-cert section
        cert_pos = out.find("Certificate Analysis")
        non_cert_pos = out.find("Other Data Entries")
        assert cert_pos != -1
        assert non_cert_pos != -1
        assert cert_pos < non_cert_pos

    def test_only_non_cert_entries_in_configmap(self):
        cm_yaml = _make_configmap_yaml({"app.properties": "host=db\nport=5432"})
        out = self._run_main(cm_yaml)
        assert "Other Data Entries" in out
        assert "app.properties" in out
        assert "host=db" in out

    def test_cert_only_no_non_cert_section(self, leaf_pem):
        cm_yaml = _make_configmap_yaml({"ca.crt": leaf_pem})
        out = self._run_main(cm_yaml)
        assert "Other Data Entries" not in out

    def test_secret_non_cert_decoded_value(self):
        encoded = base64.b64encode(b"s3cr3t").decode()
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "mysecret", "namespace": "default"},
            "data": {"password": encoded},
        }
        out = self._run_main(yaml.dump(secret))
        assert "password" in out
        assert "s3cr3t" in out
