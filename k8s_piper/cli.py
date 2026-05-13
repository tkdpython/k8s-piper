"""CLI entry point for k8s-piper."""

import argparse
import sys

from k8s_piper import __version__
from k8s_piper.k8s_manifest import ParseError, parse_manifest
from k8s_piper.cert_analyzer import extract_cert_bundles
from k8s_piper.workload_analyzer import WORKLOAD_KINDS, extract_workload_info
from k8s_piper.rbac_analyzer import RBAC_KINDS, extract_rbac_info
from k8s_piper.display import display_certs, display_workload, display_rbac

# Resource kinds that carry certificate data
_CERT_KINDS = frozenset({"ConfigMap", "Secret"})

# All recognised kinds
_ALL_SUPPORTED_KINDS = _CERT_KINDS | WORKLOAD_KINDS | RBAC_KINDS


def _build_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(
        prog="k8s-piper",
        description=(
            "Pipe kubectl output into k8s-piper to analyse Kubernetes resources.\n\n"
            "The resource type is detected automatically from the manifest kind.\n\n"
            "Examples:\n"
            "  kubectl get cm ca -n mynamespace -o yaml | k8s-piper\n"
            "  kubectl get secret mycerts -n mynamespace -o yaml | k8s-piper\n"
            "  kubectl get deploy myapp -n mynamespace -o yaml | k8s-piper\n"
            "  kubectl get clusterrole admin -o yaml | k8s-piper"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s {0}".format(__version__),
    )
    return parser


def main():
    # type: () -> None
    parser = _build_parser()
    parser.parse_args()

    if sys.stdin.isatty():
        parser.error(
            "No input detected. Pipe kubectl output into k8s-piper.\n"
            "  Example: kubectl get deploy myapp -n mynamespace -o yaml | k8s-piper"
        )

    raw = sys.stdin.read()
    if not raw.strip():
        parser.error("Received empty input from stdin.")

    try:
        manifest = parse_manifest(raw)
    except ParseError as exc:
        sys.exit("Error: {0}".format(exc))

    kind = manifest.kind

    if kind in _CERT_KINDS:
        bundles = extract_cert_bundles(manifest)
        display_certs(manifest, bundles)
    elif kind in WORKLOAD_KINDS:
        info = extract_workload_info(manifest)
        display_workload(manifest, info)
    elif kind in RBAC_KINDS:
        info = extract_rbac_info(manifest)
        display_rbac(manifest, info)
    else:
        sys.exit(
            "Error: unsupported resource kind '{0}'.\n"
            "Supported kinds: {1}".format(
                kind,
                ", ".join(sorted(_ALL_SUPPORTED_KINDS)),
            )
        )


if __name__ == "__main__":
    main()
