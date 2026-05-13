"""CLI entry point for k8s-piper."""

import argparse
import sys

from k8s_piper import __version__
from k8s_piper.k8s_manifest import ParseError, parse_manifest
from k8s_piper.cert_analyzer import extract_cert_bundles
from k8s_piper.display import display_certs


def _build_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(
        prog="k8s-piper",
        description=(
            "Pipe kubectl output into k8s-piper to analyse Kubernetes resources.\n\n"
            "Examples:\n"
            "  kubectl get cm ca -n mynamespace -o yaml | k8s-piper --certs\n"
            "  kubectl get secret mycerts -n mynamespace -o yaml | k8s-piper --certs"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--certs",
        action="store_true",
        help="Extract and analyse X.509 certificate information",
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
    args = parser.parse_args()

    # Check that at least one analysis mode is requested
    if not args.certs:
        parser.print_help()
        sys.exit(0)

    # Read manifest from stdin
    if sys.stdin.isatty():
        parser.error(
            "No input detected. Pipe kubectl output into k8s-piper.\n"
            "  Example: kubectl get cm ca -n mynamespace -o yaml | k8s-piper --certs"
        )

    raw = sys.stdin.read()
    if not raw.strip():
        parser.error("Received empty input from stdin.")

    try:
        manifest = parse_manifest(raw)
    except ParseError as exc:
        sys.exit("Error: {0}".format(exc))

    if args.certs:
        bundles = extract_cert_bundles(manifest)
        display_certs(manifest, bundles)


if __name__ == "__main__":
    main()
