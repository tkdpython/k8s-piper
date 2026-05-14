"""k8s-piper: A tool for extracting and analyzing Kubernetes resource information."""

try:
    from k8s_piper._version import version as __version__
except ImportError:
    __version__ = "0.0.0.dev0"
