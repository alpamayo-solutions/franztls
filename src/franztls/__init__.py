from importlib.metadata import version

from .cert_manager import CertManager
from .exceptions import CertificateExpiredException

__version__ = version("franztls")

__all__ = [
    "CertManager",
    "CertificateExpiredException",
    "__version__",
]
