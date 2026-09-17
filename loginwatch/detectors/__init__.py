"""Detector package.

Importing this module is what populates the registry: each detector module
registers its class on import, and `build_detectors(config)` then instantiates
whichever ones the config file enables.
"""

from .base import REGISTRY, Detector, build_detectors, register  # noqa: F401

# Import order does not matter; each module self-registers.
from . import anomalous_hour  # noqa: F401,E402
from . import brute_force  # noqa: F401,E402
from . import credential_stuffing  # noqa: F401,E402
from . import impossible_travel  # noqa: F401,E402
from . import new_device_location  # noqa: F401,E402
from . import password_spray  # noqa: F401,E402
from . import post_failure_success  # noqa: F401,E402

__all__ = ["REGISTRY", "Detector", "build_detectors", "register"]
