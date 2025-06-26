"""Atlas Application."""

from packaging.version import Version

__version__ = "0.3.18"

v = Version(version=__version__)

__version_info__ = (
    v.major,
    v.minor,
    v.micro,
    v.pre,  # tuple like ('a', 3) or None
    v.dev,  # int or None
)

__all__ = ["__version__", "__version_info__"]
