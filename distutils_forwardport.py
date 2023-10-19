"""
Forward port to support a small subset of distutils functionality for our upstream dependencies.
"""
from __future__ import annotations

try:
    # Check if we need to fix anything
    from distutils import version
except ImportError:
    import sys

    import packaging.version


    class LooseVersion(packaging.version.Version):
        """
        Forward port of LooseVersion (mostly equal to Version).
        """

        @property
        def version(self) -> tuple[int, ...]:
            """
            Get a tuple of the release version ints.
            """
            return self.release

        @property
        def vstring(self) -> str:
            """
            Forward port of str(self).
            """
            return str(self)

        def __lt__(self, other: str | "_BaseVersion") -> bool:  # type: ignore[name-defined]  # noqa: F821,UP037
            """
            Less than: we add support for comparison with str.
            """
            if isinstance(other, str):
                return self < LooseVersion(other)
            return super().__lt__(other)

        def __le__(self, other: str | "_BaseVersion") -> bool:  # type: ignore[name-defined]  # noqa: F821,UP037
            """
            Less than or equal: we add support for comparison with str.
            """
            if isinstance(other, str):
                return self <= LooseVersion(other)
            return super().__le__(other)

        def __eq__(self, other: object) -> bool:
            """
            Equals: we add support for comparison with str.
            """
            if isinstance(other, str):
                return self == LooseVersion(other)
            return super().__eq__(other)

        def __ge__(self, other: str | "_BaseVersion") -> bool:  # type: ignore[name-defined]  # noqa: F821,UP037
            """
            Greater than or equal: we add support for comparison with str.
            """
            if isinstance(other, str):
                return self >= LooseVersion(other)
            return super().__ge__(other)

        def __gt__(self, other: str | "_BaseVersion") -> bool:  # type: ignore[name-defined]  # noqa: F821,UP037
            """
            Greater than: we add support for comparison with str.
            """
            if isinstance(other, str):
                return self > LooseVersion(other)
            return super().__gt__(other)

        def __ne__(self, other: object) -> bool:
            """
            Not equal: we add support for comparison with str.
            """
            if isinstance(other, str):
                return self != LooseVersion(other)
            return super().__ne__(other)


    packaging.version.LooseVersion = LooseVersion  # type: ignore[attr-defined]
    sys.modules["distutils.version"] = packaging.version
    sys.modules["distutils"] = sys.modules[LooseVersion.__module__]
    version = packaging.version  # type: ignore[misc]
