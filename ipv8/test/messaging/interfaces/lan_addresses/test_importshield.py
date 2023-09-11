from __future__ import annotations

import contextlib
import io
import sys
from importlib.abc import MetaPathFinder

from .....messaging.interfaces.lan_addresses.importshield import Platform, conditional_import_shield
from ....base import TestBase


class SegfaultingImporter(MetaPathFinder):
    """
    Importer that causes segfaults, scary!
    """

    def find_module(self, fullname: str, path: str) -> SegfaultingImporter | None:
        """
        Only serve imports from this class called "killer_import", as a safety feature.
        """
        if fullname == f"{self.__module__[:self.__module__.rindex('.')]}.killer_import":
            return self
        return None

    def load_module(self, _: str) -> None:
        """
        Cause a segfault when the module is actually loaded.

        We cannot simply raise an ``AssertionError`` here, as the import protection SHOULD also serve as a general
        ``try: ... except Exception: ...`` handler.
        """
        import ctypes
        return ctypes.cast(id(0), ctypes.POINTER(ctypes.c_char_p)).contents.value


class TestImportShield(TestBase):
    """
    Tests relating to the import shield.
    """

    def test_stop_import(self) -> None:
        """
        Check that segfaulting imports are properly ignored when the platform does not match.
        """
        # Create an importable module ".killer_import" that segfaults the Python interpreter when imported.
        sys.meta_path.append(SegfaultingImporter())

        # The result value should remain unaltered if the import was properly ignored
        result = 42.0

        with conditional_import_shield(Platform.NONE, True):
            from .killer_import import ctypes
            result = ctypes.__version__  # We should've already segfaulted here, just in case: also change the result

        self.assertEqual(42.0, result)

    def test_allow_import(self) -> None:
        """
        Check that allowed imports are actually imported.
        """
        result = 0.0

        with conditional_import_shield(Platform.ANY, False):
            import math
            result = sum(math.frexp(80) * 8) - 19.0  # Does not work without the ``math`` import.

        self.assertEqual(42.0, result)

    def test_allow_import_log_exception(self) -> None:
        """
        Check that allowed imports are actually imported.
        """
        log = io.StringIO()
        with contextlib.redirect_stderr(log), conditional_import_shield(Platform.ANY, True):
            import math
            print(math.factorial(-1))  # This leads to an error that we should print.  # noqa: T201

        self.assertNotEqual("", log.getvalue())
