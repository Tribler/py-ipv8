from __future__ import annotations

import inspect
import platform
import sys
import traceback
from contextlib import AbstractContextManager
from enum import Enum
from types import TracebackType


class Platform(Enum):
    ANY = None
    NONE = 0  # For stubbing and testing.
    WINDOWS = "Windows"
    LINUX = "Linux"


class conditional_import_shield(AbstractContextManager):
    """
    Context manager that provides two things:

     1. Conditional imports based on platform (``platform.system()``).
     2. Exception handling and logging.
    """

    def __init__(self, platf: Platform = Platform.ANY, verbose: bool = False) -> None:
        """
        Create a new ``conditional_import_shield`` context manager.

        :param verbose: Log any errors that are encountered while fetching addresses.
        :param platf: The platform conditional (or ``None`` to run on all platforms).
        """
        self.right_platform = platf.value is None or platform.system() == platf.value
        f_current = inspect.currentframe()
        if f_current is None:
            raise RuntimeError("Could not determine current frame!")
        f_back = f_current.f_back
        if f_back is None:
            raise RuntimeError("Could not determine calling frame!")
        self.module_name = f_back.f_globals["__name__"]
        self.package_backup = sys.modules[self.module_name].__package__
        self.package_overwritten = False
        self.verbose = verbose

    def __enter__(self) -> conditional_import_shield:
        """
        When we enter the context, check if we are running on the right platform.

        If we are not on the right platform, we temporarily sabotage the module's import system.
        """
        if self.right_platform:
            return self
        self.package_overwritten = True
        sys.modules[self.module_name].__package__ = ""
        return self

    def __exit__(self, exctype: type[BaseException] | None, excinst: BaseException | None,
                 exctb: TracebackType | None) -> bool:
        """
        When we exit the context, unsabotage the import system and log any exceptions.
        """
        if self.package_overwritten:
            sys.modules[self.module_name].__package__ = self.package_backup
            # Should be an ImportError due to our sabotage. Otherwise, log the exception:
            if self.verbose and exctype is not ImportError:
                traceback.print_exception(exctype, excinst, exctb)
            return True
        # Should have finished without exception:
        if self.verbose and exctype is not None:
            traceback.print_exception(exctype, excinst, exctb)
        return True
