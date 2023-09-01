"""
This module provides basic database functionalty and simple version control.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""
from __future__ import annotations

import logging
import os
import sqlite3
from abc import ABCMeta, abstractmethod
from collections import defaultdict
from sqlite3 import Connection, Cursor, OperationalError
from threading import RLock
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator, Mapping, Tuple, Union, cast

if TYPE_CHECKING:
    from types import TracebackType

    from _typeshed import SupportsLenAndGetItem
    from typing_extensions import Self

DB_TYPES = Union[int, float, str, bytes, None]

db_locks: dict[str, RLock] = defaultdict(RLock)


def db_call(f: Callable[..., Any]) -> Callable[..., Any | None]:
    """
    Wait for the database lock before calling a function and return None if the cursor could not be acquired.
    """
    def wrapper(self: Database, *args: Any, **kwargs) -> Any | None:  # noqa: ANN401
        with db_locks[self._file_path]:
            if self._cursor:
                return f(self, *args, **kwargs)
            return None
    return wrapper


def _thread_safe_result_it(result: Cursor, fetch_all: bool = True) -> Iterator[DB_TYPES]:
    rows = (result.fetchall() if fetch_all else result.fetchone()) or []
    return (row for row in rows)


class IgnoreCommits(Exception):
    """
    Ignore all commits made within the body of a 'with database:' clause.

    with database:
       # all commit statements are delayed until the database.__exit__
       database.commit()
       database.commit()
       # raising IgnoreCommits causes all commits to be ignored
       raise IgnoreCommits()
    """

    def __init__(self) -> None:
        """
        Create a new exception instance.
        """
        super().__init__("Ignore all commits made within __enter__ and __exit__")


class DatabaseException(RuntimeError):
    """
    Exception for database integrity violations.
    """


class Database(metaclass=ABCMeta):
    """
    Wrapper for SQLite 3 calls.
    """

    def __init__(self, file_path: str) -> None:
        """
        Initialize a new Database instance.

        @param file_path: the path to the database file.
        @type file_path: unicode
        """
        self._assert(isinstance(file_path, str),
                     "expected file_path to be unicode, but was %s" % str(type(file_path)))

        super().__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        self._logger.debug("loading database [%s]", file_path)
        self._file_path = file_path

        # _CONNECTION, _CURSOR, AND _DATABASE_VERSION are set during open(...)
        self._connection: Connection | None = None
        self._cursor: Cursor | None = None
        self._database_version = 0

        # Database.commit() is enabled when _pending_commits == 0.  Database.commit() is disabled
        # when _pending_commits > 0.  A commit is required when _pending_commits > 1.
        self._pending_commits = 0

    def _assert(self, condition: bool, message: str = "") -> None:
        """
        Check if condition is True, or raise a DatabaseException with a message.
        """
        if not condition:
            raise DatabaseException(str(message))

    def open(self, initial_statements: bool = True, prepare_visioning: bool = True) -> bool:  # noqa: A003
        """
        Open a connection to the underlying database file.
        """
        self._assert(self._cursor is None, "Database.open() has already been called")
        self._assert(self._connection is None, "Database.open() has already been called")

        self._logger.debug("open database [%s]", self._file_path)
        if (not self._file_path.startswith(':')
                and not os.path.isfile(self._file_path)
                and not os.path.exists(os.path.dirname(self._file_path))):
            os.makedirs(os.path.dirname(self._file_path))
        self._connect()
        if initial_statements:
            self._initial_statements()
        if prepare_visioning:
            self._prepare_version()
        return True

    @db_call
    def close(self, commit: bool = True) -> bool:
        """
        Close the connection to the database.
        """
        self._assert(self._cursor is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(self._connection is not None,
                     "Database.close() has been called or Database.open() has not been called")
        if commit:
            self.commit(exiting=True)
        self._logger.debug("close database [%s]", self._file_path)
        cast(Cursor, self._cursor).close()
        self._cursor = None
        cast(Connection, self._connection).close()
        self._connection = None
        return True

    def _connect(self) -> None:
        self._connection = sqlite3.connect(self._file_path, check_same_thread=False)
        self._connection.text_factory = bytes
        self._cursor = self._connection.cursor()

        assert self._cursor

    def _initial_statements(self) -> None:
        self._assert(self._cursor is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(self._connection is not None,
                     "Database.close() has been called or Database.open() has not been called")

        # collect current database configuration
        cursor = cast(Cursor, self._cursor)
        page_size = int(next(cursor.execute("PRAGMA page_size"))[0])
        journal_mode = next(cursor.execute("PRAGMA journal_mode"))[0].decode().upper()
        synchronous = next(cursor.execute("PRAGMA synchronous"))[0]
        synchronous = synchronous.decode().upper() if isinstance(synchronous, bytes) else synchronous

        #
        # PRAGMA page_size = bytes;
        # http://www.sqlite.org/pragma.html#pragma_page_size
        # Note that changing page_size has no effect unless performed on a new database or followed
        # directly by VACUUM.  Since we do not want the cost of VACUUM every time we load a
        # database, existing databases must be upgraded.
        #
        if page_size < 8192:
            self._logger.debug("PRAGMA page_size = 8192 (previously: %s) [%s]", page_size, self._file_path)

            # it is not possible to change page_size when WAL is enabled
            if journal_mode == "WAL":
                cursor.executescript("PRAGMA journal_mode = DELETE")
                journal_mode = "DELETE"
            cursor.execute("PRAGMA page_size = 8192")
            cursor.execute("VACUUM")
            page_size = 8192

        else:
            self._logger.debug("PRAGMA page_size = %s (no change) [%s]", page_size, self._file_path)

        #
        # PRAGMA journal_mode = DELETE | TRUNCATE | PERSIST | MEMORY | WAL | OFF
        # http://www.sqlite.org/pragma.html#pragma_page_size
        #
        if not (journal_mode == "WAL" or self._file_path == ":memory:"):
            self._logger.debug("PRAGMA journal_mode = WAL (previously: %s) [%s]", journal_mode, self._file_path)
            cursor.execute("PRAGMA locking_mode = EXCLUSIVE")
            cursor.execute("PRAGMA journal_mode = WAL")
        else:
            self._logger.debug("PRAGMA journal_mode = %s (no change) [%s]", journal_mode, self._file_path)

        #
        # PRAGMA synchronous = 0 | OFF | 1 | NORMAL | 2 | FULL;
        # http://www.sqlite.org/pragma.html#pragma_synchronous
        #
        if synchronous not in ("NORMAL", 1):
            self._logger.debug("PRAGMA synchronous = NORMAL (previously: %s) [%s]", synchronous, self._file_path)
            cursor.execute("PRAGMA synchronous = NORMAL")
        else:
            self._logger.debug("PRAGMA synchronous = %s (no change) [%s]", synchronous, self._file_path)

    def _prepare_version(self) -> None:
        self._assert(self._cursor is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(self._connection is not None,
                     "Database.close() has been called or Database.open() has not been called")

        # check is the database contains an 'option' table
        try:
            count = next(cast(Iterator[int], self.execute("SELECT COUNT(*) FROM sqlite_master "
                                                          "WHERE type = 'table' AND name = 'option'")))
        except OperationalError as e:
            raise RuntimeError from e

        if count:
            # get version from required 'option' table
            try:
                version, = next(cast(Iterator[Tuple[bytes]], self.execute("SELECT value FROM option "
                                                                          "WHERE key == 'database_version' "
                                                                          "LIMIT 1")))
            except OperationalError:
                # the 'database_version' key was not found
                version = b"0"
        else:
            # the 'option' table probably hasn't been created yet
            version = b"0"

        self._database_version = self.check_database(version)
        self._assert(isinstance(self._database_version, int),
                     "expected databse version to be int or long, but was type %s" % str(type(self._database_version)))

    @property
    def database_version(self) -> int:
        """
        The current (expected) version of the database.
        """
        return self._database_version

    @property
    def file_path(self) -> str:
        """
        The database filename including path.
        """
        return self._file_path

    def __enter__(self) -> Self:
        """
        Enters a no-commit state.  The commit will be performed by __exit__.

        @return: The method self.execute
        """
        self._assert(self._cursor is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(self._connection is not None,
                     "Database.close() has been called or Database.open() has not been called")

        self._logger.debug("disabling commit [%s]", self._file_path)
        self._pending_commits = max(1, self._pending_commits)
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None,
                 traceback: TracebackType | None) -> bool:
        """
        Leaves a no-commit state.  A commit will be performed if Database.commit() was called while
        in the no-commit state.
        """
        self._assert(self._cursor is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(self._connection is not None,
                     "Database.close() has been called or Database.open() has not been called")

        self._pending_commits, pending_commits = 0, self._pending_commits

        if exc_type is None:
            self._logger.debug("enabling commit [%s]", self._file_path)
            if pending_commits > 1:
                self._logger.debug("performing %d pending commits [%s]", pending_commits - 1, self._file_path)
                self.commit()
            return True

        if isinstance(exc_value, IgnoreCommits):
            self._logger.debug("enabling commit without committing now [%s]", self._file_path)
            return True

        # Niels 23-01-2013, an exception happened from within the with database block
        # returning False to let Python reraise the exception.
        return False

    @db_call
    def execute(self, statement: str, bindings: SupportsLenAndGetItem | Mapping[str, Any] = (),
                get_lastrowid: bool = False,
                fetch_all: bool = True) -> int | Iterator[DB_TYPES] | Iterator[list[DB_TYPES]] | None:
        """
        Execute one SQL statement.

        A SQL query must be presented in unicode format.  This is to ensure that no unicode
        exeptions occur when the bindings are merged into the statement.

        Furthermore, the bindings may not contain any strings either.  For a 'string' the unicode
        type must be used.  For a binary string the buffer(...) type must be used.

        The SQL query may contain placeholder entries defined with a '?'.  Each of these
        placeholders will be used to store one value from bindings.  The placeholders are filled by
        sqlite and all proper escaping is done, making this the preferred way of adding variables to
        the SQL query.

        @param statement: the SQL statement that is to be executed.
        @type statement: unicode

        @param bindings: the values that must be set to the placeholders in statement.
        @type bindings: list, tuple, dict, or set

        @returns: unknown
        @raise sqlite.Error: unknown
        """
        self._logger.log(logging.NOTSET, "%s <-- %s [%s]", statement, bindings, self._file_path)
        cursor = cast(Cursor, self._cursor)
        result = cursor.execute(statement, bindings)
        if get_lastrowid:
            return cursor.lastrowid
        return _thread_safe_result_it(result, fetch_all)

    @db_call
    def executescript(self, statements: str, fetch_all: bool = True) -> Iterator[DB_TYPES]:
        """
        Execute multiple SQL statements at once.
        """
        self._assert(self._cursor is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(self._connection is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(isinstance(statements, str), "The SQL statement must be given in unicode")

        self._logger.log(logging.NOTSET, "%s [%s]", statements, self._file_path)

        result = cast(Cursor, self._cursor).executescript(statements)
        return _thread_safe_result_it(result, fetch_all)

    @db_call
    def executemany(self, statement: str, sequenceofbindings: Iterable[SupportsLenAndGetItem | Mapping[str, Any]],
                    fetch_all: bool = True) -> Iterator[DB_TYPES]:
        """
        Execute one SQL statement several times.

        All SQL queries must be presented in unicode format.  This is to ensure that no unicode
        exeptions occur when the bindings are merged into the statement.

        Furthermore, the bindings may not contain any strings either.  For a 'string' the unicode
        type must be used.  For a binary string the buffer(...) type must be used.

        The SQL query may contain placeholder entries defined with a '?'.  Each of these
        placeholders will be used to store one value from bindings.  The placeholders are filled by
        sqlite and all proper escaping is done, making this the preferred way of adding variables to
        the SQL query.

        @param statement: the SQL statement that is to be executed.
        @type statement: unicode

        @param sequenceofbindings: a list, tuple, set, or generator of bindings, where every binding
                                   contains the values that must be set to the placeholders in
                                   statement.

        @type sequenceofbindings: list, tuple, set or generator

        @returns: unknown
        @raise sqlite.Error: unknown
        """
        self._assert(self._cursor is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(self._connection is not None,
                     "Database.close() has been called or Database.open() has not been called")

        self._logger.log(logging.NOTSET, "%s [%s]", statement, self._file_path)
        result = cast(Cursor, self._cursor).executemany(statement, sequenceofbindings)
        return _thread_safe_result_it(result, fetch_all)

    @db_call
    def commit(self, exiting: bool = False) -> bool:
        """
        Attempt to commit the current transaction and return False when the commit needs to wait for pending commits.
        """
        self._assert(self._cursor is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(self._connection is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(not (exiting and self._pending_commits), "No pending commits should be present when exiting")

        if self._pending_commits:
            self._logger.debug("defer commit [%s]", self._file_path)
            self._pending_commits += 1
            return False

        self._logger.debug("commit [%s]", self._file_path)
        cast(Connection, self._connection).commit()
        return True

    @abstractmethod
    def check_database(self, database_version: bytes) -> int:
        """
        Check the database and upgrade if required.

        This method is called once for each Database instance to ensure that the database structure
        and version is correct.  Each Database must contain one table of the structure below where
        the database_version is stored.  This value is used to keep track of the current database
        version.

        >>> CREATE TABLE option(key TEXT PRIMARY KEY, value BLOB);
        >>> INSERT INTO option(key, value) VALUES('database_version', '1');

        @param database_version: the current database_version value from the option table. This
         value reverts to u'0' when the table could not be accessed.
        @type database_version: unicode
        """
