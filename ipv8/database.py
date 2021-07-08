"""
This module provides basic database functionalty and simple version control.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""
import logging
import os
import sqlite3
import typing
from abc import ABCMeta, abstractmethod
from collections import defaultdict
from threading import RLock


db_locks: typing.Dict[str, RLock] = defaultdict(RLock)


def db_call(f):
    def wrapper(self, *args, **kwargs):
        with db_locks[self._file_path]:
            if self._cursor:
                return f(self, *args, **kwargs)
            return None
    return wrapper


def _thread_safe_result_it(result, fetch_all=True):
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
    def __init__(self):
        super(IgnoreCommits, self).__init__("Ignore all commits made within __enter__ and __exit__")


class DatabaseException(RuntimeError):
    pass


class Database(metaclass=ABCMeta):

    def __init__(self, file_path):
        """
        Initialize a new Database instance.

        @param file_path: the path to the database file.
        @type file_path: unicode
        """
        self._assert(isinstance(file_path, str),
                     "expected file_path to be unicode, but was %s" % str(type(file_path)))

        super(Database, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        self._logger.debug("loading database [%s]", file_path)
        self._file_path = file_path

        # _CONNECTION, _CURSOR, AND _DATABASE_VERSION are set during open(...)
        self._connection = None
        self._cursor = None
        self._database_version = 0

        # Database.commit() is enabled when _pending_commits == 0.  Database.commit() is disabled
        # when _pending_commits > 0.  A commit is required when _pending_commits > 1.
        self._pending_commits = 0

    def _assert(self, condition, message=""):
        """
        Check if condition is True, or raise a DatabaseException with a message.
        """
        if not condition:
            raise DatabaseException(str(message))

    def open(self, initial_statements=True, prepare_visioning=True):
        self._assert(self._cursor is None, "Database.open() has already been called")
        self._assert(self._connection is None, "Database.open() has already been called")

        self._logger.debug("open database [%s]", self._file_path)
        if (not self._file_path.startswith(':')) and (not os.path.isfile(self._file_path)):
            if not os.path.exists(os.path.dirname(self._file_path)):
                os.makedirs(os.path.dirname(self._file_path))
        self._connect()
        if initial_statements:
            self._initial_statements()
        if prepare_visioning:
            self._prepare_version()
        return True

    @db_call
    def close(self, commit=True):
        self._assert(self._cursor is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(self._connection is not None,
                     "Database.close() has been called or Database.open() has not been called")
        if commit:
            self.commit(exiting=True)
        self._logger.debug("close database [%s]", self._file_path)
        self._cursor.close()
        self._cursor = None
        self._connection.close()
        self._connection = None
        return True

    def _connect(self):
        self._connection = sqlite3.connect(self._file_path, check_same_thread=False)
        self._connection.text_factory = bytes
        self._cursor = self._connection.cursor()

        assert self._cursor

    def _initial_statements(self):
        self._assert(self._cursor is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(self._connection is not None,
                     "Database.close() has been called or Database.open() has not been called")

        # collect current database configuration
        page_size = int(next(self._cursor.execute("PRAGMA page_size"))[0])
        journal_mode = next(self._cursor.execute("PRAGMA journal_mode"))[0].decode().upper()
        synchronous = next(self._cursor.execute("PRAGMA synchronous"))[0]
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
                self._cursor.executescript("PRAGMA journal_mode = DELETE")
                journal_mode = "DELETE"
            self._cursor.execute("PRAGMA page_size = 8192")
            self._cursor.execute("VACUUM")
            page_size = 8192

        else:
            self._logger.debug("PRAGMA page_size = %s (no change) [%s]", page_size, self._file_path)

        #
        # PRAGMA journal_mode = DELETE | TRUNCATE | PERSIST | MEMORY | WAL | OFF
        # http://www.sqlite.org/pragma.html#pragma_page_size
        #
        if not (journal_mode == "WAL" or self._file_path == ":memory:"):
            self._logger.debug("PRAGMA journal_mode = WAL (previously: %s) [%s]", journal_mode, self._file_path)
            self._cursor.execute("PRAGMA locking_mode = EXCLUSIVE")
            self._cursor.execute("PRAGMA journal_mode = WAL")
        else:
            self._logger.debug("PRAGMA journal_mode = %s (no change) [%s]", journal_mode, self._file_path)

        #
        # PRAGMA synchronous = 0 | OFF | 1 | NORMAL | 2 | FULL;
        # http://www.sqlite.org/pragma.html#pragma_synchronous
        #
        if synchronous not in ("NORMAL", 1):
            self._logger.debug("PRAGMA synchronous = NORMAL (previously: %s) [%s]", synchronous, self._file_path)
            self._cursor.execute("PRAGMA synchronous = NORMAL")
        else:
            self._logger.debug("PRAGMA synchronous = %s (no change) [%s]", synchronous, self._file_path)

    def _prepare_version(self):
        self._assert(self._cursor is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(self._connection is not None,
                     "Database.close() has been called or Database.open() has not been called")

        # check is the database contains an 'option' table
        try:
            count, = next(self.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'option'"))
        except StopIteration:
            raise RuntimeError()

        if count:
            # get version from required 'option' table
            try:
                version, = next(self.execute("SELECT value FROM option WHERE key == 'database_version' LIMIT 1"))
            except StopIteration:
                # the 'database_version' key was not found
                version = b"0"
        else:
            # the 'option' table probably hasn't been created yet
            version = b"0"

        self._database_version = self.check_database(version)
        self._assert(isinstance(self._database_version, int),
                     "expected databse version to be int or long, but was type %s" % str(type(self._database_version)))

    @property
    def database_version(self):
        return self._database_version

    @property
    def file_path(self):
        """
        The database filename including path.
        """
        return self._file_path

    def __enter__(self):
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

    def __exit__(self, exc_type, exc_value, traceback):
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

        elif isinstance(exc_value, IgnoreCommits):
            self._logger.debug("enabling commit without committing now [%s]", self._file_path)
            return True

        else:
            # Niels 23-01-2013, an exception happened from within the with database block
            # returning False to let Python reraise the exception.
            return False

    @db_call
    def execute(self, statement, bindings=(), get_lastrowid=False, fetch_all=True):
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
        result = self._cursor.execute(statement, bindings)
        if get_lastrowid:
            return self._cursor.lastrowid
        return _thread_safe_result_it(result, fetch_all)

    @db_call
    def executescript(self, statements, fetch_all=True):
        self._assert(self._cursor is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(self._connection is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(isinstance(statements, str), "The SQL statement must be given in unicode")

        self._logger.log(logging.NOTSET, "%s [%s]", statements, self._file_path)

        result = self._cursor.executescript(statements)
        return _thread_safe_result_it(result, fetch_all)

    @db_call
    def executemany(self, statement, sequenceofbindings, fetch_all=True):
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
        result = self._cursor.executemany(statement, sequenceofbindings)
        return _thread_safe_result_it(result, fetch_all)

    @db_call
    def commit(self, exiting=False):
        self._assert(self._cursor is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(self._connection is not None,
                     "Database.close() has been called or Database.open() has not been called")
        self._assert(not (exiting and self._pending_commits), "No pending commits should be present when exiting")

        if self._pending_commits:
            self._logger.debug("defer commit [%s]", self._file_path)
            self._pending_commits += 1
            return False

        else:
            self._logger.debug("commit [%s]", self._file_path)
            return self._connection.commit()

    @abstractmethod
    def check_database(self, database_version):
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
        pass
