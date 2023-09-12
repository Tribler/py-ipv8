from ..database import Database
from .base import TestBase


class MockDatabase(Database):
    """
    Database that only creates the bare minimum versioning.
    """

    def check_database(self, database_version: bytes) -> int:
        """
        Inject a database version of 0 and succeed.
        """
        self.execute("CREATE TABLE option(key TEXT PRIMARY KEY, value BLOB)")
        self.execute("INSERT INTO option(key, value) VALUES('database_version', '0')")
        self.commit()
        return 0


class TestDatabase(TestBase):
    """
    Tests related to the database class.
    """

    def setUp(self) -> None:
        """
        Create a memory-based database.
        """
        super().setUp()
        self.database = MockDatabase(":memory:")

    def test_unloaded(self) -> None:
        """
        Check if an unloaded database returns None for queries.
        """
        self.assertIsNone(self.database.execute("SELECT * FROM option"))

    def test_closed(self) -> None:
        """
        Check if an unloaded database returns None for queries.
        """
        self.database.open()
        self.assertListEqual([(b'database_version', b'0')], list(self.database.execute("SELECT * FROM option")))
        self.database.close(True)
        self.assertIsNone(self.database.execute("SELECT * FROM option"))
