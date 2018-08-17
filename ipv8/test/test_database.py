import unittest

from ..database import Database


class MockDatabase(Database):

    def check_database(self, database_version):
        self.execute("CREATE TABLE option(key TEXT PRIMARY KEY, value BLOB)")
        self.execute("INSERT INTO option(key, value) VALUES('database_version', '0')")
        self.commit()
        return 0


class TestDatabase(unittest.TestCase):

    def setUp(self):
        self.database = MockDatabase(":memory:")

    def test_unloaded(self):
        """
        Check if an unloaded database returns None for queries.
        """
        self.assertIsNone(self.database.execute("SELECT * FROM option"))

    def test_closed(self):
        """
        Check if an unloaded database returns None for queries.
        """
        self.database.open()
        self.assertListEqual([('database_version', '0')], list(self.database.execute("SELECT * FROM option")))
        self.database.close(True)
        self.assertIsNone(self.database.execute("SELECT * FROM option"))
