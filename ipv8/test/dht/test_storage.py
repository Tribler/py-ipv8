import time

from ...dht.storage import Storage
from ..base import TestBase


class TestStorage(TestBase):
    """
    Tests related to Storage objects.
    """

    def test_get_and_put(self) -> None:
        """
        Check that unique values can be added to a storage key.
        """
        storage = Storage()

        storage.put(b'key', b'value1')
        self.assertEqual(storage.get(b'key'), [b'value1'])

        storage.put(b'key', b'value2')
        self.assertEqual(storage.get(b'key'), [b'value2', b'value1'])

        storage.put(b'key', b'value1')
        self.assertEqual(storage.get(b'key'), [b'value1', b'value2'])

    def test_items_older_than(self) -> None:
        """
        Check that inserted values can be filtered based on their age.
        """
        storage = Storage()
        storage.put(b'key', b'value')
        storage.items[b'key'][0].last_update = time.time() - 1
        self.assertEqual(storage.items_older_than(0), [(b'key', b'value')])
        self.assertEqual(storage.items_older_than(10), [])

    def test_clean(self) -> None:
        """
        Check that expired values are removed when cleaning a storage.
        """
        storage = Storage()

        storage.put(b'key', b'value', max_age=60)
        storage.items[b'key'][0].last_update = time.time() - 120
        storage.clean()
        self.assertEqual(storage.get(b'key'), [])

        storage.put(b'key', b'value', 60)
        storage.items[b'key'][0].last_update = time.time()
        storage.clean()
        self.assertEqual(storage.get(b'key'), [b'value'])
