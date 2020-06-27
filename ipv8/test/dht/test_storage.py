import time

from ..base import TestBase
from ...dht.storage import Storage


class TestStorage(TestBase):

    def test_get_and_put(self):
        storage = Storage()

        storage.put(b'key', b'value1')
        self.assertEqual(storage.get(b'key'), [b'value1'])

        storage.put(b'key', b'value2')
        self.assertEqual(storage.get(b'key'), [b'value2', b'value1'])

        storage.put(b'key', b'value1')
        self.assertEqual(storage.get(b'key'), [b'value1', b'value2'])

    def test_items_older_than(self):
        storage = Storage()
        storage.put(b'key', b'value')
        storage.items[b'key'][0].last_update = time.time() - 1
        self.assertEqual(storage.items_older_than(0), [(b'key', b'value')])
        self.assertEqual(storage.items_older_than(10), [])

    def test_clean(self):
        storage = Storage()

        storage.put(b'key', b'value', max_age=60)
        storage.items[b'key'][0].last_update = time.time() - 120
        storage.clean()
        self.assertEqual(storage.get('key'), [])

        storage.put(b'key', b'value', 60)
        storage.items[b'key'][0].last_update = time.time()
        storage.clean()
        self.assertEqual(storage.get(b'key'), [b'value'])
