from ..base import TestBase
from ...dht.trie import Trie


class TestNode(TestBase):

    def setUp(self):
        super().setUp()
        self.trie = Trie('01')

    def test_get_set_del(self):
        self.trie['0'] = 1
        self.assertEqual(self.trie['0'], 1)

        self.trie['01'] = 2
        self.assertEqual(self.trie['01'], 2)

        self.trie['111'] = 4
        self.assertEqual(self.trie['111'], 4)

        self.trie['111'] = 3
        self.assertEqual(self.trie['111'], 3)

        with self.assertRaises(KeyError):
            # pylint: disable=W0104
            self.trie['000']

        del self.trie['111']
        with self.assertRaises(KeyError):
            # pylint: disable=W0104
            self.trie['111']

        with self.assertRaises(KeyError):
            del self.trie['1111']

    def test_longest_prefix(self):
        with self.assertRaises(KeyError):
            self.trie.longest_prefix('111')
        self.assertEqual(self.trie.longest_prefix('111', default=None), None)

        self.trie['0'] = 1
        self.trie['01'] = 2
        self.trie['111'] = 3

        self.assertEqual(self.trie.longest_prefix('000'), '0')
        self.assertEqual(self.trie.longest_prefix('111'), '111')

    def test_longest_prefix_item(self):
        with self.assertRaises(KeyError):
            self.trie.longest_prefix_item('111')
        self.assertEqual(self.trie.longest_prefix_item('111', default=None), None)

        self.trie['0'] = 1
        self.trie['01'] = 2
        self.trie['111'] = 3

        self.assertEqual(self.trie.longest_prefix_item('000'), ('0', 1))
        self.assertEqual(self.trie.longest_prefix_item('111'), ('111', 3))

    def test_longest_prefix_value(self):
        with self.assertRaises(KeyError):
            self.trie.longest_prefix_value('111')
        self.assertEqual(self.trie.longest_prefix_value('111', default=None), None)

        self.trie['0'] = 1
        self.trie['01'] = 2
        self.trie['111'] = 3

        self.assertEqual(self.trie.longest_prefix_value('000'), 1)
        self.assertEqual(self.trie.longest_prefix_value('111'), 3)

    def test_suffixes(self):
        self.assertEqual(self.trie.suffixes('111'), [])

        self.trie['0'] = 1
        self.trie['01'] = 2
        self.trie['111'] = 3
        self.trie['111111'] = 4

        self.assertEqual(self.trie.suffixes('0'), ['', '1'])
        self.assertEqual(self.trie.suffixes('11'), ['1', '1111'])

    def test_values(self):
        self.trie['0'] = 1
        self.trie['01'] = 2
        self.trie['111'] = 3

        self.assertSetEqual(set(self.trie.values()), {1, 2, 3})
        self.assertSetEqual(set(self.trie.values()), {1, 2, 3})
