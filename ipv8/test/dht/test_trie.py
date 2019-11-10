from ..base import TestBase
from ...dht.trie import Trie


class TestNode(TestBase):

    def setUp(self):
        super(TestNode, self).setUp()
        self.trie = Trie(u'01')

    def test_get_set_del(self):
        self.trie[u'0'] = 1
        self.assertEqual(self.trie[u'0'], 1)

        self.trie[u'01'] = 2
        self.assertEqual(self.trie[u'01'], 2)

        self.trie[u'111'] = 4
        self.assertEqual(self.trie[u'111'], 4)

        self.trie[u'111'] = 3
        self.assertEqual(self.trie[u'111'], 3)

        with self.assertRaises(KeyError):
            # pylint: disable=W0104
            self.trie[u'000']

        del self.trie[u'111']
        with self.assertRaises(KeyError):
            # pylint: disable=W0104
            self.trie[u'111']

        with self.assertRaises(KeyError):
            del self.trie[u'1111']

    def test_longest_prefix(self):
        with self.assertRaises(KeyError):
            self.trie.longest_prefix(u'111')
        self.assertEqual(self.trie.longest_prefix(u'111', default=None), None)

        self.trie[u'0'] = 1
        self.trie[u'01'] = 2
        self.trie[u'111'] = 3

        self.assertEqual(self.trie.longest_prefix(u'000'), u'0')
        self.assertEqual(self.trie.longest_prefix(u'111'), u'111')

    def test_longest_prefix_item(self):
        with self.assertRaises(KeyError):
            self.trie.longest_prefix_item(u'111')
        self.assertEqual(self.trie.longest_prefix_item(u'111', default=None), None)

        self.trie[u'0'] = 1
        self.trie[u'01'] = 2
        self.trie[u'111'] = 3

        self.assertEqual(self.trie.longest_prefix_item(u'000'), (u'0', 1))
        self.assertEqual(self.trie.longest_prefix_item(u'111'), (u'111', 3))

    def test_longest_prefix_value(self):
        with self.assertRaises(KeyError):
            self.trie.longest_prefix_value(u'111')
        self.assertEqual(self.trie.longest_prefix_value(u'111', default=None), None)

        self.trie[u'0'] = 1
        self.trie[u'01'] = 2
        self.trie[u'111'] = 3

        self.assertEqual(self.trie.longest_prefix_value(u'000'), 1)
        self.assertEqual(self.trie.longest_prefix_value(u'111'), 3)

    def test_suffixes(self):
        self.assertEqual(self.trie.suffixes(u'111'), [])

        self.trie[u'0'] = 1
        self.trie[u'01'] = 2
        self.trie[u'111'] = 3
        self.trie[u'111111'] = 4

        self.assertEqual(self.trie.suffixes(u'0'), [u'', u'1'])
        self.assertEqual(self.trie.suffixes(u'11'), [u'1', u'1111'])

    def test_values(self):
        self.trie['0'] = 1
        self.trie['01'] = 2
        self.trie['111'] = 3

        self.assertSetEqual(set(self.trie.values()), set([1, 2, 3]))
        self.assertSetEqual(set(self.trie.values()), set([1, 2, 3]))
