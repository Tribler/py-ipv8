from ...dht.trie import Trie
from ..base import TestBase


class TestNode(TestBase):
    """
    Tests for trie nodes.
    """

    def setUp(self) -> None:
        """
        Set up with a single Trie.
        """
        super().setUp()
        self.trie = Trie('01')

    def test_get_set_del(self) -> None:
        """
        Test getting, setting and deleting from the Trie.
        """
        self.trie['0'] = 1
        self.assertEqual(self.trie['0'], 1)

        self.trie['01'] = 2
        self.assertEqual(self.trie['01'], 2)

        self.trie['111'] = 4
        self.assertEqual(self.trie['111'], 4)

        self.trie['111'] = 3
        self.assertEqual(self.trie['111'], 3)

        with self.assertRaises(KeyError):
            self.trie['000']

        del self.trie['111']
        with self.assertRaises(KeyError):
            self.trie['111']

        with self.assertRaises(KeyError):
            del self.trie['1111']

    def test_longest_prefix(self) -> None:
        """
        Test matching the longest prefix.
        """
        with self.assertRaises(KeyError):
            self.trie.longest_prefix('111')
        self.assertEqual(self.trie.longest_prefix('111', default=None), None)

        self.trie['0'] = 1
        self.trie['01'] = 2
        self.trie['111'] = 3

        self.assertEqual(self.trie.longest_prefix('000'), '0')
        self.assertEqual(self.trie.longest_prefix('111'), '111')

    def test_longest_prefix_item(self) -> None:
        """
        Test matching the longest prefix item.
        """
        with self.assertRaises(KeyError):
            self.trie.longest_prefix_item('111')
        self.assertEqual(self.trie.longest_prefix_item('111', default=None), None)

        self.trie['0'] = 1
        self.trie['01'] = 2
        self.trie['111'] = 3

        self.assertEqual(self.trie.longest_prefix_item('000'), ('0', 1))
        self.assertEqual(self.trie.longest_prefix_item('111'), ('111', 3))

    def test_longest_prefix_value(self) -> None:
        """
        Test matching the longest prefix value.
        """
        with self.assertRaises(KeyError):
            self.trie.longest_prefix_value('111')
        self.assertEqual(self.trie.longest_prefix_value('111', default=None), None)

        self.trie['0'] = 1
        self.trie['01'] = 2
        self.trie['111'] = 3

        self.assertEqual(self.trie.longest_prefix_value('000'), 1)
        self.assertEqual(self.trie.longest_prefix_value('111'), 3)

    def test_suffixes(self) -> None:
        """
        Test matching suffixes.
        """
        self.assertEqual(self.trie.suffixes('111'), [])

        self.trie['0'] = 1
        self.trie['01'] = 2
        self.trie['111'] = 3
        self.trie['111111'] = 4

        self.assertEqual(self.trie.suffixes('0'), ['', '1'])
        self.assertEqual(self.trie.suffixes('11'), ['1', '1111'])

    def test_values(self) -> None:
        """
        Test setting values.
        """
        self.trie['0'] = 1
        self.trie['01'] = 2
        self.trie['111'] = 3

        self.assertSetEqual(set(self.trie.values()), {1, 2, 3})
        self.assertSetEqual(set(self.trie.values()), {1, 2, 3})
