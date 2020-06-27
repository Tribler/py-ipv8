from collections import OrderedDict

from ...base import TestBase
from ....messaging.deprecated.sorting import sortable_sort


class TestSorting(TestBase):

    def test_illegal_object(self):
        self.assertRaises(RuntimeError, sortable_sort, self)

    def test_type_ordering(self):
        """
        Check if types form the primary sorting key.
        """
        out = sortable_sort(["1", None, [1, 2], True, 1])

        self.assertListEqual(out, [None, True, 1, "1", [1, 2]])

    def test_single_none(self):
        """
        Check if a None is returned as is.
        """
        self.assertEqual(sortable_sort(None), None)

    def test_single_bool_true(self):
        """
        Check if a True is returned as is.
        """
        self.assertEqual(sortable_sort(True), True)

    def test_single_bool_false(self):
        """
        Check if a False is returned as is.
        """
        self.assertEqual(sortable_sort(False), False)

    def test_single_float_zero(self):
        """
        Check if a 0.0 is returned as is.
        """
        self.assertEqual(sortable_sort(0.0), 0.0)

    def test_single_float_minus_one(self):
        """
        Check if a -1.0 is returned as is.
        """
        self.assertEqual(sortable_sort(-1.0), -1.0)

    def test_single_float_plus_one(self):
        """
        Check if a 1.0 is returned as is.
        """
        self.assertEqual(sortable_sort(1.0), 1.0)

    def test_single_float_large(self):
        """
        Check if a 99999.9999 is returned as is.
        """
        self.assertEqual(sortable_sort(99999.9999), 99999.9999)

    def test_single_int_zero(self):
        """
        Check if a 0 is returned as is.
        """
        self.assertEqual(sortable_sort(0), 0)

    def test_single_int_minus_one(self):
        """
        Check if a -1 is returned as is.
        """
        self.assertEqual(sortable_sort(-1), -1)

    def test_single_int_plus_one(self):
        """
        Check if a 1 is returned as is.
        """
        self.assertEqual(sortable_sort(1), 1)

    def test_single_float_int(self):
        """
        Check if a 999999999 is returned as is.
        """
        self.assertEqual(sortable_sort(999999999), 999999999)

    def test_single_bytes_empty(self):
        """
        Check if an empty byte string is returned as is.
        """
        self.assertEqual(sortable_sort(b""), b"")

    def test_single_bytes_one(self):
        """
        Check if a single character byte string is returned as is.
        """
        self.assertEqual(sortable_sort(b"\x01"), b"\x01")

    def test_single_bytes_many(self):
        """
        Check if an all different bytes string is returned as is.
        """
        self.assertEqual(sortable_sort(bytes(range(256))), bytes(range(256)))

    def test_single_str_empty(self):
        """
        Check if an empty string is returned as is.
        """
        self.assertEqual(sortable_sort(""), "")

    def test_single_str_one(self):
        """
        Check if a single character string is returned as is.
        """
        self.assertEqual(sortable_sort("\x01"), "\x01")

    def test_single_str_many(self):
        """
        Check if an all different character string is returned as is.
        """
        self.assertEqual(sortable_sort("".join([chr(c) for c in range(256)])), "".join([chr(c) for c in range(256)]))

    def test_single_tuple_empty(self):
        """
        Check if an empty tuple is returned as is.
        """
        self.assertTupleEqual(sortable_sort(tuple()), tuple())

    def test_single_tuple_one(self):
        """
        Check if a single entry tuple is returned as is.
        """
        self.assertTupleEqual(sortable_sort((b"\x01", )), (b"\x01", ))

    def test_single_tuple_many(self):
        """
        Check if a filled tuple is returned as is.
        """
        data = (5, 4, "z", "a", [4, 2])
        expected = (5, 4, "z", "a", [2, 4])

        self.assertTupleEqual(sortable_sort(data), expected)

    def test_single_set_empty(self):
        """
        Check if an empty set is returned as is.
        """
        self.assertSetEqual(sortable_sort(set()), set())
        self.assertListEqual(list(sortable_sort(set())), [])

    def test_single_set_one(self):
        """
        Check if a single entry set is returned as is.
        """
        self.assertSetEqual(sortable_sort(set([b"\x01"])), set([b"\x01"]))
        self.assertListEqual(list(sortable_sort({b"\x01"})), [b"\x01"])

    def test_single_set_many(self):
        """
        Check if a filled set is returned sorted.
        """
        data = {5, 4, "z", "a"}
        expected = [4, 5, "a", "z"]

        self.assertSetEqual(sortable_sort(data), set(expected))
        self.assertListEqual(list(sortable_sort(data)), expected)

    def test_single_list_empty(self):
        """
        Check if an empty list is returned as is.
        """
        self.assertListEqual(sortable_sort([]), [])

    def test_single_list_one(self):
        """
        Check if a single entry list is returned as is.
        """
        self.assertListEqual(sortable_sort([b"\x01"]), [b"\x01"])

    def test_single_list_many(self):
        """
        Check if a filled list is returned sorted.
        """
        data = [5, 4, "z", "a", [4, 2]]
        expected = [4, 5, "a", "z", [2, 4]]

        self.assertListEqual(sortable_sort(data), expected)

    def test_single_dict_empty(self):
        """
        Check if an empty dict is returned as is.
        """
        self.assertDictEqual(sortable_sort({}), {})

    def test_single_dict_one(self):
        """
        Check if a single entry dict is returned as is.
        """
        self.assertDictEqual(sortable_sort({b"\x01": b"\x02"}), {b"\x01": b"\x02"})

    def test_single_dict_many(self):
        """
        Check if a filled dict is returned sorted.
        """
        data = {5: 4, "z": "a", 1: [4, 2]}
        expected = {1: [2, 4], 5: 4, "z": "a"}

        self.assertDictEqual(sortable_sort(data), expected)

    def test_nested_list_single(self):
        """
        Check if a list of lists is sorted.
        """
        data = [[5, 4], [2, 3], [1, 0]]
        expected = [[0, 1], [2, 3], [4, 5]]

        self.assertListEqual(sortable_sort(data), expected)

    def test_nested_list_equal(self):
        """
        Check if a list of equal lists is sorted.
        """
        data = [[0, 1], [1, 0]]
        expected = [[0, 1], [0, 1]]

        self.assertListEqual(sortable_sort(data), expected)

    def test_nested_list_partial(self):
        """
        Check if a list of lists with overlap is sorted.
        """
        data = [[1, 2], [0, 1, 2, 3], [2, 1, 0], [0, 1, 4, 3, 2]]
        expected = [[0, 1, 2], [0, 1, 2, 3], [0, 1, 2, 3, 4], [1, 2]]

        self.assertListEqual(sortable_sort(data), expected)

    def test_nested_list_double_mixed(self):
        """
        Check if a list of lists of half list is sorted.
        """
        data = [[5, 4], [[2, 2.5], 3], [1, 0]]
        expected = [[0, 1], [3, [2, 2.5]], [4, 5]]

        self.assertListEqual(sortable_sort(data), expected)

    def test_nested_list_double_pure(self):
        """
        Check if a list of lists of list is sorted.
        """
        data = [[5, 4], [[2, 2.5], [3, 3.5]], [1, 0]]
        expected = [[0, 1], [4, 5], [[2, 2.5], [3, 3.5]]]

        self.assertListEqual(sortable_sort(data), expected)

    def test_nested_list_bools(self):
        """
        Check if booleans are propertly sorted in a list.
        """
        data = [True, False, False, True, False]
        expected = [False, False, False, True, True]

        self.assertListEqual(sortable_sort(data), expected)

    def test_nested_list_none(self):
        """
        Check if nones are propertly sorted in a list.
        """
        data = [None, None, [None]]
        expected = [None, None, [None]]

        self.assertListEqual(sortable_sort(data), expected)

    def test_nested_dict_single(self):
        """
        Check if a dict of lists is sorted.
        """
        data = {1: [5, 4], 3: [2, 3], 2: [1, 0]}
        expected = OrderedDict([(1, [4, 5]), (2, [0, 1]), (3, [2, 3])])

        self.assertDictEqual(sortable_sort(data), expected)

    def test_nested_dict_double(self):
        """
        Check if a dict of dicts is sorted.
        """
        data = {7: {2: 4, 4: 5}, 1: {4: 5, 2: 3}}
        expected = OrderedDict([(1, OrderedDict([(2, 3), (4, 5)])), (7, OrderedDict([(2, 4), (4, 5)]))])

        self.assertDictEqual(sortable_sort(data), expected)

    def test_payload_of_doom(self):
        """
        Check if an inconsistent sorted() list is sorted correctly.

        In other words:
            Given: set(data) == set(data2)

            Given: sorted(data) != sorted(data2)

            Then: sortable_sort(data) == sortable_sort(data2)
        """
        data = ['a', u'b', (1, ), 'c']
        data2 = ['a', u'b', 'c', (1, )]

        self.assertListEqual(sortable_sort(data), sortable_sort(data2))
