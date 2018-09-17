from __future__ import absolute_import
from __future__ import division

from unittest import TestCase

from ...deprecated.bloomfilter import BloomFilter
from ...util import grange


class TestBloomFilter(TestCase):

    def test_fixed_size_constructor(self):
        """
        Testing BloomFilter(int:m_size, float:f_error_rate, str:prefix="")
        """
        blooms = [BloomFilter(128 * 8, 0.25),
                  BloomFilter(128 * 8, 0.25, ""),
                  BloomFilter(128 * 8, 0.25, prefix="")]

        for bloom in blooms:
            bloom.add_keys(str(i) for i in grange(100))
            self.assertEqual(bloom.size, 128 * 8)
            self.assertEqual(len(bloom.bytes), 128)
            self.assertEqual(bloom.prefix, "")

        blooms = [BloomFilter(128 * 8, 0.25, "p"),
                  BloomFilter(128 * 8, 0.25, prefix="p")]

        for bloom in blooms:
            bloom.add_keys(str(i) for i in grange(100))
            self.assertEqual(bloom.size, 128 * 8)
            self.assertEqual(len(bloom.bytes), 128)
            self.assertEqual(bloom.prefix, "p")

    def test_adaptive_size_constructor(self):
        """
        Testing BloomFilter(float:f_error_rate, int:n_capacity, str:prefix="")
        """
        blooms = [BloomFilter(0.25, 142),
                  BloomFilter(0.25, 142, ""),
                  BloomFilter(0.25, 142, prefix="")]

        for bloom in blooms:
            bloom.add_keys(str(i) for i in grange(100))
            self.assertEqual(bloom.prefix, "")

        blooms = [BloomFilter(0.25, 142, "p"),
                  BloomFilter(0.25, 142, prefix="p")]

        for bloom in blooms:
            bloom.add_keys(str(i) for i in grange(100))
            self.assertEqual(bloom.prefix, "p")

    def test_load_constructor(self):
        """
        Testing BloomFilter(str:bytes, int:k_functions, str:prefix="")
        """
        bloom = BloomFilter(128 * 8, 0.25)
        bloom.add_keys(str(i) for i in grange(100))
        bytes_, functions = bloom.bytes, bloom.functions

        blooms = [BloomFilter(bytes_, functions),
                  BloomFilter(bytes_, functions, ""),
                  BloomFilter(bytes_, functions, prefix="")]

        for bloom in blooms:
            self.assertEqual(bloom.size, 128 * 8)
            self.assertEqual(bloom.bytes, bytes_)
            self.assertEqual(bloom.prefix, "")
            self.assertTrue(all(str(i) in bloom for i in grange(100)))

        bloom = BloomFilter(128 * 8, 0.25, "p")
        bloom.add_keys(str(i) for i in grange(100))
        bytes_, functions = bloom.bytes, bloom.functions

        blooms = [BloomFilter(bytes_, functions, "p"),
                  BloomFilter(bytes_, functions, prefix="p")]

        for bloom in blooms:
            self.assertEqual(bloom.size, 128 * 8)
            self.assertEqual(bloom.bytes, bytes_)
            self.assertEqual(bloom.prefix, "p")
            self.assertTrue(all(str(i) in bloom for i in grange(100)))

    def test_clear(self):
        """
        Testing BloomFilter.clear()
        """
        bloom = BloomFilter(128 * 8, 0.25)
        self.assertEqual(bloom.bits_checked, 0)
        bloom.add_keys(str(i) for i in grange(100))
        self.assertNotEqual(bloom.bits_checked, 0)
        bloom.clear()
        self.assertEqual(bloom.bits_checked, 0)

    def test_false_positives(self):
        """
        Testing false positives.
        """
        args = [(0.1, 128, ""),
                (0.2, 128, ""),
                (0.3, 128, ""),
                (0.4, 128, ""),
                (0.1, 1024, ""),
                (0.2, 1024, ""),
                (0.3, 1024, ""),
                (0.4, 1024, ""),
                (0.1, 128, "p"),
                (0.2, 128, "p"),
                (0.3, 128, "p"),
                (0.4, 128, "p"),
                (0.1, 1024, "p"),
                (0.2, 1024, "p"),
                (0.3, 1024, "p"),
                (0.4, 1024, "p")]

        for f_error_rate, n_capacity, prefix in args:
            bloom = BloomFilter(f_error_rate, n_capacity, prefix)
            bloom.add_keys(str(i) for i in grange(n_capacity))
            self.assertTrue(all(str(i) in bloom for i in grange(n_capacity)))
            false_positives = sum(str(i) in bloom for i in grange(n_capacity, n_capacity + 10000))
            self.assertAlmostEqual(1.0 * false_positives / 10000, f_error_rate, delta=0.05)
