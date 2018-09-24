from collections import OrderedDict

from ...util import is_long_or_int, is_unicode


class SortableTypeEnum(object):
    """
    Initial type sorting enum: the lower enum values are inserted closer to the head of the list.

    We distinguish:
     - NONE: None
     - BOOLEAN: bool
     - NUMBER: float, int, long
     - STRING: bytes, str, unicode
     - LIST: dict, list, set, tuple*

     * Note that a tuple is a special kind of LIST, which is not sorted.
       This would, for instance, sort (key, value) pairs.
    """

    NONE = 0
    BOOLEAN = 1
    NUMBER = 2
    STRING = 3
    LIST = 4


class Sortable(object):
    """
    Wrapper for sortable types.
    """

    def __init__(self, value):
        """
        Wrap a value as a Sortable, which allows it to be sorted with `sorted()` or `list.sort()`.

        :param value: a wrappable value
        """
        self.source = value # The source value
        self.value = value # The sorted value
        if self.value is None:
            self.type = SortableTypeEnum.NONE
        elif isinstance(self.value, bool):
            self.type = SortableTypeEnum.BOOLEAN
        elif isinstance(self.value, float) or is_long_or_int(self.value):
            self.type = SortableTypeEnum.NUMBER
        elif isinstance(self.value, (bytes, str)) or is_unicode(self.value):
            self.type = SortableTypeEnum.STRING
        elif isinstance(self.value, (set, dict, tuple, list)):
            self.type = SortableTypeEnum.LIST
            if isinstance(value, dict):
                self.value = sorted([Sortable((k, v)) for k, v in list(value.items())])
            elif isinstance(value, tuple):
                self.value = [Sortable(v) for v in value]
            else:
                self.value = sorted([Sortable(v) for v in value])
        else:
            raise RuntimeError("Unsortable value %s!" % repr(self.value))

    def compare(self, other):
        """
        Compare this Sortable to another Sortable.

        :param other: the Sortable to compare to
        :type other: Sortable
        :return: -1, 0 or 1 if this object is smaller, equal or larger than the other object
        """
        # Initially we sort on enum value (NONE < BOOLEAN < .. < LIST)
        if other.type == self.type:
            if self.type == SortableTypeEnum.NONE:
                # None is always equal
                return 0
            if self.type == SortableTypeEnum.BOOLEAN:
                # False < True
                if self.value == other.value:
                    return 0
                if self.value:
                    return 1
                return -1
            if self.type == SortableTypeEnum.NUMBER:
                # Python allows us to intrinsically compare float to int and long
                if self.value == other.value:
                    return 0
                if self.value < other.value:
                    return -1
                return 1
            if self.type == SortableTypeEnum.STRING:
                # To deal with unicode we cast all string types to a list of ordinals
                my_ordinals = self.value if isinstance(self.value, bytes) else [ord(c) for c in self.value]
                other_ordinals = other.value if isinstance(other.value, bytes) else [ord(c) for c in other.value]
            else:
                # All list types can simply give their sorted values for comparison
                my_ordinals = self.value
                other_ordinals = other.value
            n = min(len(my_ordinals), len(other_ordinals))
            for i in range(n):
                # Compare each value between lists, this is supported through the Sortable wrapper.
                if my_ordinals[i] < other_ordinals[i]:
                    return -1
                elif my_ordinals[i] > other_ordinals[i]:
                    return 1
            # If all list entries are equal, the shortest list is smaller
            if len(my_ordinals) < len(other_ordinals):
                return -1
            elif len(my_ordinals) > len(other_ordinals):
                return 1
            return 0
        elif self.type < other.type:
            return -1
        return 1

    def finalize(self):
        """
        Unwrap this Sortable to its sorted value.

        Note that LISTs are type-changed:
         - dict -> OrderedDict
         - list -> list
         - set -> list
         - tuple -> tuple (order preserved)

        :return: this Sortable as its source data type
        """
        if self.type == SortableTypeEnum.LIST:
            converted = [v.finalize() for v in self.value]
            if isinstance(self.source, dict):
                out = OrderedDict()
                for v in converted:
                    out[v[0]] = v[1]
                return out
            return tuple(converted) if isinstance(self.source, tuple) else converted
        return self.value

    def __lt__(self, other):
        return self.compare(other) < 0

    def __gt__(self, other):
        return self.compare(other) > 0


def sortable_sort(data):
    """
    Sort complex input containing any combination of:

     - None
     - bool
     - float
     - int
     - long
     - bytes
     - str
     - unicode
     - dict
     - list
     - set
     - tuple

    :return: the sorted input
    """
    return Sortable(data).finalize()


__all__ = ["sortable_sort"]
