from . import DHTError

# Sentinel object
Null = object()


class Node(object):
    """
    This class represents a node within a prefix tree.
    """

    def __init__(self):
        self.value = None
        self.children = {}


class Trie(object):
    """
    This class represents a prefix tree.
    """

    def __init__(self, alphabet):
        self.alphabet = alphabet
        self.root = Node()

    def _find(self, key):
        node = self.root
        for char in key:
            node = node.children.get(char)
            if node is None:
                break
        return node

    def __getitem__(self, key):
        node = self._find(key)
        if node is None or node.value is None:
            raise KeyError
        return node.value

    def __setitem__(self, key, value):
        node = self.root
        for char in key:
            if char not in self.alphabet:
                raise DHTError('Error while adding item to trie')

            next_node = node.children.get(char)
            if next_node is None:
                next_node = node.children[char] = Node()
            node = next_node
        node.value = value

    def __delitem__(self, key):
        toremove = []

        node = self.root
        toremove.append(('', node))
        for char in key:
            toremove.append((char, node))
            node = node.children.get(char)
            if node is None:
                break

        if node is None or node.value is None:
            raise KeyError

        node.value = None
        while node.value is None and not node.children and toremove:
            char, node = toremove.pop()
            node.children.pop(char)

    def itervalues(self):
        def generator(node):
            if node.value is not None:
                yield node.value
            for _, child in node.children.items():
                for subresult in generator(child):
                    yield subresult
        return generator(self.root)

    def values(self):
        return list(self.itervalues())

    def longest_prefix_item(self, key, default=Null):
        prefix = ''
        value = None

        node = self.root
        for index, _ in enumerate(key):
            node = node.children.get(key[index])
            if node is None:
                break
            if node.value is not None:
                prefix = key[:index + 1]
                value = node.value

        if value:
            return prefix, value
        elif default is not Null:
            return default
        raise KeyError

    def longest_prefix(self, key, default=Null):
        result = self.longest_prefix_item(key, default=default)
        return result[0] if result != default else default

    def longest_prefix_value(self, key, default=Null):
        result = self.longest_prefix_item(key, default=default)
        return result[1] if result != default else default

    def suffixes(self, key):
        node = self._find(key)

        suffixes = []
        if node is None:
            return suffixes
        if node.value is not None:
            suffixes.append('')

        for char, node in node.children.items():
            if node.value:
                suffixes.append(char)
            for nested_suffix in self.suffixes(key + char):
                suffix = char + nested_suffix
                if suffix not in suffixes:
                    suffixes.append(suffix)

        return suffixes
