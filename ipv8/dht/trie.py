from __future__ import annotations

from typing import Generic, Iterator, Tuple, TypeVar, cast

from . import DHTError

# Sentinel object
NullType = object
Null = NullType()
ValueType = TypeVar("ValueType")  # Normally: Bucket


class Node(Generic[ValueType]):
    """
    This class represents a node within a prefix tree.
    """

    def __init__(self) -> None:
        """
        Create a new node data structure.
        """
        self.value: ValueType | None = None
        self.children: dict[str, Node] = {}


class Trie(Generic[ValueType]):
    """
    This class represents a prefix tree.
    """

    def __init__(self, alphabet: str) -> None:
        """
        Create a new prefix tree with the given permitted prefix characters.
        """
        self.alphabet = alphabet
        self.root = Node[ValueType]()

    def _find(self, key: str) -> Node[ValueType] | None:
        """
        Find the node to serve for the given key.
        """
        node: Node[ValueType] | None = self.root
        for char in key:
            node = cast(Node[ValueType], node).children.get(char)
            if node is None:
                break
        return node

    def __getitem__(self, key: str) -> ValueType:
        """
        Get the value belonging to a given key.
        """
        node = self._find(key)
        if node is None or node.value is None:
            raise KeyError
        return node.value

    def __setitem__(self, key: str, value: ValueType) -> None:
        """
        Set the value for the given key.
        """
        node = self.root
        for char in key:
            if char not in self.alphabet:
                msg = "Error while adding item to trie"
                raise DHTError(msg)

            next_node = node.children.get(char)
            if next_node is None:
                next_node = node.children[char] = Node()
            node = next_node
        node.value = value

    def __delitem__(self, key: str) -> None:
        """
        Remove the given key or raise a KeyError if the key was not found.
        """
        toremove: list[tuple[str, Node[ValueType]]] = []

        node: Node[ValueType] | None = self.root
        toremove.append(('', cast(Node[ValueType], node)))
        for char in key:
            toremove.append((char, cast(Node[ValueType], node)))
            node = cast(Node, node).children.get(char)
            if node is None:
                break

        if node is None or cast(Node[ValueType], node).value is None:
            raise KeyError
        rm_node: Node[ValueType] = cast(Node[ValueType], node)

        rm_node.value = None
        while rm_node.value is None and not rm_node.children and toremove:
            char, rm_node = toremove.pop()
            rm_node.children.pop(char)

    def itervalues(self) -> Iterator[ValueType]:
        """
        Iterate over all stored values.
        """
        def generator(node: Node) -> Iterator:
            if node.value is not None:
                yield node.value
            for child in node.children.values():
                yield from generator(child)
        return generator(self.root)

    def values(self) -> list[ValueType]:
        """
        Get all the stored values as a list.
        """
        return list(self.itervalues())

    def longest_prefix_item(self, key: str, default: tuple[str, ValueType] | NullType = Null) -> tuple[str, ValueType]:
        """
        Get longest matching prefix, for the given key, and its value.

        Raises a KeyError if no node is found at all.
        """
        prefix = ''
        value = None

        node: Node[ValueType] | None = self.root
        for index, _ in enumerate(key):
            node = cast(Node[ValueType], node).children.get(key[index])
            if node is None:
                break
            if node.value is not None:
                prefix = key[:index + 1]
                value = node.value

        if value:
            return prefix, value
        if default is not Null:
            return cast(Tuple[str, ValueType], default)
        raise KeyError

    def longest_prefix(self, key: str, default: str | NullType = Null) -> str:
        """
        Get longest matching prefix, for the given key.

        Raises a KeyError if no node is found at all.
        """
        result = self.longest_prefix_item(key, default=default)
        return result[0] if result != default else cast(str, default)

    def longest_prefix_value(self, key: str, default: ValueType | NullType = Null) -> ValueType:
        """
        Get the value of the longest matching prefix, for the given key.

        Raises a KeyError if no node is found at all.
        """
        result = self.longest_prefix_item(key, default=default)
        return result[1] if result != default else cast(ValueType, default)

    def suffixes(self, key: str) -> list[str]:
        """
        Get the known suffixes for the given key.
        """
        node = self._find(key)

        suffixes: list[str] = []
        if node is None:
            return suffixes
        if node.value is not None:
            suffixes.append('')

        for char, node in node.children.items():  # noqa: B020
            if node.value:
                suffixes.append(char)
            for nested_suffix in self.suffixes(key + char):
                suffix = char + nested_suffix
                if suffix not in suffixes:
                    suffixes.append(suffix)

        return suffixes
