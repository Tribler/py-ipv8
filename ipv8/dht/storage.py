from __future__ import annotations

import hashlib
import time
from collections import defaultdict


class Value:
    """
    Class for storing DHT values.
    """

    def __init__(self, id_: bytes, data: bytes, max_age: float, version: int) -> None:
        """
        Create a new value.
        """
        self.id = id_
        self.data = data
        self.last_update = time.time()
        self.max_age = max_age
        self.version = version

    @property
    def age(self) -> float:
        """
        The time (in seconds) since the last update.
        """
        return time.time() - self.last_update

    @property
    def expired(self) -> bool:
        """
        Whether the maximum time since the last update has been reached.
        """
        return self.age > self.max_age

    def __eq__(self, other: object) -> bool:
        """
        Whether this value equals another given value.
        """
        if not isinstance(other, Value):
            return False
        return self.id == other.id

    def __hash__(self) -> int:
        """
        The hash is always 0, forcing an expensive lookup.
        """
        return 0


class Storage:
    """
    Class for storing key-value pairs in memory.
    """

    def __init__(self) -> None:
        """
        Create a new storage for Values.
        """
        self.items: dict[bytes, list[Value]] = defaultdict(list)

    def put(self, key: bytes, data: bytes,
            id_: bytes | None = None, max_age: float = 86400, version: int = 0) -> None:
        """
        Store the given data under a certain key.
        """
        id_ = id_ or hashlib.sha1(data).digest()
        new_value = Value(id_, data, max_age, version)

        try:
            index = self.items[key].index(new_value)
            old_value = self.items[key][index]
            if new_value.version >= old_value.version:
                self.items[key].pop(index)
                self.items[key].insert(0, new_value)
                self.items[key].sort(key=lambda v: 1 if v.id == key else 0)
        except ValueError:
            self.items[key].insert(0, new_value)
            self.items[key].sort(key=lambda v: 1 if v.id == key else 0)

    def get(self, key: bytes, starting_point: int = 0, limit: int | None = None) -> list[bytes]:
        """
        Get the values stored at the given key.
        """
        upper_bound = (starting_point + limit) if limit else limit
        return [value.data for value in self.items[key][starting_point:upper_bound]] if key in self.items else []

    def items_older_than(self, min_age: float) -> list[tuple[bytes, bytes]]:
        """
        Get all values that have not been updated for the given amount of time (in seconds).
        """
        items = []
        for key in self.items:
            items += [(key, value.data) for value in self.items[key] if value.age > min_age]
        return items

    def clean(self) -> None:
        """
        Remove all expired items.
        """
        for key in self.items:
            for index, value in reversed(list(enumerate(self.items[key]))):
                if value.expired:
                    self.items[key].pop(index)
                else:
                    break
