from dataclasses import dataclass

from ipv8.messaging.lazy_payload import VariablePayload
from ipv8.messaging.payload_dataclass import DataClassPayload


class A(VariablePayload):
    format_list = ['I', 'H']
    names = ["foo", "bar"]


class B(VariablePayload):
    format_list = [A, 'H']  # Note that we pass the class A
    names = ["a", "baz"]


@dataclass
class Message(DataClassPayload[1]):
    @dataclass
    class Item:
        foo: int
        bar: int

    item: Item
    items: [Item]  # Yes, you can even make this a list!
    baz: int
