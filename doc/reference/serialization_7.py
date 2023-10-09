from ipv8.messaging.lazy_payload import VariablePayload
from ipv8.messaging.payload_dataclass import dataclass


class A(VariablePayload):
    format_list = ['I', 'H']
    names = ["foo", "bar"]


class B(VariablePayload):
    format_list = [A, 'H']  # Note that we pass the class A
    names = ["a", "baz"]


@dataclass(msg_id=1)
class Message:
    @dataclass
    class Item:
        foo: int
        bar: int

    item: Item
    items: [Item]  # Yes, you can even make this a list!
    baz: int
