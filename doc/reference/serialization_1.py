from __future__ import annotations

from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.messaging.payload import Payload
from ipv8.messaging.payload_dataclass import dataclass, type_from_format
from ipv8.messaging.serialization import Serializable


class MySerializable(Serializable):
    format_list = ['I', 'H']

    def __init__(self, field1: int, field2: int) -> None:
        self.field1 = field1
        self.field2 = field2

    def to_pack_list(self) -> list[tuple]:
        return [('I', self.field1),
                ('H', self.field2)]

    @classmethod
    def from_unpack_list(cls: type[MySerializable],
                         field1: int, field2: int) -> MySerializable:
        return cls(field1, field2)


class MyPayload(Payload):
    format_list = ['I', 'H']

    def __init__(self, field1: int, field2: int) -> None:
        self.field1 = field1
        self.field2 = field2

    def to_pack_list(self) -> list[tuple]:
        return [('I', self.field1),
                ('H', self.field2)]

    @classmethod
    def from_unpack_list(cls: type[MyPayload],
                         field1: int, field2: int) -> MyPayload:
        return cls(field1, field2)


class MyVariablePayload(VariablePayload):
    format_list = ['I', 'H']
    names = ['field1', 'field2']


@vp_compile
class MyCVariablePayload(VariablePayload):
    format_list = ['I', 'H']
    names = ['field1', 'field2']


I = type_from_format('I')
H = type_from_format('H')


@dataclass
class MyDataclassPayload:
    field1: I
    field2: H


serializable1 = MySerializable(1, 2)
serializable2 = MyPayload(1, 2)
serializable3 = MyVariablePayload(1, 2)
serializable4 = MyCVariablePayload(1, 2)
serializable5 = MyDataclassPayload(1, 2)

print("As string:")
print(serializable1)
print(serializable2)
print(serializable3)
print(serializable4)
print(serializable5)
