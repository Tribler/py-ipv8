from dataclasses import dataclass

from pyipv8.ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from pyipv8.ipv8.messaging.payload import Payload
from pyipv8.ipv8.messaging.payload_dataclass import overwrite_dataclass, type_from_format
from pyipv8.ipv8.messaging.serialization import Serializable

dataclass = overwrite_dataclass(dataclass)


class MySerializable(Serializable):
    format_list = ['I', 'H']

    def __init__(self, field1, field2):
        self.field1 = field1
        self.field2 = field2

    def to_pack_list(self):
        return [('I', self.field1),
                ('H', self.field2)]

    @classmethod
    def from_unpack_list(cls, *args):
        return cls(*args)


class MyPayload(Payload):
    format_list = ['I', 'H']

    def __init__(self, field1, field2):
        self.field1 = field1
        self.field2 = field2

    def to_pack_list(self):
        return [('I', self.field1),
                ('H', self.field2)]

    @classmethod
    def from_unpack_list(cls, *args):
        return cls(*args)


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
