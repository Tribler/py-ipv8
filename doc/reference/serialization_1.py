import timeit

from pyipv8.ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from pyipv8.ipv8.messaging.payload import Payload
from pyipv8.ipv8.messaging.serialization import Serializable


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


serializable1 = MySerializable(1, 2)
serializable2 = MyPayload(1, 2)
serializable3 = MyVariablePayload(1, 2)
serializable4 = MyCVariablePayload(1, 2)

print("As string:")
print(serializable1)
print(serializable2)
print(serializable3)
print(serializable4)

print("Field values:")
print(serializable1.field1, serializable1.field2)
print(serializable2.field1, serializable2.field2)
print(serializable3.field1, getattr(serializable3, 'field2', '<undefined>'))
print(serializable4.field1, getattr(serializable4, 'field2', '<undefined>'))

print("Serialization speed:")
print(timeit.timeit('serializable1.to_pack_list()', number=1000, globals=locals()))
print(timeit.timeit('serializable2.to_pack_list()', number=1000, globals=locals()))
print(timeit.timeit('serializable3.to_pack_list()', number=1000, globals=locals()))
print(timeit.timeit('serializable4.to_pack_list()', number=1000, globals=locals()))

print("Unserialization speed:")
print(timeit.timeit('serializable1.from_unpack_list(1, 2)', number=1000, globals=locals()))
print(timeit.timeit('serializable2.from_unpack_list(1, 2)', number=1000, globals=locals()))
print(timeit.timeit('serializable3.from_unpack_list(1, 2)', number=1000, globals=locals()))
print(timeit.timeit('serializable4.from_unpack_list(1, 2)', number=1000, globals=locals()))
