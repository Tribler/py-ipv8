from dataclasses import dataclass
import json

from pyipv8.ipv8.messaging.payload_dataclass import overwrite_dataclass
from pyipv8.ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from pyipv8.ipv8.messaging.serialization import default_serializer

dataclass = overwrite_dataclass(dataclass)


@vp_compile
class VPMessageKeepDict(VariablePayload):
    msg_id = 1
    format_list = ['varlenH']
    names = ["dictionary"]

    def fix_pack_dictionary(self, the_dictionary: dict) -> bytes:
        return json.dumps(the_dictionary).encode()

    @classmethod
    def fix_unpack_dictionary(cls, serialized_dictionary: bytes) -> dict:
        return json.loads(serialized_dictionary.decode())


@dataclass(msg_id=2)
class DCMessageKeepDict:
    dictionary: str

    def fix_pack_dictionary(self, the_dictionary: dict) -> str:
        return json.dumps(the_dictionary)

    @classmethod
    def fix_unpack_dictionary(cls, serialized_dictionary: str) -> dict:
        return json.loads(serialized_dictionary)


data = {"1": 1, "key": "value"}

message1 = VPMessageKeepDict(data)
message2 = DCMessageKeepDict(data)

assert message1.dictionary["1"] == 1
assert message1.dictionary["key"] == "value"
assert message2.dictionary["1"] == 1
assert message2.dictionary["key"] == "value"

serialized1 = default_serializer.pack_serializable(message1)
serialized2 = default_serializer.pack_serializable(message2)

assert serialized1 == serialized2

unserialized1, _ = default_serializer.unpack_serializable(VPMessageKeepDict, serialized1)
unserialized2, _ = default_serializer.unpack_serializable(DCMessageKeepDict, serialized2)

assert unserialized1.dictionary["1"] == 1
assert unserialized1.dictionary["key"] == "value"
assert unserialized2.dictionary["1"] == 1
assert unserialized2.dictionary["key"] == "value"
