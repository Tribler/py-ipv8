from __future__ import annotations

from functools import reduce
from struct import calcsize, pack, unpack_from

from ...messaging.lazy_payload import VariablePayload, vp_compile
from ..serialization import Packer


@vp_compile
class ExtraIntroductionPayload(VariablePayload):
    """
    Payload to piggyback onto introduction messages.
    """

    names = ["flags"]
    format_list = ["flags"]

    flags: list[int]


class Flags(Packer):
    """
    Packer for flags (default: as a short).
    """

    def __init__(self, fmt: str = ">H") -> None:
        """
        Allocate flags in the given ``struct`` format.
        """
        self.format = fmt
        self.size = calcsize(fmt)

    def pack(self, data: list[int]) -> bytes:
        """
        Pack the individual flag integer values into a single integer and serialize them.
        """
        return pack(self.format, reduce(lambda a, b: a | b, data, 0))

    def unpack(self, data: bytes, offset: int, unpack_list: list, *args: object) -> int:
        """
        Uncompress the flags from their serialized form.
        """
        number, = unpack_from(self.format, data, offset)
        unpack_list.append(list(filter(None, [number & (2 ** i) for i in range(self.size * 8)])))
        return self.size
