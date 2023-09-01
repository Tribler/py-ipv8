from __future__ import annotations

from .payload import Payload


class BinMemberAuthenticationPayload(Payload):
    """
    Public key (bytes) storage payload.
    """

    format_list = ['varlenH', ]

    def __init__(self, public_key_bin: bytes) -> None:
        """
        Create a new payload.
        """
        super().__init__()
        self.public_key_bin = public_key_bin

    def to_pack_list(self) -> list[tuple]:
        """
        Convert this payload to a pack list.
        """
        return [('varlenH', self.public_key_bin)]

    @classmethod
    def from_unpack_list(cls: type[BinMemberAuthenticationPayload],
                         public_key_bin: bytes) -> BinMemberAuthenticationPayload:
        """
        Read the serialized key material into a payload.
        """
        return BinMemberAuthenticationPayload(public_key_bin)


class GlobalTimeDistributionPayload(Payload):
    """
    Payload to communicate (and synchronize) Lamport timestamps.
    """

    format_list = ['Q', ]

    def __init__(self, global_time: int) -> None:
        """
        Create a new payload.
        """
        super().__init__()
        self.global_time = global_time

    def to_pack_list(self) -> list[tuple]:
        """
        Convert this payload to a pack list.
        """
        return [('Q', self.global_time)]

    @classmethod
    def from_unpack_list(cls: type[GlobalTimeDistributionPayload], global_time: int) -> GlobalTimeDistributionPayload:
        """
        Read the serialized time into a payload.
        """
        return GlobalTimeDistributionPayload(global_time)
