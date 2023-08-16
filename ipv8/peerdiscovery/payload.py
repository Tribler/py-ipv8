from __future__ import annotations

from socket import inet_aton, inet_ntoa
from struct import pack, unpack
from typing import TYPE_CHECKING

from ..messaging.payload import IntroductionRequestPayload, Payload, decode_connection_type, encode_connection_type

if TYPE_CHECKING:
    from ..types import Address


class SimilarityRequestPayload(Payload):
    """
    Payload to request overlap with our own Community instances.
    """

    msg_id = 1
    format_list = ['H', '4SH', '4SH', 'bits', 'raw']

    def __init__(self, identifier: int, lan_address: Address, wan_address: Address,  # noqa: PLR0913
                 connection_type: str, preference_list: list[bytes]) -> None:
        """
        Create a new similarity request payload.
        """
        super().__init__()
        self.identifier = identifier % 65536
        self.preference_list = preference_list
        self.lan_address = lan_address
        self.wan_address = wan_address
        self.connection_type = connection_type

    def to_pack_list(self) -> list[tuple]:
        """
        Pack our values.
        """
        encoded_connection_type = encode_connection_type(self.connection_type)
        return [('H', self.identifier),
                ('4SH', inet_aton(self.lan_address[0]), self.lan_address[1]),
                ('4SH', inet_aton(self.wan_address[0]), self.wan_address[1]),
                ('bits', encoded_connection_type[0], encoded_connection_type[1], 0, 0, 0, 0, 0, 0),
                ('raw', b"".join(self.preference_list))]


    @classmethod
    def from_unpack_list(cls: type[SimilarityRequestPayload], identifier: int,  # noqa: PLR0913
                         lan_address: tuple[bytes, int], wan_address: tuple[bytes, int],
                         connection_type_0: int, connection_type_1: int,
                         dflag0: int, dflag1: int, dflag2: int, dflag3: int, dflag4: int, dflag5: int,  # noqa: ARG003
                         preference_list: bytes) -> SimilarityRequestPayload:
        """
        Unpack a SimilarityRequestPayload.
        """
        args = [identifier,
                (inet_ntoa(lan_address[0]), lan_address[1]),
                (inet_ntoa(wan_address[0]), wan_address[1]),
                decode_connection_type(connection_type_0, connection_type_1),
                [preference_list[i:i + 20] for i in range(0, len(preference_list), 20)]]

        return SimilarityRequestPayload(*args)


class SimilarityResponsePayload(Payload):
    """
    Payload to respond with overlap with our own Community instances.
    """

    msg_id = 2
    format_list = ['H', 'varlenHx20', 'raw']

    def __init__(self, identifier: int, preference_list: list[bytes], tb_overlap: list[tuple[bytes, int]]) -> None:
        """
        Create a new similarity response payload.
        """
        super().__init__()
        self.identifier = identifier % 65536
        self.preference_list = preference_list
        self.tb_overlap = tb_overlap

    def to_pack_list(self) -> list[tuple]:
        """
        Pack our values.
        """
        encoded_tb_overlap = [pack(">20sI", *tb) for tb in self.tb_overlap]
        return [('H', self.identifier),
                ('varlenHx20', b"".join(self.preference_list)),
                ('raw', b"".join(encoded_tb_overlap))]

    @classmethod
    def from_unpack_list(cls: type[SimilarityResponsePayload], identifier: int,
                         preference_list: bytes, tb_overlap: bytes) -> SimilarityResponsePayload:
        """
        Unpack a SimilarityResponsePayload.
        """
        return SimilarityResponsePayload(identifier,
                                         [preference_list[i:i + 20] for i in range(0, len(preference_list), 20)],
                                         [(tb_overlap[i:i + 20], unpack(">I", tb_overlap[i + 20:i + 24])[0])
                                          for i in range(0, len(tb_overlap), 24)])


class PingPayload(Payload):
    """
    Payload used to ask for a pong.
    """

    msg_id = 3
    format_list = ['H']

    def __init__(self, identifier: int) -> None:
        """
        Create a new ping with a given nonce.
        """
        super().__init__()
        self.identifier = identifier % 65536

    def to_pack_list(self) -> list[tuple]:
        """
        Pack our values.
        """
        return [('H', self.identifier), ]

    @classmethod
    def from_unpack_list(cls: type[PingPayload], identifier: int) -> PingPayload:
        """
        Unpack a PingPayload.
        """
        return PingPayload(identifier)


class PongPayload(PingPayload):
    """
    Payload used to answer a ping.
    """

    msg_id = 4


class DiscoveryIntroductionRequestPayload(IntroductionRequestPayload):
    """
    Custom introduction request override for Dispersy backward compatibility.
    """

    format_list = ['c20s', '4SH', '4SH', '4SH', 'bits', 'H', 'raw']

    def __init__(self, introduce_to: bytes, destination_address: Address, source_lan_address: Address,  # noqa: PLR0913
                 source_wan_address: Address, advice: int, connection_type: str, identifier: int,
                 extra_bytes: bytes) -> None:
        """
        Create a new introduction request.
        """
        super().__init__(destination_address, source_lan_address, source_wan_address, advice, connection_type,
                         identifier, extra_bytes)
        self.introduce_to = introduce_to

    def to_pack_list(self) -> list[tuple]:
        """
        Pack our values.
        """
        data = super().to_pack_list()
        data.insert(0, ('c20s', b'Y', self.introduce_to))
        return data

    @classmethod
    def from_unpack_list(cls: type[DiscoveryIntroductionRequestPayload],  # type: ignore[override]  # noqa: PLR0913
                         introduce_to: bytes,
                         destination_address: tuple[bytes, int], source_lan_address: tuple[bytes, int],
                         source_wan_address: tuple[bytes, int], connection_type_0: int, connection_type_1: int,
                         dflag0: int, dflag1: int, dflag2: int, tunnel: int, _: int, advice: int,  # noqa: ARG003
                         identifier: int, extra_bytes: bytes) -> DiscoveryIntroductionRequestPayload:
        """
        Unpack a DiscoveryIntroductionRequestPayload.
        """
        args = [introduce_to[1:],
                (inet_ntoa(destination_address[0]), destination_address[1]),
                (inet_ntoa(source_lan_address[0]), source_lan_address[1]),
                (inet_ntoa(source_wan_address[0]), source_wan_address[1]),
                [True, False][advice],
                decode_connection_type(connection_type_0, connection_type_1),
                identifier,
                extra_bytes]

        return DiscoveryIntroductionRequestPayload(*args)
