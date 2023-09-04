from __future__ import annotations

from typing import TYPE_CHECKING

from ..messaging.lazy_payload import VariablePayloadWID, vp_compile
from ..messaging.serialization import Payload

if TYPE_CHECKING:
    from ..types import Address


def encode_connection_type(type: str) -> tuple[int, int]:  # noqa: A002
    """
    Convert a type string to a tuple.
    """
    if type == "public":
        return 1, 0
    if type == "symmetric-NAT":
        return 1, 1
    return 0, 0


def decode_connection_type(bit_0: int, bit_1: int) -> str:
    """
    Convert connection type flags to a type string.
    """
    bits = (bit_0, bit_1)
    if bits == (0, 0):
        return "unknown"
    if bits == (1, 0):
        return "public"
    if bits == (1, 1):
        return "symmetric-NAT"
    return "N/A"


class IntroductionRequestPayload(Payload):
    """
    Payload sent to peers that we are not connected to yet but have been punctured for us.
    """

    msg_id = 246
    format_list = ['ipv4', 'ipv4', 'ipv4', 'bits', 'H', 'raw']

    def __init__(self, destination_address: Address, source_lan_address: Address,  # noqa: PLR0913
                 source_wan_address: Address, advice: bool, connection_type: str, identifier: int, extra_bytes: bytes,
                 supports_new_style: bool = True) -> None:
        """
        Create the payload for an introduction-request message.

        DESTINATION_ADDRESS is the address of the receiver.  Effectively this should be the
        wan address that others can use to contact the receiver.

        SOURCE_LAN_ADDRESS is the lan address of the sender.  Nodes in the same LAN
        should use this address to communicate.

        SOURCE_WAN_ADDRESS is the wan address of the sender.  Nodes not in the same
        LAN should use this address to communicate.

        ADVICE is a boolean value.  When True the receiver will introduce the sender to a new
        node.  This introduction will be facilitated by the receiver sending a puncture-request
        to the new node.

        CONNECTION_TYPE is a unicode string indicating the connection type that the message
        creator has. Currently, the following values are supported: u"unknown", u"public", and
        u"symmetric-NAT".

        IDENTIFIER is a number that must be given in the associated introduction-response.  This
        number allows to distinguish between multiple introduction-response messages.

        EXTRA_BYTES is a string that can be used to piggyback extra information.
        """
        super().__init__()
        self.destination_address = destination_address
        self.source_lan_address = source_lan_address
        self.source_wan_address = source_wan_address
        self.advice = advice
        self.supports_new_style = supports_new_style
        self.connection_type = connection_type
        self.identifier = identifier % 65536
        self.extra_bytes = extra_bytes

    def to_pack_list(self) -> list[tuple]:
        """
        Convert this payload to a pack list.
        """
        encoded_connection_type = encode_connection_type(self.connection_type)
        return [('ipv4', self.destination_address),
                ('ipv4', self.source_lan_address),
                ('ipv4', self.source_wan_address),
                ('bits', encoded_connection_type[0], encoded_connection_type[1], self.supports_new_style, 0, 0, 0, 0,
                 self.advice),
                ('H', self.identifier),
                ('raw', self.extra_bytes)]

    @classmethod
    def from_unpack_list(cls: type[IntroductionRequestPayload], destination_address: Address,  # noqa: PLR0913
                         source_lan_address: Address, source_wan_address: Address, connection_type_0: bool,
                         connection_type_1: bool, supports_new_style: bool,
                         dflag1: bool, dflag2: bool, tunnel: bool, sync: bool,  # noqa: ARG003
                         advice: bool, identifier: int, extra_bytes: bytes) -> IntroductionRequestPayload:
        """
        Unpack a payload from the given data.
        """
        return IntroductionRequestPayload(destination_address,
                                          source_lan_address,
                                          source_wan_address,
                                          [True, False][advice],
                                          decode_connection_type(connection_type_0, connection_type_1),
                                          identifier,
                                          extra_bytes,
                                          supports_new_style)


@vp_compile
class NewIntroductionRequestPayload(VariablePayloadWID):
    """
    New introduction request that supports non-IPv4 addresses.
    """

    msg_id = 234
    format_list = ['ip_address', 'ip_address', 'ip_address', 'H', 'bits', 'raw']
    names = ["destination_address", "source_lan_address", "source_wan_address", "identifier", "connection_type_0",
             "connection_type_1", "supports_new_style", "dflag1", "dflag2", "tunnel", "sync", "advice", "extra_bytes"]

    destination_address: Address
    source_lan_address: Address
    source_wan_address: Address
    identifier: int
    connection_type_0: int
    connection_type_1: int
    supports_new_style: int
    dflag1: int
    dflag2: int
    tunnel: int
    sync: int
    advice: int
    extra_bytes: bytes


class IntroductionResponsePayload(Payload):
    """
    Response to introduction requests.
    """

    msg_id = 245
    format_list = ['ipv4', 'ipv4', 'ipv4', 'ipv4', 'ipv4', 'bits', 'H', 'raw']

    def __init__(self, destination_address: Address, source_lan_address: Address,  # noqa: PLR0913
                 source_wan_address: Address, lan_introduction_address: Address,
                 wan_introduction_address: Address, connection_type: str, identifier: int, extra_bytes: bytes,
                 supports_new_style: bool = True, intro_supports_new_style: bool = False,
                 peer_limit_reached: bool = False) -> None:
        """
        Create the payload for an introduction-response message.

        DESTINATION_ADDRESS is the address of the receiver.  Effectively this should be the
        wan address that others can use to contact the receiver.

        SOURCE_LAN_ADDRESS is the lan address of the sender.  Nodes in the same LAN
        should use this address to communicate.

        SOURCE_WAN_ADDRESS is the wan address of the sender.  Nodes not in the same
        LAN should use this address to communicate.

        LAN_INTRODUCTION_ADDRESS is the lan address of the node that the sender
        advises the receiver to contact.  This address is zero when the associated request did
        not want advice.

        WAN_INTRODUCTION_ADDRESS is the wan address of the node that the sender
        advises the receiver to contact.  This address is zero when the associated request did
        not want advice.

        CONNECTION_TYPE is a unicode string indicating the connection type that the message
        creator has. Currently, the following values are supported: u"unknown", u"public", and
        u"symmetric-NAT".

        IDENTIFIER is a number that was given in the associated introduction-request.  This
        number allows to distinguish between multiple introduction-response messages.

        EXTRA_BYTES is a string that can be used to piggyback extra information.

        When the associated request wanted advice the sender will also sent a puncture-request
        message to either the lan_introduction_address or the wan_introduction_address
        (depending on their positions).  The introduced node must sent a puncture message to the
        receiver to punch a hole in its NAT.
        """
        super().__init__()
        self.destination_address = destination_address
        self.source_lan_address = source_lan_address
        self.source_wan_address = source_wan_address
        self.lan_introduction_address = lan_introduction_address
        self.wan_introduction_address = wan_introduction_address
        self.connection_type = connection_type
        self.supports_new_style = supports_new_style
        self.intro_supports_new_style = intro_supports_new_style
        self.peer_limit_reached = peer_limit_reached
        self.identifier = identifier % 65536
        self.extra_bytes = extra_bytes

    def to_pack_list(self) -> list[tuple]:
        """
        Convert this payload to a pack list.
        """
        encoded_connection_type = encode_connection_type(self.connection_type)
        return [('ipv4', self.destination_address),
                ('ipv4', self.source_lan_address),
                ('ipv4', self.source_wan_address),
                ('ipv4', self.lan_introduction_address),
                ('ipv4', self.wan_introduction_address),
                ('bits', encoded_connection_type[0], encoded_connection_type[1], 0, self.supports_new_style,
                 self.intro_supports_new_style, self.peer_limit_reached, 0, 0),
                ('H', self.identifier),
                ('raw', self.extra_bytes)]

    @classmethod
    def from_unpack_list(cls: type[IntroductionResponsePayload], destination_address: Address,  # noqa: PLR0913
                         source_lan_address: Address, source_wan_address: Address, introduction_lan_address: Address,
                         introduction_wan_address: Address, connection_type_0: bool, connection_type_1: bool,
                         dflag0: bool, supports_new_style: bool, intro_supports_new_style: bool,  # noqa: ARG003
                         peer_limit_reached: bool, dflag4: bool, dflag5: bool, identifier: int,  # noqa: ARG003
                         extra_bytes: bytes) -> IntroductionResponsePayload:
        """
        Convert the raw data to a payload.
        """
        return IntroductionResponsePayload(destination_address,
                                           source_lan_address,
                                           source_wan_address,
                                           introduction_lan_address,
                                           introduction_wan_address,
                                           decode_connection_type(connection_type_0, connection_type_1),
                                           identifier,
                                           extra_bytes,
                                           supports_new_style,
                                           intro_supports_new_style,
                                           peer_limit_reached)


@vp_compile
class NewIntroductionResponsePayload(VariablePayloadWID):
    """
    New introduction response that supports non-IPv4 addresses.
    """

    msg_id = 233
    format_list = ['ip_address', 'ip_address', 'ip_address', 'ip_address', 'ip_address', 'H', 'bits', 'raw']
    names = ["destination_address", "source_lan_address", "source_wan_address", "lan_introduction_address",
             "wan_introduction_address", "identifier", "intro_supports_new_style", "flag1", "flag2", "flag3",
             "flag4", "flag5", "flag6", "flag7", "extra_bytes"]

    destination_address: Address
    source_lan_address: Address
    source_wan_address: Address
    lan_introduction_address: Address
    wan_introduction_address: Address
    identifier: int
    intro_supports_new_style: bool
    flag1: int
    flag2: int
    flag3: int
    flag4: int
    flag5: int
    flag6: int
    flag7: int
    extra_bytes: bytes


class PunctureRequestPayload(Payload):
    """
    Payload to ask someone to puncture a third party for us.
    """

    msg_id = 250
    format_list = ['ipv4', 'ipv4', 'H']

    def __init__(self, lan_walker_address: Address, wan_walker_address: Address, identifier: int) -> None:
        """
        Create the payload for a puncture-request payload.

        LAN_WALKER_ADDRESS is the lan address of the node that the sender wants us to
        contact.  This contact attempt should punch a hole in our NAT to allow the node to
        connect to us.

        WAN_WALKER_ADDRESS is the wan address of the node that the sender wants us to
        contact.  This contact attempt should punch a hole in our NAT to allow the node to
        connect to us.

        IDENTIFIER is a number that was given in the associated introduction-request.  This
        number allows to distinguish between multiple introduction-response messages.
        """
        super().__init__()
        self.lan_walker_address = lan_walker_address
        self.wan_walker_address = wan_walker_address
        self.identifier = identifier % 65536

    def to_pack_list(self) -> list[tuple]:
        """
        Convert this payload to a pack list.
        """
        return [('ipv4', self.lan_walker_address),
                ('ipv4', self.wan_walker_address),
                ('H', self.identifier)]

    @classmethod
    def from_unpack_list(cls: type[PunctureRequestPayload], lan_walker_address: Address, wan_walker_address: Address,
                         identifier: int) -> PunctureRequestPayload:
        """
        Create a payload from the given data.
        """
        return PunctureRequestPayload(lan_walker_address, wan_walker_address, identifier)


@vp_compile
class NewPunctureRequestPayload(VariablePayloadWID):
    """
    New puncture request that supports non-IPv4 addresses.
    """

    msg_id = 232
    format_list = ['ip_address', 'ip_address', 'H']
    names = ["lan_walker_address", "wan_walker_address", "identifier"]

    lan_walker_address: Address
    wan_walker_address: Address
    identifier: int


class PuncturePayload(Payload):
    """
    Attempt to puncture a NAT layer.
    """

    msg_id = 249
    format_list = ['ipv4', 'ipv4', 'H']

    def __init__(self, source_lan_address: Address, source_wan_address: Address, identifier :int) -> None:
        """
        Create the payload for a puncture message.

        SOURCE_LAN_ADDRESS is the lan address of the sender.  Nodes in the same LAN
        should use this address to communicate.

        SOURCE_WAN_ADDRESS is the wan address of the sender.  Nodes not in the same
        LAN should use this address to communicate.

        IDENTIFIER is a number that was given in the associated introduction-request.  This
        number allows to distinguish between multiple introduction-response messages.
        """
        super().__init__()
        self.source_lan_address = source_lan_address
        self.source_wan_address = source_wan_address
        self.identifier = identifier % 65536

    def to_pack_list(self) -> list[tuple]:
        """
        Convert this payload to a pack list.
        """
        return [('ipv4', self.source_lan_address),
                ('ipv4', self.source_wan_address),
                ('H', self.identifier)]


    @classmethod
    def from_unpack_list(cls: type[PuncturePayload], lan_walker_address: Address, wan_walker_address: Address,
                         identifier: int) -> PuncturePayload:
        """
        Conver the given data to a payload.
        """
        return PuncturePayload(lan_walker_address, wan_walker_address, identifier)


@vp_compile
class NewPuncturePayload(VariablePayloadWID):
    """
    New puncture payload that supports non-IPv4 addresses.
    """

    msg_id = 231
    format_list = ['ip_address', 'ip_address', 'H']
    names = ["source_lan_address", "source_wan_address", "identifier"]

    source_lan_address: Address
    source_wan_address: Address
    identifier: int
