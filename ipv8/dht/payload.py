from __future__ import annotations

from typing import cast

from ..messaging.lazy_payload import VariablePayload, VariablePayloadWID, vp_compile
from ..messaging.serialization import Packer, Serializer
from ..types import Address
from .routing import Node


@vp_compile
class PingRequestPayload(VariablePayloadWID):
    """
    Payload to send ping messages with a given identifier nonce.
    """

    msg_id = 1
    names = ['identifier']
    format_list = ['I']

    identifier: int


@vp_compile
class PingResponsePayload(VariablePayloadWID):
    """
    Payload to respond to pings with a given identifier.
    """

    msg_id = 2
    names = ['identifier']
    format_list = ['I']

    identifier: int


@vp_compile
class StoreRequestPayload(VariablePayloadWID):
    """
    Payload for a token-holder to send a target certain values to store, with a given identifier nonce.
    """

    msg_id = 3
    names = ['identifier', 'token', 'target', 'values']
    format_list = ['I', '20s', '20s', 'varlenH-list']

    identifier: int
    token: bytes
    target: bytes
    values: list[bytes]


@vp_compile
class StoreResponsePayload(VariablePayloadWID):
    """
    Response that the previously-given values have been stored.
    """

    msg_id = 4
    names = ['identifier']
    format_list = ['I']

    identifier: int


@vp_compile
class FindRequestPayload(VariablePayloadWID):
    """
    Attempt for our lan address to have the given target fetch values and nodes for us from a given starting offset,
    potentially with a request to force new node connections even if some are already known.
    """

    msg_id = 5
    names = ['identifier', 'lan_address', 'target', 'offset', 'force_nodes']
    format_list = ['I', 'ip_address', '20s', 'I', '?']

    identifier: int
    lan_address: Address
    target: bytes
    offset: int
    force_nodes: bool


@vp_compile
class FindResponsePayload(VariablePayloadWID):
    """
    Response to a find request with the known values and nodes for the queried starting offset.
    """

    msg_id = 6
    names = ['identifier', 'token', 'values', 'nodes']
    format_list = ['I', '20s', 'varlenH-list', 'node-list']

    identifier: int
    token: bytes
    values: list[bytes]
    nodes: list[Node]


@vp_compile
class StorePeerRequestPayload(VariablePayloadWID):
    """
    Request to another node to register our own node (id) as a server of the given target.
    """

    msg_id = 7
    names = ['identifier', 'token', 'target']
    format_list = ['I', '20s', '20s']

    identifier: int
    token: bytes
    target: bytes


@vp_compile
class StorePeerResponsePayload(VariablePayloadWID):
    """
    Confirmation that a node (id) has been stored as part of our tree.
    """

    msg_id = 8
    names = ['identifier']
    format_list = ['I']

    identifier: int


@vp_compile
class ConnectPeerRequestPayload(VariablePayloadWID):
    """
    Request for our lan address to be introduced to peers in the target range.
    """

    msg_id = 9
    names = ['identifier', 'lan_address', 'target']
    format_list = ['I', 'ip_address', '20s']

    identifier: int
    lan_address: Address
    target: bytes


@vp_compile
class ConnectPeerResponsePayload(VariablePayloadWID):
    """
    A response to a connection request, with the nodes that have been punctured (and are hopefully connectable).
    """

    msg_id = 10
    names = ['identifier', 'nodes']
    format_list = ['I', 'node-list']

    identifier: int
    nodes: list[Node]


@vp_compile
class StrPayload(VariablePayload):
    """
    Paylaod to pack bytes.
    """

    names = ['data']
    format_list = ['raw']

    data: bytes


@vp_compile
class SignedStrPayload(VariablePayload):
    """
    Payload to pack bytes with a version and a public key.
    """

    names = ['data', 'version', 'public_key']
    format_list = ['varlenH', 'I', 'varlenH']

    data: bytes
    version: int
    public_key: bytes


class NodePacker(Packer):
    """
    Serialization packing format for DHT nodes.
    """

    def __init__(self, serializer: Serializer) -> None:
        """
        Our packer uses the serializer to serialize our IP address and public key sub-packers.
        """
        self.serializer = serializer

    def pack(self, node: Node) -> bytes:
        """
        Pack the given node to bytes.
        """
        return self.serializer.pack('ip_address', node.address) + \
            self.serializer.pack('varlenH', node.public_key.key_to_bin())

    def unpack(self, data: bytes, offset: int, unpack_list: list, *args: object) -> int:
        """
        Unpack the node format from the given offset in the data and add the unpacked object to the list.
        """
        address, offset = self.serializer.unpack('ip_address', data, offset)
        key, offset = self.serializer.unpack('varlenH', data, offset)
        unpack_list.append(Node(cast(bytes, key), address=cast(Address, address)))
        return offset
