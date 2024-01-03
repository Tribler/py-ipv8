from __future__ import annotations

from functools import reduce
from struct import calcsize, pack, unpack_from
from typing import TYPE_CHECKING

from ...messaging.lazy_payload import VariablePayload, VariablePayloadWID, vp_compile
from ..serialization import Packer

if TYPE_CHECKING:
    from ...types import Address


class CellablePayload(VariablePayloadWID):
    """
    Payloads need a ``msg_id`` and a ``circuit_id`` to be turned into a tunnel-able cell.
    """

    circuit_id: int


@vp_compile
class ExtraIntroductionPayload(VariablePayload):
    """
    Payload to piggyback onto introduction messages.
    """

    names = ['flags']
    format_list = ['flags']

    flags: list[int]


@vp_compile
class DataPayload(CellablePayload):
    """
    Payload to transfer raw data over a circuit.
    """

    msg_id = 1
    names = ['circuit_id', 'dest_address', 'org_address', 'data']
    format_list = ['I', 'address', 'address', 'raw']

    circuit_id: int
    dest_address: Address
    org_address: Address
    data: bytes


@vp_compile
class CreatePayload(CellablePayload):
    """
    Payload to initiate circuit creation.
    """

    msg_id = 2
    names = ['circuit_id', 'identifier', 'node_public_key', 'key']
    format_list = ['I', 'H', 'varlenH', 'varlenH']

    circuit_id: int
    identifier: int
    node_public_key: bytes
    key: bytes


@vp_compile
class CreatedPayload(CellablePayload):
    """
    Payload to signal initial circuit first-hop completion.
    """

    msg_id = 3
    names = ['circuit_id', 'identifier', 'key', 'auth', 'candidates_enc']
    format_list = ['I', 'H', 'varlenH', '32s', 'raw']

    circuit_id: int
    identifier: int
    key: bytes
    auth: bytes
    candidates_enc: bytes


@vp_compile
class ExtendPayload(CellablePayload):
    """
    Payload to initiate circuit extension.
    """

    msg_id = 4
    names = ['circuit_id', 'identifier', 'node_public_key', 'key', 'node_addr']
    format_list = ['I', 'H', 'varlenH', 'varlenH', 'ip_address']

    circuit_id: int
    identifier: int
    node_public_key: bytes
    key: bytes
    node_addr: Address


@vp_compile
class ExtendedPayload(CellablePayload):
    """
    Payload to signal extension completion.
    """

    msg_id = 5
    names = ['circuit_id', 'identifier', 'key', 'auth', 'candidates_enc']
    format_list = ['I', 'H', 'varlenH', '32s', 'raw']

    circuit_id: int
    identifier: int
    key: bytes
    auth: bytes
    candidates_enc: bytes


@vp_compile
class PingPayload(CellablePayload):
    """
    Payload to ping over a circuit.
    """

    msg_id = 6
    names = ['circuit_id', 'identifier']
    format_list = ['I', 'H']

    circuit_id: int
    identifier: int


@vp_compile
class PongPayload(CellablePayload):
    """
    Payload to pong over a circuit.
    """

    msg_id = 7
    names = ['circuit_id', 'identifier']
    format_list = ['I', 'H']

    circuit_id: int
    identifier: int


@vp_compile
class DestroyPayload(CellablePayload):
    """
    Payload to signal destruction of a circuit.
    """

    msg_id = 8
    names = ['circuit_id', 'reason']
    format_list = ['I', 'H']

    circuit_id: int
    reason: int


@vp_compile
class EstablishIntroPayload(CellablePayload):
    """
    Payload to initiate establishment of an introduction point.
    """

    msg_id = 9
    names = ['circuit_id', 'identifier', 'info_hash', 'public_key']
    format_list = ['I', 'H', '20s', 'varlenH']

    circuit_id: int
    identifier: int
    info_hash: bytes
    public_key: bytes


@vp_compile
class IntroEstablishedPayload(CellablePayload):
    """
    Payload to signal completion of introduction point establishment.
    """

    msg_id = 10
    names = ['circuit_id', 'identifier']
    format_list = ['I', 'H']

    circuit_id: int
    identifier: int


@vp_compile
class EstablishRendezvousPayload(CellablePayload):
    """
    Payload to initiate creation of a rendezvous point.
    """

    msg_id = 11
    names = ['circuit_id', 'identifier', 'cookie']
    format_list = ['I', 'H', '20s']

    circuit_id: int
    identifier: int
    cookie: bytes


@vp_compile
class RendezvousEstablishedPayload(CellablePayload):
    """
    Payload to signal completion of a rendezvous point.
    """

    msg_id = 12
    names = ['circuit_id', 'identifier', 'rendezvous_point_addr']
    format_list = ['I', 'H', 'ip_address']

    circuit_id: int
    identifier: int
    rendezvous_point_addr: Address


@vp_compile
class CreateE2EPayload(VariablePayloadWID):
    """
    Payload to initiate e2e hookup.
    """

    msg_id = 13
    names = ['identifier', 'info_hash', 'node_public_key', 'key']
    format_list = ['H', '20s', 'varlenH', 'varlenH']

    identifier: int
    info_hash: bytes
    node_public_key: bytes
    key: bytes


@vp_compile
class CreatedE2EPayload(VariablePayloadWID):
    """
    Payload to signal completion of e2e hookup.
    """

    msg_id = 14
    names = ['identifier', 'key', 'auth', 'rp_info_enc']
    format_list = ['H', 'varlenH', '32s', 'raw']

    identifier: int
    key: bytes
    auth: bytes
    rp_info_enc: bytes


@vp_compile
class LinkE2EPayload(CellablePayload):
    """
    Payload to initiate completion linking of an e2e hookup.
    """

    msg_id = 15
    names = ['circuit_id', 'identifier', 'cookie']
    format_list = ['I', 'H', '20s']

    circuit_id: int
    identifier: int
    cookie: bytes


@vp_compile
class LinkedE2EPayload(CellablePayload):
    """
    Payload to signal completion of the final linking of the e2e circuit.
    """

    msg_id = 16
    names = ['circuit_id', 'identifier']
    format_list = ['I', 'H']

    circuit_id: int
    identifier: int


@vp_compile
class PeersRequestPayload(CellablePayload):
    """
    Request for peer lookup for the given info hash.
    """

    msg_id = 17
    names = ['circuit_id', 'identifier', 'info_hash']
    format_list = ['I', 'H', '20s']

    circuit_id: int
    identifier: int
    info_hash: bytes


@vp_compile
class IntroductionInfo(VariablePayload):
    """
    Payload for introduction info.
    """

    names = ['address', 'key', 'seeder_pk', 'source']
    format_list = ['ip_address', 'varlenH', 'varlenH', 'B']

    address: Address
    key: bytes
    seeder_pk: bytes
    source: int


@vp_compile
class PeersResponsePayload(CellablePayload):
    """
    Payload to respond with introduction info of peers for a given info hash.
    """

    msg_id = 18
    names = ['circuit_id', 'identifier', 'info_hash', 'peers']
    format_list = ['I', 'H', '20s', [IntroductionInfo]]

    circuit_id: int
    identifier: int
    info_hash: bytes
    peers: list[IntroductionInfo]


@vp_compile
class RendezvousInfo(VariablePayload):
    """
    Payload for rendezvous info.
    """

    names = ['address', 'key', 'cookie']
    format_list = ['ip_address', 'varlenH', '20s']

    address: Address
    key: bytes
    cookie: bytes


@vp_compile
class TestRequestPayload(CellablePayload):
    """
    Speedtest initiation.
    """

    msg_id = 19
    names = ['circuit_id', 'identifier', 'response_size', 'data']
    format_list = ['I', 'H', 'H', 'raw']

    circuit_id: int
    identifier: int
    response_size: int
    data: bytes


@vp_compile
class TestResponsePayload(CellablePayload):
    """
    Speedtest response.
    """

    msg_id = 20
    names = ['circuit_id', 'identifier', 'data']
    format_list = ['I', 'H', 'raw']

    circuit_id: int
    identifier: int
    data: bytes


class Flags(Packer):
    """
    Packer for flags (default: as a short).
    """

    def __init__(self, fmt: str = '>H') -> None:
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


class CellPayload:
    """
    Raw circuit data.
    """

    msg_id = 0

    def __init__(self, circuit_id: int, message: bytes, plaintext: bool = False, relay_early: bool = False) -> None:
        """
        Prepare the given message for cell encryption (or plaintext).
        """
        self.circuit_id = circuit_id
        self.message = message
        self.plaintext = plaintext
        self.relay_early = relay_early

    def unwrap(self, prefix: bytes) -> bytes:
        """
        Reorder the binary format of this cell, injecting its prefix and circuit id.
        """
        return b''.join([prefix,
                         self.message[0:1],
                         pack('!I', self.circuit_id),
                         self.message[1:]])

    def to_bin(self, prefix: bytes) -> bytes:
        """
        Reorder the binary format of this cell, injecting its message id, circuit id and flags.
        """
        return b''.join([prefix,
                         bytes([self.msg_id]),
                         pack('!I??', self.circuit_id, self.plaintext, self.relay_early) + self.message])

    @classmethod
    def from_bin(cls: type[CellPayload], packet: bytes) -> CellPayload:
        """
        Reconstruct a CellPayload from the given binary format, ordered using ``to_bin()``.
        """
        circuit_id, plaintext, relay_early = unpack_from('!I??', packet, 23)
        return cls(circuit_id, packet[29:], plaintext, relay_early)


NO_CRYPTO_PACKETS = [CreatePayload.msg_id, CreatedPayload.msg_id]
