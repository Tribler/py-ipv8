from functools import reduce
from struct import calcsize, pack, unpack_from

from ...messaging.anonymization.tunnel import (CIRCUIT_TYPE_RP_DOWNLOADER, CIRCUIT_TYPE_RP_SEEDER, EXIT_NODE,
                                               EXIT_NODE_SALT, ORIGINATOR, ORIGINATOR_SALT)
from ...messaging.anonymization.tunnelcrypto import CryptoException
from ...messaging.lazy_payload import VariablePayload, vp_compile

NO_CRYPTO_PACKETS = [2, 3]


@vp_compile
class ExtraIntroductionPayload(VariablePayload):
    names = ['flags']
    format_list = ['flags']


@vp_compile
class DataPayload(VariablePayload):
    msg_id = 1
    names = ['circuit_id', 'dest_address', 'org_address', 'data']
    format_list = ['I', 'address', 'address', 'raw']


@vp_compile
class CreatePayload(VariablePayload):
    msg_id = 2
    names = ['circuit_id', 'identifier', 'node_public_key', 'key']
    format_list = ['I', 'H', 'varlenH', 'varlenH']


@vp_compile
class CreatedPayload(VariablePayload):
    msg_id = 3
    names = ['circuit_id', 'identifier', 'key', 'auth', 'candidate_list_enc']
    format_list = ['I', 'H', 'varlenH', '32s', 'raw']


@vp_compile
class ExtendPayload(VariablePayload):
    msg_id = 4
    names = ['circuit_id', 'identifier', 'node_public_key', 'key', 'node_addr']
    format_list = ['I', 'H', 'varlenH', 'varlenH', 'ipv4']


@vp_compile
class ExtendedPayload(VariablePayload):
    msg_id = 5
    names = ['circuit_id', 'identifier', 'key', 'auth', 'candidate_list_enc']
    format_list = ['I', 'H', 'varlenH', '32s', 'raw']


@vp_compile
class PingPayload(VariablePayload):
    msg_id = 6
    names = ['circuit_id', 'identifier']
    format_list = ['I', 'H']


@vp_compile
class PongPayload(VariablePayload):
    msg_id = 7
    names = ['circuit_id', 'identifier']
    format_list = ['I', 'H']


@vp_compile
class DestroyPayload(VariablePayload):
    msg_id = 8
    names = ['circuit_id', 'reason']
    format_list = ['I', 'H']


@vp_compile
class EstablishIntroPayload(VariablePayload):
    msg_id = 9
    names = ['circuit_id', 'identifier', 'info_hash', 'public_key']
    format_list = ['I', 'H', '20s', 'varlenH']


@vp_compile
class IntroEstablishedPayload(VariablePayload):
    msg_id = 10
    names = ['circuit_id', 'identifier']
    format_list = ['I', 'H']


@vp_compile
class EstablishRendezvousPayload(VariablePayload):
    msg_id = 11
    names = ['circuit_id', 'identifier', 'cookie']
    format_list = ['I', 'H', '20s']


@vp_compile
class RendezvousEstablishedPayload(VariablePayload):
    msg_id = 12
    names = ['circuit_id', 'identifier', 'rendezvous_point_addr']
    format_list = ['I', 'H', 'ipv4']


@vp_compile
class CreateE2EPayload(VariablePayload):
    msg_id = 13
    names = ['identifier', 'info_hash', 'node_public_key', 'key']
    format_list = ['H', '20s', 'varlenH', 'varlenH']


@vp_compile
class CreatedE2EPayload(VariablePayload):
    msg_id = 14
    names = ['identifier', 'key', 'auth', 'rp_info_enc']
    format_list = ['H', 'varlenH', '32s', 'raw']


@vp_compile
class LinkE2EPayload(VariablePayload):
    msg_id = 15
    names = ['circuit_id', 'identifier', 'cookie']
    format_list = ['I', 'H', '20s']


@vp_compile
class LinkedE2EPayload(VariablePayload):
    msg_id = 16
    names = ['circuit_id', 'identifier']
    format_list = ['I', 'H']


@vp_compile
class PeersRequestPayload(VariablePayload):
    msg_id = 17
    names = ['circuit_id', 'identifier', 'info_hash']
    format_list = ['I', 'H', '20s']


@vp_compile
class IntroductionInfo(VariablePayload):
    names = ['address', 'key', 'seeder_pk', 'source']
    format_list = ['ipv4', 'varlenH', 'varlenH', 'B']


@vp_compile
class PeersResponsePayload(VariablePayload):
    msg_id = 18
    names = ['circuit_id', 'identifier', 'info_hash', 'peers']
    format_list = ['I', 'H', '20s', [IntroductionInfo]]


@vp_compile
class RendezvousInfo(VariablePayload):
    names = ['address', 'key', 'cookie']
    format_list = ['ipv4', 'varlenH', '20s']


@vp_compile
class TestRequestPayload(VariablePayload):
    msg_id = 19
    names = ['circuit_id', 'identifier', 'response_size', 'data']
    format_list = ['I', 'H', 'H', 'raw']


@vp_compile
class TestResponsePayload(VariablePayload):
    msg_id = 20
    names = ['circuit_id', 'identifier', 'data']
    format_list = ['I', 'H', 'raw']


class Flags:

    def __init__(self, fmt='>H'):
        self.format = fmt
        self.size = calcsize(fmt)

    def pack(self, data):
        return pack(self.format, reduce(lambda a, b: a | b, data, 0))

    def unpack(self, data, offset, unpack_list):
        number, = unpack_from(self.format, data, offset)
        unpack_list.append(list(filter(None, [number & (2 ** i) for i in range(self.size * 8)])))
        return self.size


class CellPayload:
    msg_id = 0

    def __init__(self, circuit_id, message, plaintext=False, relay_early=False):
        self.circuit_id = circuit_id
        self.message = message
        self.plaintext = plaintext
        self.relay_early = relay_early

    def encrypt(self, crypto, circuit=None, relay_session_keys=None):
        if self.plaintext:
            return

        if circuit:
            if circuit.hs_session_keys and circuit.ctype in [CIRCUIT_TYPE_RP_SEEDER, CIRCUIT_TYPE_RP_DOWNLOADER]:
                direction = int(circuit.ctype == CIRCUIT_TYPE_RP_SEEDER)
                self.message = crypto.encrypt_str(self.message,
                                                  *crypto.get_session_keys(circuit.hs_session_keys, direction))

            for hop in reversed(circuit.hops):
                self.message = crypto.encrypt_str(self.message, *crypto.get_session_keys(hop.session_keys, EXIT_NODE))

        elif relay_session_keys:
            self.message = crypto.encrypt_str(self.message, *crypto.get_session_keys(relay_session_keys, ORIGINATOR))

        else:
            raise CryptoException("Error encrypting message for unknown circuit %d" % self.circuit_id)

    def decrypt(self, crypto, circuit=None, relay_session_keys=None):
        if self.plaintext:
            return

        if circuit:
            if not circuit.hops:
                raise CryptoException("Error decrypting message for 0-hop circuit %d" % self.circuit_id)

            # Remove all the encryption layers
            for layer, hop in enumerate(circuit.hops):
                try:
                    self.message = crypto.decrypt_str(self.message,
                                                      hop.session_keys[ORIGINATOR],
                                                      hop.session_keys[ORIGINATOR_SALT])
                except ValueError as e:
                    raise CryptoException("Got exception %r when trying to remove encryption layer %s "
                                          "for message: %r received for circuit_id: %s, circuit_hops: %r" %
                                          (e, layer, self.message, self.circuit_id, circuit.hops)) from e

            if circuit.hs_session_keys and circuit.ctype in [CIRCUIT_TYPE_RP_SEEDER, CIRCUIT_TYPE_RP_DOWNLOADER]:
                direction = int(circuit.ctype == CIRCUIT_TYPE_RP_DOWNLOADER)
                direction_salt = direction + 2
                self.message = crypto.decrypt_str(self.message,
                                                  circuit.hs_session_keys[direction],
                                                  circuit.hs_session_keys[direction_salt])

        elif relay_session_keys:
            try:
                self.message = crypto.decrypt_str(self.message,
                                                  relay_session_keys[EXIT_NODE],
                                                  relay_session_keys[EXIT_NODE_SALT])
            except ValueError as e:
                raise CryptoException("Got exception %r when trying to decrypt relay message: "
                                      "cell received for circuit_id: %s" % (e, self.circuit_id)) from e

        else:
            raise CryptoException("Error decrypting message for unknown circuit %d" % self.circuit_id)

    def unwrap(self, prefix):
        return b''.join([prefix,
                         self.message[0:1],
                         pack('!I', self.circuit_id),
                         self.message[1:]])

    def to_bin(self, prefix):
        return b''.join([prefix,
                         bytes([self.msg_id]),
                         pack('!I??', self.circuit_id, self.plaintext, self.relay_early) + self.message])

    @classmethod
    def from_bin(cls, packet):
        circuit_id, plaintext, relay_early = unpack_from('!I??', packet, 23)
        return cls(circuit_id, packet[29:], plaintext, relay_early)
