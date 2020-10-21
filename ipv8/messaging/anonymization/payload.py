import socket
from functools import reduce
from struct import pack, unpack_from

from cryptography.exceptions import InvalidTag

from ...messaging.anonymization.tunnel import (CIRCUIT_TYPE_RP_DOWNLOADER, CIRCUIT_TYPE_RP_SEEDER, EXIT_NODE,
                                               EXIT_NODE_SALT, ORIGINATOR, ORIGINATOR_SALT)
from ...messaging.anonymization.tunnelcrypto import CryptoException
from ...messaging.lazy_payload import VariablePayload, vp_compile
from ...messaging.payload import Payload

ADDRESS_TYPE_IPV4 = 0x01
ADDRESS_TYPE_DOMAIN_NAME = 0x02

NO_CRYPTO_PACKETS = [2, 3]


def encode_address(host, port):
    try:
        ip = socket.inet_aton(host)
        is_ip = True
    except (ValueError, OSError):
        is_ip = False

    if is_ip:
        return pack("!B4sH", ADDRESS_TYPE_IPV4, ip, port)
    else:
        host_bytes = host.encode('utf-8')
        return pack("!BH", ADDRESS_TYPE_DOMAIN_NAME, len(host_bytes)) + host_bytes + pack("!H", port)


def decode_address(packet):
    addr_type, = unpack_from("!B", packet)

    if addr_type == ADDRESS_TYPE_IPV4:
        host, port = unpack_from('!4sH', packet, 1)
        return socket.inet_ntoa(host), port

    elif addr_type == ADDRESS_TYPE_DOMAIN_NAME:
        length, = unpack_from('!H', packet, 1)
        host = packet[3:3 + length].decode('utf-8')
        port, = unpack_from('!H', packet, 3 + length)
        return host, port

    return None


class ExtraIntroductionPayload(Payload):

    format_list = ['H']

    def __init__(self, flags):
        super(ExtraIntroductionPayload, self).__init__()
        self.flags = flags

    def to_pack_list(self):
        return [('H', reduce(lambda a, b: a | b, self.flags))]

    @classmethod
    def from_unpack_list(cls, flags):
        return ExtraIntroductionPayload(list(filter(None, [flags & (2**i) for i in range(16)])))


class DataPayload(object):
    msg_id = 0

    def __init__(self, circuit_id, dest_address, org_address, data):
        self.circuit_id = circuit_id
        self.dest_address = dest_address
        self.org_address = org_address
        self.data = data

    def to_bin(self):
        # Note that since we always wrap data packets in cells, we do not need to include prefix + message_id
        dest = encode_address(*self.dest_address)
        org = encode_address(*self.org_address)
        return b''.join([pack('!H', len(dest)), dest,
                         pack('!H', len(org)), org,
                         self.data])

    @classmethod
    def from_bin(cls, packet):
        circuit_id, len_dest = unpack_from('!IH', packet, 23)
        len_org, = unpack_from('!H', packet, 29 + len_dest)
        return cls(circuit_id,
                   decode_address(packet[29:29 + len_dest]),
                   decode_address(packet[31 + len_dest:31 + len_dest + len_org]),
                   packet[31 + len_dest + len_org:])


class CellPayload(object):
    msg_id = 1

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
                except InvalidTag as e:
                    raise CryptoException("Got exception %r when trying to remove encryption layer %s "
                                          "for message: %r received for circuit_id: %s, circuit_hops: %r" %
                                          (e, layer, self.message, self.circuit_id, circuit.hops))

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
            except InvalidTag as e:
                # Reasons that can cause this:
                # - The introductionpoint circuit is extended with a candidate
                # that is already part of the circuit, causing a crypto error.
                # Should not happen anyway, thorough analysis of the debug log
                # may reveal why and how this candidate is discovered.
                # - The pubkey of the introduction point changed (e.g. due to a
                # restart), while other peers in the network are still exchanging
                # the old key information.
                # - A hostile peer may have forged the key of a candidate while
                # pexing information about candidates, thus polluting the network
                # with wrong information. I doubt this is the case but it's
                # possible. :)
                # (from https://github.com/Tribler/tribler/issues/1932#issuecomment-182035383)
                raise CryptoException("Got exception %r when trying to decrypt relay message: "
                                      "cell received for circuit_id: %s" % (e, self.circuit_id))

        else:
            raise CryptoException("Error decrypting message for unknown circuit %d" % self.circuit_id)

    def unwrap(self, prefix):
        return b''.join([prefix,
                         self.message[0:1],
                         pack('!I', self.circuit_id),
                         self.message[1:]])

    def to_bin(self, prefix):
        return b''.join([prefix,
                         bytes([1]),
                         pack('!I??', self.circuit_id, self.plaintext, self.relay_early) + self.message])

    @classmethod
    def from_bin(cls, packet):
        circuit_id, plaintext, relay_early = unpack_from('!I??', packet, 23)
        return cls(circuit_id, packet[29:], plaintext, relay_early)


@vp_compile
class CreatePayload(VariablePayload):
    msg_id = 2
    format_list = ['I', 'H', 'varlenH', 'varlenH']
    names = ['circuit_id', 'identifier', 'node_public_key', 'key']


@vp_compile
class CreatedPayload(VariablePayload):
    msg_id = 3
    format_list = ['I', 'H', 'varlenH', '32s', 'raw']
    names = ['circuit_id', 'identifier', 'key', 'auth', 'candidate_list_enc']


@vp_compile
class ExtendPayload(VariablePayload):
    msg_id = 4
    format_list = ['I', 'H', 'varlenH', 'varlenH', 'ipv4']
    names = ['circuit_id', 'identifier', 'node_public_key', 'key', 'node_addr']


@vp_compile
class ExtendedPayload(VariablePayload):
    msg_id = 5
    format_list = ['I', 'H', 'varlenH', '32s', 'raw']
    names = ['circuit_id', 'identifier', 'key', 'auth', 'candidate_list_enc']


@vp_compile
class PingPayload(VariablePayload):
    msg_id = 6
    format_list = ['I', 'H']
    names = ['circuit_id', 'identifier']


@vp_compile
class PongPayload(VariablePayload):
    msg_id = 7
    format_list = ['I', 'H']
    names = ['circuit_id', 'identifier']


@vp_compile
class DestroyPayload(VariablePayload):
    msg_id = 10
    format_list = ['I', 'H']
    names = ['circuit_id', 'reason']


@vp_compile
class EstablishIntroPayload(VariablePayload):
    msg_id = 11
    format_list = ['I', 'H', '20s', 'varlenH']
    names = ['circuit_id', 'identifier', 'info_hash', 'public_key']


@vp_compile
class IntroEstablishedPayload(VariablePayload):
    msg_id = 12
    format_list = ['I', 'H']
    names = ['circuit_id', 'identifier']


@vp_compile
class EstablishRendezvousPayload(VariablePayload):
    msg_id = 15
    format_list = ['I', 'H', '20s']
    names = ['circuit_id', 'identifier', 'cookie']


@vp_compile
class RendezvousEstablishedPayload(VariablePayload):
    msg_id = 16
    format_list = ['I', 'H', 'ipv4']
    names = ['circuit_id', 'identifier', 'rendezvous_point_addr']


@vp_compile
class CreateE2EPayload(VariablePayload):
    msg_id = 17
    format_list = ['H', '20s', 'varlenH', 'varlenH']
    names = ['identifier', 'info_hash', 'node_public_key', 'key']


@vp_compile
class CreatedE2EPayload(VariablePayload):
    msg_id = 18
    format_list = ['H', 'varlenH', '32s', 'raw']
    names = ['identifier', 'key', 'auth', 'rp_info_enc']


@vp_compile
class LinkE2EPayload(VariablePayload):
    msg_id = 19
    format_list = ['I', 'H', '20s']
    names = ['circuit_id', 'identifier', 'cookie']


@vp_compile
class LinkedE2EPayload(VariablePayload):
    msg_id = 20
    format_list = ['I', 'H']
    names = ['circuit_id', 'identifier']


@vp_compile
class PeersRequestPayload(VariablePayload):
    msg_id = 21
    format_list = ['I', 'H', '20s']
    names = ['circuit_id', 'identifier', 'info_hash']


@vp_compile
class PeersResponsePayload(VariablePayload):
    msg_id = 22
    format_list = ['I', 'H', '20s', 'raw']
    names = ['circuit_id', 'identifier', 'info_hash', 'peers']


class TestRequestPayload:
    msg_id = 30

    def __init__(self, circuit_id, identifier, response_size, data):
        self.circuit_id = circuit_id
        self.identifier = identifier
        self.response_size = response_size
        self.data = data

    def to_bin(self):
        return pack(f'!HH{len(self.data)}s', self.identifier, self.response_size, self.data)

    @classmethod
    def from_bin(cls, packet):
        return cls(*unpack_from('!IHH', packet, 23), packet[31:])


class TestResponsePayload:
    msg_id = 31

    def __init__(self, circuit_id, identifier, data):
        self.circuit_id = circuit_id
        self.identifier = identifier
        self.data = data

    def to_bin(self):
        return pack(f'!H{len(self.data)}s', self.identifier, self.data)

    @classmethod
    def from_bin(cls, packet):
        return cls(*unpack_from('!IH', packet, 23), packet[29:])
