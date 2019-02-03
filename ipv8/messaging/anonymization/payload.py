from __future__ import absolute_import

import socket
from struct import pack, unpack_from

from cryptography.exceptions import InvalidTag

from ...messaging.serialization import default_serializer
from ...messaging.anonymization.tunnel import CIRCUIT_TYPE_RENDEZVOUS, CIRCUIT_TYPE_RP,\
                                              ORIGINATOR, EXIT_NODE, ORIGINATOR_SALT, EXIT_NODE_SALT
from ...messaging.anonymization.tunnelcrypto import CryptoException
from ...messaging.payload import Payload
from ...util import cast_to_bin, cast_to_chr

ADDRESS_TYPE_IPV4 = 0x01
ADDRESS_TYPE_DOMAIN_NAME = 0x02

NO_CRYPTO_PACKETS = [2, 3]


def encode_address(host, port):
    if not isinstance(host, str):
        host = cast_to_chr(host)
    try:
        ip = socket.inet_aton(host)
        is_ip = True
    except socket.error:
        is_ip = False

    if is_ip:
        return pack("!B4sH", ADDRESS_TYPE_IPV4, ip, port)
    else:
        return pack("!BH", ADDRESS_TYPE_DOMAIN_NAME, len(host)) + cast_to_bin(host) + pack("!H", port)


def decode_address(packet):
    addr_type, = unpack_from("!B", packet)

    if addr_type == ADDRESS_TYPE_IPV4:
        host, port = unpack_from('!4sH', packet, 1)
        return socket.inet_ntoa(host), port

    elif addr_type == ADDRESS_TYPE_DOMAIN_NAME:
        length, = unpack_from('!H', packet, 1)
        host = packet[3:3 + length]
        port, = unpack_from('!H', packet, 3 + length)
        return host, port

    return None


class ExtraIntroductionPayload(Payload):

    format_list = ['?']

    def __init__(self, exitnode):
        self.exitnode = exitnode

    def to_pack_list(self):
        return [('?', self.exitnode)]

    @classmethod
    def from_unpack_list(cls, exitnode):
        return ExtraIntroductionPayload(exitnode)


class DataPayload(Payload):

    format_list = ['I', 'varlenH', 'varlenH', 'raw']

    def __init__(self, circuit_id, dest_address, org_address, data):
        super(DataPayload, self).__init__()
        self.circuit_id = circuit_id
        self.dest_address = dest_address
        self.org_address = org_address
        self.data = data

    def to_pack_list(self):
        return [('I', self.circuit_id),
                ('varlenH', encode_address(*self.dest_address)),
                ('varlenH', encode_address(*self.org_address)),
                ('raw', self.data)]

    @classmethod
    def from_unpack_list(cls, circuit_id, dest_address, org_address, data):
        return DataPayload(circuit_id, decode_address(dest_address), decode_address(org_address), data)


class CellPayload(Payload):

    format_list = ['I', 'B', 'raw']

    def __init__(self, circuit_id, message_type, message=""):
        super(CellPayload, self).__init__()
        self.circuit_id = circuit_id
        self.message_type = message_type
        self.message = message

    @property
    def is_data(self):
        return self.message_type == 0

    @property
    def is_encrypted_message_type(self):
        return self.message_type not in NO_CRYPTO_PACKETS

    def encrypt(self, crypto, circuit=None, relay_session_keys=None):
        if not self.is_encrypted_message_type:
            return

        if circuit:
            if self.is_data and circuit.ctype in [CIRCUIT_TYPE_RENDEZVOUS, CIRCUIT_TYPE_RP]:
                direction = int(circuit.ctype == CIRCUIT_TYPE_RP)
                self.message = crypto.encrypt_str(self.message,
                                                  *crypto.get_session_keys(circuit.hs_session_keys, direction))

            for hop in reversed(circuit.hops):
                self.message = crypto.encrypt_str(self.message, *crypto.get_session_keys(hop.session_keys, EXIT_NODE))

        elif relay_session_keys:
            self.message = crypto.encrypt_str(self.message, *crypto.get_session_keys(relay_session_keys, ORIGINATOR))

        else:
            raise CryptoException("Error encrypting message for unknown circuit %d" % self.circuit_id)

    def decrypt(self, crypto, circuit=None, relay_session_keys=None):
        if not self.is_encrypted_message_type:
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
                                          "for message: %r received for circuit_id: %s, is_data: %i, circuit_hops: %r" %
                                          (e, layer, self.message, self.circuit_id, self.is_data, circuit.hops))

            if self.is_data and circuit.ctype in [CIRCUIT_TYPE_RENDEZVOUS, CIRCUIT_TYPE_RP]:
                direction = int(circuit.ctype == CIRCUIT_TYPE_RENDEZVOUS)
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
                                      "%r received for circuit_id: %s, is_data: %i, " %
                                      (e, self.message, self.circuit_id, self.is_data))

        else:
            raise CryptoException("Error decrypting message for unknown circuit %d" % self.circuit_id)

    def unwrap(self, prefix):
        return prefix + default_serializer.pack_multiple([('B', self.message_type),
                                                          ('I', self.circuit_id),
                                                          ('raw', self.message)])[0]

    def to_pack_list(self):
        return [('I', self.circuit_id),
                ('B', self.message_type),
                ('raw', self.message)]

    @classmethod
    def from_unpack_list(cls, circuit_id, message_type, message):
        return CellPayload(circuit_id, message_type, message)


class CreatePayload(Payload):

    format_list = ['I', 'H', 'H', 'raw']

    def __init__(self, circuit_id, node_public_key, key):
        super(CreatePayload, self).__init__()
        self.circuit_id = circuit_id
        self.node_public_key = node_public_key
        self.key = key

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', len(self.node_public_key)),
                ('H', len(self.key)),
                ('raw', self.node_public_key + self.key)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, pubkey_len, key_len, pubkey_key):
        node_public_key = pubkey_key[:pubkey_len]
        key = pubkey_key[-key_len:]
        return CreatePayload(circuit_id, node_public_key, key)


class CreatedPayload(Payload):

    format_list = ['I', 'H', '32s', 'raw']

    def __init__(self, circuit_id, key, auth, candidate_list):
        super(CreatedPayload, self).__init__()
        self.circuit_id = circuit_id
        self.key = key
        self.auth = auth
        self.candidate_list = candidate_list

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', len(self.key)),
                ('32s', self.auth),
                ('raw', self.key + self.candidate_list)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, key_len, auth, key_clist):
        key = key_clist[:key_len]
        candidate_list = key_clist[key_len:]
        return CreatedPayload(circuit_id, key, auth, candidate_list)


class ExtendPayload(Payload):

    format_list = ['I', 'H', 'H', 'raw']

    def __init__(self, circuit_id, node_public_key, node_addr, key):
        super(ExtendPayload, self).__init__()
        self.circuit_id = circuit_id
        self.node_public_key = node_public_key
        self.node_addr = node_addr
        self.key = key

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', len(self.node_public_key)),
                ('H', len(self.key)),
                ('raw', self.node_public_key + self.key)]

        if self.node_addr:
            host, port = self.node_addr
            if not isinstance(host, str):
                host = cast_to_chr(host)
            data.append(('4SH', socket.inet_aton(host), port))

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, pubkey_len, key_len, pubkey_key_node_addr):
        node_public_key = pubkey_key_node_addr[:pubkey_len]
        key = pubkey_key_node_addr[pubkey_len:pubkey_len+key_len]
        node_addr = None
        if pubkey_len+key_len < len(pubkey_key_node_addr):
            host, port = unpack_from('>4sH', pubkey_key_node_addr, pubkey_len+key_len)
            node_addr = (socket.inet_ntoa(host), port)
        return ExtendPayload(circuit_id, node_public_key, node_addr, key)


class ExtendedPayload(Payload):

    format_list = ['I', 'H', '32s', 'raw']

    def __init__(self, circuit_id, key, auth, candidate_list):
        super(ExtendedPayload, self).__init__()
        self.circuit_id = circuit_id
        self.key = key
        self.auth = auth
        self.candidate_list = candidate_list

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', len(self.key)),
                ('32s', self.auth),
                ('raw', self.key + self.candidate_list)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, key_len, auth, key_clist):
        key = key_clist[:key_len]
        candidate_list = key_clist[key_len:]
        return ExtendedPayload(circuit_id, key, auth, candidate_list)


class PingPayload(Payload):

    format_list = ['I', 'H']

    def __init__(self, circuit_id, identifier):
        super(PingPayload, self).__init__()
        self.circuit_id = circuit_id
        self.identifier = identifier

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier):
        return PingPayload(circuit_id, identifier)


class PongPayload(PingPayload):
    pass


class DestroyPayload(Payload):

    format_list = ['I', 'H']

    def __init__(self, circuit_id, reason):
        super(DestroyPayload, self).__init__()
        self.circuit_id = circuit_id
        self.reason = reason

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.reason)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, reason):
        return DestroyPayload(circuit_id, reason)


class EstablishIntroPayload(Payload):

    format_list = ['I', 'H', '20s']

    def __init__(self, circuit_id, identifier, info_hash):
        super(EstablishIntroPayload, self).__init__()
        self.circuit_id = circuit_id
        self.identifier = identifier
        self.info_hash = info_hash

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier),
                ('20s', self.info_hash)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier, info_hash):
        return EstablishIntroPayload(circuit_id, identifier, info_hash)


class IntroEstablishedPayload(Payload):

    format_list = ['I', 'H']

    def __init__(self, circuit_id, identifier):
        super(IntroEstablishedPayload, self).__init__()
        self.circuit_id = circuit_id
        self.identifier = identifier

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier):
        return IntroEstablishedPayload(circuit_id, identifier)


class EstablishRendezvousPayload(Payload):

    format_list = ['I', 'H', '20s']

    def __init__(self, circuit_id, identifier, cookie):
        super(EstablishRendezvousPayload, self).__init__()
        self.circuit_id = circuit_id
        self.identifier = identifier
        self.cookie = cookie

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier),
                ('20s', self.cookie)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier, cookie):
        return EstablishRendezvousPayload(circuit_id, identifier, cookie)


class RendezvousEstablishedPayload(Payload):

    format_list = ['I', 'H', '4SH']

    def __init__(self, circuit_id, identifier, rendezvous_point_addr):
        super(RendezvousEstablishedPayload, self).__init__()
        self.circuit_id = circuit_id
        self.identifier = identifier
        self.rendezvous_point_addr = rendezvous_point_addr

    def to_pack_list(self):
        host, port = self.rendezvous_point_addr
        data = [('I', self.circuit_id),
                ('H', self.identifier),
                ('4SH', socket.inet_aton(host), port)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier, address):
        rendezvous_point_addr = (socket.inet_ntoa(address[0]), address[1])
        return RendezvousEstablishedPayload(circuit_id, identifier, rendezvous_point_addr)


class KeyRequestPayload(Payload):

    format_list = ['H', '20s']

    def __init__(self, identifier, info_hash):
        super(KeyRequestPayload, self).__init__()
        self.identifier = identifier
        self.info_hash = info_hash

    def to_pack_list(self):
        data = [('H', self.identifier),
                ('20s', self.info_hash)]

        return data

    @classmethod
    def from_unpack_list(cls, identifier, info_hash):
        return KeyRequestPayload(identifier, info_hash)


class KeyResponsePayload(Payload):

    format_list = ['H', 'varlenH', 'raw']

    def __init__(self, identifier, public_key, pex_peers):
        super(KeyResponsePayload, self).__init__()
        self.identifier = identifier
        self.public_key = public_key
        self.pex_peers = pex_peers

    def to_pack_list(self):
        data = [('H', self.identifier),
                ('varlenH', self.public_key),
                ('raw', self.pex_peers)]

        return data

    @classmethod
    def from_unpack_list(cls, identifier, public_key, pex_peers):
        return KeyResponsePayload(identifier, public_key, pex_peers)


class CreateE2EPayload(Payload):

    format_list = ['H', '20s', 'H', 'H', 'raw']

    def __init__(self, identifier, info_hash, node_public_key, key):
        super(CreateE2EPayload, self).__init__()
        self.identifier = identifier
        self.info_hash = info_hash
        self.node_public_key = node_public_key
        self.key = key

    def to_pack_list(self):
        data = [('H', self.identifier),
                ('20s', self.info_hash),
                ('H', len(self.node_public_key)),
                ('H', len(self.key)),
                ('raw', self.node_public_key + self.key)]

        return data

    @classmethod
    def from_unpack_list(cls, identifier, info_hash, pubkey_len, key_len, pubkey_key):
        node_public_key = pubkey_key[:pubkey_len]
        key = pubkey_key[pubkey_len:]
        return CreateE2EPayload(identifier, info_hash, node_public_key, key)


class CreatedE2EPayload(Payload):

    format_list = ['H', 'H', '32s', 'raw']

    def __init__(self, identifier, key, auth, rp_sock_addr):
        super(CreatedE2EPayload, self).__init__()
        self.identifier = identifier
        self.key = key
        self.auth = auth
        self.rp_sock_addr = rp_sock_addr

    def to_pack_list(self):
        data = [('H', self.identifier),
                ('H', len(self.key)),
                ('32s', self.auth),
                ('raw', self.key + self.rp_sock_addr)]

        return data

    @classmethod
    def from_unpack_list(cls, identifier, key_len, auth, key_rpsockaddr):
        key = key_rpsockaddr[:key_len]
        rp_sock_addr = key_rpsockaddr[key_len:]
        return CreatedE2EPayload(identifier, key, auth, rp_sock_addr)


class DHTRequestPayload(Payload):

    format_list = ['I', 'H', '20s']

    def __init__(self, circuit_id, identifier, info_hash):
        super(DHTRequestPayload, self).__init__()
        self.circuit_id = circuit_id
        self.identifier = identifier
        self.info_hash = info_hash

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier),
                ('20s', self.info_hash)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier, info_hash):
        return DHTRequestPayload(circuit_id, identifier, info_hash)


class DHTResponsePayload(Payload):

    format_list = ['I', 'H', '20s', 'raw']

    def __init__(self, circuit_id, identifier, info_hash, peers):
        super(DHTResponsePayload, self).__init__()
        self.circuit_id = circuit_id
        self.identifier = identifier
        self.info_hash = info_hash
        self.peers = peers

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier),
                ('20s', self.info_hash),
                ('raw', self.peers)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier, info_hash, peers):
        return DHTResponsePayload(circuit_id, identifier, info_hash, peers)


class LinkE2EPayload(Payload):

    format_list = ['I', 'H', '20s']

    def __init__(self, circuit_id, identifier, cookie):
        super(LinkE2EPayload, self).__init__()
        self.circuit_id = circuit_id
        self.identifier = identifier
        self.cookie = cookie

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier),
                ('20s', self.cookie)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier, cookie):
        return LinkE2EPayload(circuit_id, identifier, cookie)


class LinkedE2EPayload(Payload):

    format_list = ['I', 'H']

    def __init__(self, circuit_id, identifier):
        super(LinkedE2EPayload, self).__init__()
        self.circuit_id = circuit_id
        self.identifier = identifier

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier):
        return LinkedE2EPayload(circuit_id, identifier)
