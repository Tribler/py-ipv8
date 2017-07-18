from socket import inet_aton, inet_ntoa

from deprecated.payload import Payload, IntroductionRequestPayload, IntroductionResponsePayload


class TunnelIntroductionRequestPayload(IntroductionRequestPayload):

    format_list = ['?', ] + IntroductionRequestPayload.format_list

    def __init__(self, destination_address, source_lan_address, source_wan_address, advice, connection_type,
                 sync, identifier, exitnode = False):
        super(TunnelIntroductionRequestPayload, self).__init__(destination_address,
                                                               source_lan_address, source_wan_address,
                                                               advice, connection_type, sync, identifier)
        self._exitnode = exitnode

    def to_pack_list(self):
        data = super(TunnelIntroductionRequestPayload, self).to_pack_list()
        data.insert(0, ('?', self.exitnode))

        return data

    @classmethod
    def from_unpack_list(cls, exitnode, destination_address, source_lan_address, source_wan_address,
                         connection_type_0, connection_type_1, dflag0, dflag1, dflag2, tunnel, sync, advice,
                         identifier, time_low=None, time_high=None, modulo=None, modulo_offset=None,
                         functions=None, size=None, prefix_bytes=None):
        ir_payload = IntroductionRequestPayload.from_unpack_list(destination_address, source_lan_address,
                                                                 source_wan_address, connection_type_0,
                                                                 connection_type_1, dflag0, dflag1, dflag2, tunnel,
                                                                 sync, advice, identifier, time_low, time_high, modulo,
                                                                 modulo_offset, functions, size, prefix_bytes)

        return TunnelIntroductionRequestPayload(ir_payload.destination_address, ir_payload.source_lan_address,
                                                ir_payload.source_wan_address, ir_payload.advice,
                                                ir_payload.connection_type, ir_payload.sync, ir_payload.identifier,
                                                exitnode)

    @property
    def exitnode(self):
        return self._exitnode


class TunnelIntroductionResponsePayload(IntroductionResponsePayload):

    format_list = ['?', ] + IntroductionResponsePayload.format_list

    def __init__(self, destination_address, source_lan_address, source_wan_address,
                 lan_introduction_address, wan_introduction_address, connection_type,
                 tunnel, identifier, exitnode = False):
        super(TunnelIntroductionResponsePayload, self).__init__(destination_address,
                                                                source_lan_address, source_wan_address,
                                                                lan_introduction_address, wan_introduction_address,
                                                                connection_type, tunnel, identifier)
        self._exitnode = exitnode

    def to_pack_list(self):
        data = super(TunnelIntroductionResponsePayload, self).to_pack_list()
        data.insert(0, ('?', self.exitnode))

        return data

    @classmethod
    def from_unpack_list(cls, exitnode, destination_address, source_lan_address, source_wan_address,
                         introduction_lan_address, introduction_wan_address,
                         connection_type_0, connection_type_1, dflag0, dflag1, dflag2, dflag3, dflag4, dflag5,
                         identifier):
        ir_payload = IntroductionResponsePayload.from_unpack_list(destination_address, source_lan_address,
                                                                  source_wan_address, introduction_lan_address,
                                                                  introduction_wan_address, connection_type_0,
                                                                  connection_type_1, dflag0, dflag1, dflag2, dflag3,
                                                                  dflag4, dflag5, identifier)

        return TunnelIntroductionResponsePayload(ir_payload.destination_address, ir_payload.source_lan_address,
                                                 ir_payload.source_wan_address, ir_payload.lan_introduction_address,
                                                 ir_payload.wan_introduction_address, ir_payload.connection_type,
                                                 False, ir_payload.identifier, exitnode)

    @property
    def exitnode(self):
        return self._exitnode


class CellPayload(Payload):

    format_list = ['I', 'B', 'raw']

    def __init__(self, circuit_id, message_type, encrypted_message=""):
        super(CellPayload, self).__init__()
        self._circuit_id = circuit_id
        self._message_type = message_type
        self._encrypted_message = encrypted_message

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('B', self._message_type),
                ('raw', self.encrypted_message)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, message_type, encrypted_message):
        return CellPayload(circuit_id, message_type, encrypted_message)

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def message_type(self):
        return self._message_type

    @property
    def encrypted_message(self):
        return self._encrypted_message


class CreatePayload(Payload):

    format_list = ['I', 'H', 'H', '20s', 'raw']

    def __init__(self, circuit_id, node_id, node_public_key, key):
        super(CreatePayload, self).__init__()
        self._circuit_id = circuit_id
        self._node_id = node_id
        self._node_public_key = node_public_key
        self._key = key

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', len(self.node_public_key)),
                ('H', len(self.key)),
                ('20s', self.node_id),
                ('raw', self.node_public_key + self.key)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, pubkey_len, key_len, node_id, pubkey_key):
        node_public_key = pubkey_key[:pubkey_len]
        key = pubkey_key[-key_len:]
        return CreatePayload(circuit_id, node_id, node_public_key, key)

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def node_id(self):
        return self._node_id

    @property
    def node_public_key(self):
        return self._node_public_key

    @property
    def key(self):
        return self._key


class CreatedPayload(Payload):

    format_list = ['I', 'H', '32s', 'raw']

    def __init__(self, circuit_id, key, auth, candidate_list):
        super(CreatedPayload, self).__init__()
        self._circuit_id = circuit_id
        self._key = key
        self._auth = auth
        self._candidate_list = candidate_list

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

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def key(self):
        return self._key

    @property
    def auth(self):
        return self._auth

    @property
    def candidate_list(self):
        return self._candidate_list


class ExtendPayload(Payload):

    format_list = ['I', 'H', 'H', '20s', 'raw']
    optional_format_list = ['4sH']

    def __init__(self, circuit_id, node_id, node_public_key, node_addr, key):
        super(ExtendPayload, self).__init__()
        self._circuit_id = circuit_id
        self._node_id = node_id
        self._node_public_key = node_public_key
        self._node_addr = node_addr
        self._key = key

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', len(self.node_public_key)),
                ('H', len(self.key)),
                ('20s', self.node_id),
                ('raw', self.node_public_key + self.key)]

        if self.node_addr:
            host, port = self.node_addr
            data.append(('4sH', inet_aton(host), port))

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, pubkey_len, key_len, node_id, pubkey_key, node_addr=None):
        node_public_key = pubkey_key[:pubkey_len]
        key = pubkey_key[pubkey_len:pubkey_len+key_len]
        return ExtendPayload(circuit_id, node_id, node_public_key, node_addr, key)

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def node_id(self):
        return self._node_id

    @property
    def node_public_key(self):
        return self._node_public_key

    @property
    def node_addr(self):
        return self._node_addr

    @property
    def key(self):
        return self._key


class ExtendedPayload(Payload):

    format_list = ['I', 'H', '32s', 'raw']

    def __init__(self, circuit_id, key, auth, candidate_list):
        super(ExtendedPayload, self).__init__()
        self._circuit_id = circuit_id
        self._key = key
        self._auth = auth
        self._candidate_list = candidate_list

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

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def key(self):
        return self._key

    @property
    def auth(self):
        return self._auth

    @property
    def candidate_list(self):
        return self._candidate_list


class PingPayload(Payload):

    format_list = ['I', 'H']

    def __init__(self, circuit_id, identifier):
        super(PingPayload, self).__init__()
        self._circuit_id = circuit_id
        self._identifier = identifier

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier):
        return PingPayload(circuit_id, identifier)

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def identifier(self):
        return self._identifier


class PongPayload(PingPayload):
    pass


class DestroyPayload(Payload):

    format_list = ['I', 'H']

    def __init__(self, circuit_id, reason):
        super(DestroyPayload, self).__init__()
        self._circuit_id = circuit_id
        self._reason = reason

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.reason)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, reason):
        return DestroyPayload(circuit_id, reason)

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def reason(self):
        return self._reason


class StatsRequestPayload(Payload):

    format_list = ['H']

    def __init__(self, identifier):
        super(StatsRequestPayload, self).__init__()
        self._identifier = identifier

    def to_pack_list(self):
        data = [('H', self.identifier), ]

        return data

    @classmethod
    def from_unpack_list(cls, identifier):
        return StatsRequestPayload(identifier)

    @property
    def identifier(self):
        return self._identifier


class StatsResponsePayload(Payload):

    format_list = ['H', 'I', 'Q', 'Q', 'Q', 'Q', 'Q', 'Q']

    def __init__(self, identifier, stats):
        super(StatsResponsePayload, self).__init__()
        self._identifier = identifier
        self._stats = stats

    def to_pack_list(self):
        data = [('H', self.identifier),
                ('I', self.stats.get('uptime', 0)),
                ('Q', self.stats.get('bytes_up', 0)),
                ('Q', self.stats.get('bytes_down', 0)),
                ('Q', self.stats.get('bytes_relay_up', 0)),
                ('Q', self.stats.get('bytes_relay_down', 0)),
                ('Q', self.stats.get('bytes_enter', 0)),
                ('Q', self.stats.get('bytes_exit', 0))]

        return data

    @classmethod
    def from_unpack_list(cls, identifier, uptime, bytes_up, bytes_down, bytes_relay_up, bytes_relay_down,
                         bytes_enter, bytes_exit):
        stats = {
            'uptime': uptime,
            'bytes_up': bytes_up,
            'bytes_down': bytes_down,
            'bytes_relay_up': bytes_relay_up,
            'bytes_relay_down': bytes_relay_down,
            'bytes_enter': bytes_enter,
            'bytes_exit': bytes_exit
        }
        return StatsResponsePayload(identifier, stats)

    @property
    def identifier(self):
        return self._identifier

    @property
    def stats(self):
        return self._stats


class EstablishIntroPayload(Payload):

    format_list = ['I', 'H', '20s']

    def __init__(self, circuit_id, identifier, info_hash):
        super(EstablishIntroPayload, self).__init__()
        self._circuit_id = circuit_id
        self._identifier = identifier
        self._info_hash = info_hash

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier),
                ('20s', self.info_hash)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier, info_hash):
        return EstablishIntroPayload(circuit_id, identifier, info_hash)

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def identifier(self):
        return self._identifier

    @property
    def info_hash(self):
        return self._info_hash


class IntroEstablishedPayload(Payload):

    format_list = ['I', 'H']

    def __init__(self, meta, circuit_id, identifier):
        super(IntroEstablishedPayload, self).__init__()
        self._circuit_id = circuit_id
        self._identifier = identifier

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier):
        return IntroEstablishedPayload(circuit_id, identifier)

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def identifier(self):
        return self._identifier


class EstablishRendezvousPayload(Payload):

    format_list = ['I', 'H', '20s']

    def __init__(self, circuit_id, identifier, cookie):
        super(EstablishRendezvousPayload, self).__init__()
        self._circuit_id = circuit_id
        self._identifier = identifier
        self._cookie = cookie

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier),
                ('20s', self.cookie)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier, cookie):
        return EstablishRendezvousPayload(circuit_id, identifier, cookie)

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def identifier(self):
        return self._identifier

    @property
    def cookie(self):
        return self._cookie


class RendezvousEstablishedPayload(Payload):

    format_list = ['I', 'H', '4sH']

    def __init__(self, circuit_id, identifier, rendezvous_point_addr):
        super(RendezvousEstablishedPayload, self).__init__()
        self._circuit_id = circuit_id
        self._identifier = identifier
        self._rendezvous_point_addr = rendezvous_point_addr

    def to_pack_list(self):
        host, port = self.rendezvous_point_addr
        data = [('I', self.circuit_id),
                ('H', self.identifier),
                ('4sH', inet_aton(host), port)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier, address):
        rendezvous_point_addr = (inet_ntoa(address[0]), address[1])
        return RendezvousEstablishedPayload(circuit_id, identifier, rendezvous_point_addr)

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def identifier(self):
        return self._identifier

    @property
    def rendezvous_point_addr(self):
        return self._rendezvous_point_addr


class KeyRequestPayload(Payload):

    format_list = ['H', '20s']

    def __init__(self, identifier, info_hash):
        super(KeyRequestPayload, self).__init__()
        self._identifier = identifier
        self._info_hash = info_hash

    def to_pack_list(self):
        data = [('H', self.identifier),
                ('20s', self.info_hash)]

        return data

    @classmethod
    def from_unpack_list(cls, identifier, info_hash):
        return KeyRequestPayload(identifier, info_hash)

    @property
    def identifier(self):
        return self._identifier

    @property
    def info_hash(self):
        return self._info_hash


class KeyResponsePayload(Payload):

    format_list = ['H', 'varlenH', 'raw']

    def __init__(self, identifier, public_key, pex_peers):
        super(KeyResponsePayload, self).__init__()
        self._identifier = identifier
        self._public_key = public_key
        self._pex_peers = pex_peers

    def to_pack_list(self):
        data = [('H', self.identifier),
                ('varlenH', self.public_key),
                ('raw', self.pex_peers)]

        return data

    @classmethod
    def from_unpack_list(cls, identifier, public_key, pex_peers):
        return KeyResponsePayload(identifier, public_key, pex_peers)

    @property
    def identifier(self):
        return self._identifier

    @property
    def public_key(self):
        return self._public_key

    @property
    def pex_peers(self):
        return self._pex_peers


class CreateE2EPayload(Payload):

    format_list = ['H', '20s', 'H', 'H', '20s', 'raw']

    def __init__(self, identifier, info_hash, node_id, node_public_key, key):
        super(CreateE2EPayload, self).__init__()
        self._identifier = identifier
        self._info_hash = info_hash
        self._node_id = node_id
        self._node_public_key = node_public_key
        self._key = key

    def to_pack_list(self):
        data = [('H', self.identifier),
                ('20s', self.info_hash),
                ('H', len(self.node_public_key)),
                ('H', len(self.key)),
                ('20s', self.node_id),
                ('raw', self.node_public_key + self.key)]

        return data

    @classmethod
    def from_unpack_list(cls, identifier, info_hash, pubkey_len, key_len, node_id, pubkey_key):
        node_public_key = pubkey_key[:pubkey_len]
        key = pubkey_key[pubkey_len:]
        return CreateE2EPayload(identifier, info_hash, node_id, node_public_key, key)

    @property
    def identifier(self):
        return self._identifier

    @property
    def info_hash(self):
        return self._info_hash

    @property
    def node_id(self):
        return self._node_id

    @property
    def node_public_key(self):
        return self._node_public_key

    @property
    def key(self):
        return self._key


class CreatedE2EPayload(Payload):

    format_list = ['H', 'H', '32s', 'raw']

    def __init__(self, identifier, key, auth, rp_sock_addr):
        super(CreatedE2EPayload, self).__init__()
        self._identifier = identifier
        self._key = key
        self._auth = auth
        self._rp_sock_addr = rp_sock_addr

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

    @property
    def identifier(self):
        return self._identifier

    @property
    def key(self):
        return self._key

    @property
    def auth(self):
        return self._auth

    @property
    def rp_sock_addr(self):
        return self._rp_sock_addr


class DHTRequestPayload(Payload):

    format_list = ['I', 'H', '20s']

    def __init__(self, circuit_id, identifier, info_hash):
        super(DHTRequestPayload, self).__init__()
        self._circuit_id = circuit_id
        self._identifier = identifier
        self._info_hash = info_hash

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier),
                ('20s', self.info_hash)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier, info_hash):
        return DHTRequestPayload(circuit_id, identifier, info_hash)

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def identifier(self):
        return self._identifier

    @property
    def info_hash(self):
        return self._info_hash


class DHTResponsePayload(Payload):

    format_list = ['I', 'H', '20s', 'raw']

    def __init__(self, circuit_id, identifier, info_hash, peers):
        super(DHTResponsePayload, self).__init__()
        self._circuit_id = circuit_id
        self._identifier = identifier
        self._info_hash = info_hash
        self._peers = peers

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier),
                ('20s', self.info_hash),
                ('raw', self.peers)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier, info_hash, peers):
        return DHTResponsePayload(circuit_id, identifier, info_hash, peers)

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def identifier(self):
        return self._identifier

    @property
    def info_hash(self):
        return self._info_hash

    @property
    def peers(self):
        return self._peers


class LinkE2EPayload(Payload):

    format_list = ['I', 'H', '20s']

    def __init__(self, circuit_id, identifier, cookie):
        super(LinkE2EPayload, self).__init__()
        self._circuit_id = circuit_id
        self._identifier = identifier
        self._cookie = cookie

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier),
                ('20s', self.cookie)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier, cookie):
        return LinkE2EPayload(circuit_id, identifier, cookie)

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def identifier(self):
        return self._identifier

    @property
    def cookie(self):
        return self._cookie


class LinkedE2EPayload(Payload):

    format_list = ['I', 'H']

    def __init__(self, circuit_id, identifier):
        super(LinkedE2EPayload, self).__init__()
        self._circuit_id = circuit_id
        self._identifier = identifier

    def to_pack_list(self):
        data = [('I', self.circuit_id),
                ('H', self.identifier)]

        return data

    @classmethod
    def from_unpack_list(cls, circuit_id, identifier):
        return LinkedE2EPayload(circuit_id, identifier)

    @property
    def circuit_id(self):
        return self._circuit_id

    @property
    def identifier(self):
        return self._identifier
