from socket import inet_aton, inet_ntoa
from struct import pack, unpack

from ..messaging.payload import IntroductionRequestPayload, Payload, decode_connection_type, encode_connection_type


class SimilarityRequestPayload(Payload):

    format_list = ['H', '4SH', '4SH', 'bits', 'raw']

    def __init__(self, identifier, lan_address, wan_address, connection_type, preference_list):
        super(SimilarityRequestPayload, self).__init__()
        self.identifier = identifier % 65536
        self.preference_list = preference_list
        self.lan_address = lan_address
        self.wan_address = wan_address
        self.connection_type = connection_type

    def to_pack_list(self):
        encoded_connection_type = encode_connection_type(self.connection_type)
        data = [('H', self.identifier),
                ('4SH', inet_aton(self.lan_address[0]), self.lan_address[1]),
                ('4SH', inet_aton(self.wan_address[0]), self.wan_address[1]),
                ('bits', encoded_connection_type[0], encoded_connection_type[1], 0, 0, 0, 0, 0, 0),
                ('raw', b"".join(self.preference_list))]

        return data

    @classmethod
    def from_unpack_list(cls, identifier, lan_address, wan_address,
                         connection_type_0, connection_type_1, dflag0, dflag1, dflag2, dflag3, dflag4, dflag5,
                         preference_list):
        args = [identifier,
                (inet_ntoa(lan_address[0]), lan_address[1]),
                (inet_ntoa(wan_address[0]), wan_address[1]),
                decode_connection_type(connection_type_0, connection_type_1),
                [preference_list[i:i + 20] for i in range(0, len(preference_list), 20)]]

        return SimilarityRequestPayload(*args)


class SimilarityResponsePayload(Payload):

    format_list = ['H', 'varlenHx20', 'raw']

    def __init__(self, identifier, preference_list, tb_overlap):
        super(SimilarityResponsePayload, self).__init__()
        self.identifier = identifier % 65536
        self.preference_list = preference_list
        self.tb_overlap = tb_overlap

    def to_pack_list(self):
        encoded_tb_overlap = [pack(">20sI", *tb) for tb in self.tb_overlap]
        data = [('H', self.identifier),
                ('varlenHx20', b"".join(self.preference_list)),
                ('raw', b"".join(encoded_tb_overlap))]

        return data

    @classmethod
    def from_unpack_list(cls, identifier, preference_list, tb_overlap):
        args = [identifier,
                [preference_list[i:i + 20] for i in range(0, len(preference_list), 20)],
                [(tb_overlap[i:i + 20], unpack(">I", tb_overlap[i + 20:i + 24])[0])
                 for i in range(0, len(tb_overlap), 24)]]

        return SimilarityResponsePayload(*args)


class PingPayload(Payload):

    format_list = ['H']

    def __init__(self, identifier):
        super(PingPayload, self).__init__()
        self.identifier = identifier % 65536

    def to_pack_list(self):
        data = [('H', self.identifier), ]

        return data

    @classmethod
    def from_unpack_list(cls, identifier):
        return PingPayload(identifier)


class PongPayload(PingPayload):
    pass


class DiscoveryIntroductionRequestPayload(IntroductionRequestPayload):

    format_list = ['c20s', '4SH', '4SH', '4SH', 'bits', 'H', 'raw']

    def __init__(self, introduce_to, destination_address, source_lan_address, source_wan_address, advice,
                 connection_type, identifier, extra_bytes):
        super(DiscoveryIntroductionRequestPayload, self).__init__(destination_address, source_lan_address,
                                                                  source_wan_address, advice, connection_type,
                                                                  identifier, extra_bytes)
        self.introduce_to = introduce_to

    def to_pack_list(self):
        data = super(DiscoveryIntroductionRequestPayload, self).to_pack_list()
        data.insert(0, ('c20s', b'Y', self.introduce_to))
        return data

    @classmethod
    def from_unpack_list(cls, introduce_to, destination_address, source_lan_address, source_wan_address,
                         connection_type_0, connection_type_1, dflag0, dflag1, dflag2, tunnel, _, advice,
                         identifier, extra_bytes):
        args = [introduce_to[1:],
                (inet_ntoa(destination_address[0]), destination_address[1]),
                (inet_ntoa(source_lan_address[0]), source_lan_address[1]),
                (inet_ntoa(source_wan_address[0]), source_wan_address[1]),
                [True, False][advice],
                decode_connection_type(connection_type_0, connection_type_1),
                identifier,
                extra_bytes]

        return DiscoveryIntroductionRequestPayload(*args)
