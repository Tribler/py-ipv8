from socket import inet_ntoa, inet_aton
from struct import pack, unpack
from ...deprecated.payload import decode_connection_type, encode_connection_type, Payload


class SimilarityRequestPayload(Payload):

    format_list = ['H', '4SH', '4SH', 'bits', 'raw']

    def __init__(self, identifier, lan_address, wan_address, connection_type, preference_list):
        super(SimilarityRequestPayload, self).__init__()
        self._identifier = identifier
        self._preference_list = preference_list
        self._lan_address = lan_address
        self._wan_address = wan_address
        self._connection_type = connection_type

    def to_pack_list(self):
        encoded_connection_type = encode_connection_type(self._connection_type)
        data = [('H', self._identifier),
                ('4SH', inet_aton(self._lan_address[0]), self._lan_address[1]),
                ('4SH', inet_aton(self._wan_address[0]), self._wan_address[1]),
                ('bits', encoded_connection_type[0], encoded_connection_type[1], 0, 0, 0, 0, 0, 0),
                ('raw', "".join(self._preference_list))]

        return data

    @classmethod
    def from_unpack_list(cls, identifier, lan_address, wan_address,
                         connection_type_0, connection_type_1, dflag0, dflag1, dflag2, dflag3, dflag4, dflag5,
                         preference_list):
        args = [identifier,
                (inet_ntoa(lan_address[0]), lan_address[1]),
                (inet_ntoa(wan_address[0]), wan_address[1]),
                decode_connection_type(connection_type_0, connection_type_1),
                [preference_list[i:i+20] for i in range(0, len(preference_list), 20)]]

        return SimilarityRequestPayload(*args)

    @property
    def identifier(self):
        return self._identifier

    @property
    def lan_address(self):
        return self._lan_address

    @property
    def wan_address(self):
        return self._wan_address

    @property
    def connection_type(self):
        return self._connection_type

    @property
    def preference_list(self):
        return self._preference_list


class SimilarityResponsePayload(Payload):

    format_list = ['H', 'varlenHx20', 'raw']

    def __init__(self, identifier, preference_list, tb_overlap):
        super(SimilarityResponsePayload, self).__init__()
        self._identifier = identifier
        self._preference_list = preference_list
        self._tb_overlap = tb_overlap

    def to_pack_list(self):
        encoded_tb_overlap = [pack(">20sI", *tb) for tb in self._tb_overlap]
        data = [('H', self._identifier),
                ('varlenHx20', "".join(self._preference_list)),
                ('raw', "".join(encoded_tb_overlap))]

        return data

    @classmethod
    def from_unpack_list(cls, identifier, preference_list, tb_overlap):
        args = [identifier,
                [preference_list[i:i+20] for i in range(0, len(preference_list), 20)],
                [(tb_overlap[i:i+20], unpack(">I", tb_overlap[i+20:i+24])) for i in range(0, len(tb_overlap), 24)]]

        return SimilarityResponsePayload(*args)

    @property
    def identifier(self):
        return self._identifier

    @property
    def preference_list(self):
        return self._preference_list

    @property
    def tb_overlap(self):
        return self._tb_overlap


class PingPayload(Payload):

    format_list = ['H']

    def __init__(self, identifier):
        super(PingPayload, self).__init__()
        self._identifier = identifier

    def to_pack_list(self):
        data = [('H', self._identifier), ]

        return data

    @classmethod
    def from_unpack_list(cls, identifier):
        return PingPayload(identifier)

    @property
    def identifier(self):
        return self._identifier


class PongPayload(PingPayload):
    pass
