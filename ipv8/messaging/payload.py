from socket import inet_aton, inet_ntoa

from ..messaging.serialization import Serializable


def encode_connection_type(type):
    if type == u"public":
        return (1, 0)
    if type == u"symmetric-NAT":
        return (1, 1)
    return (0, 0)


def decode_connection_type(bit_0, bit_1):
    bits = (bit_0, bit_1)
    if bits == (0, 0):
        return u"unknown"
    if bits == (1, 0):
        return u"public"
    if bits == (1, 1):
        return u"symmetric-NAT"


class Payload(Serializable):

    def __str__(self):
        out = self.__class__.__name__
        for attribute in dir(self):
            if not (attribute.startswith('_') or callable(getattr(self, attribute))) \
                    and attribute not in ['format_list', 'names', 'optional_format_list']:
                out += '\n| %s: %s' % (attribute, repr(getattr(self, attribute)))
        return out


class IntroductionRequestPayload(Payload):

    format_list = ['4SH', '4SH', '4SH', 'bits', 'H', 'raw']

    def __init__(self, destination_address, source_lan_address, source_wan_address, advice, connection_type,
                 identifier, extra_bytes):
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
        creator has.  Currently the following values are supported: u"unknown", u"public", and
        u"symmetric-NAT".

        IDENTIFIER is a number that must be given in the associated introduction-response.  This
        number allows to distinguish between multiple introduction-response messages.

        EXTRA_BYTES is a string that can be used to piggyback extra information.
        """
        super(IntroductionRequestPayload, self).__init__()
        self.destination_address = destination_address
        self.source_lan_address = source_lan_address
        self.source_wan_address = source_wan_address
        self.advice = advice
        self.connection_type = connection_type
        self.identifier = identifier % 65536
        self.extra_bytes = extra_bytes

    def to_pack_list(self):
        encoded_connection_type = encode_connection_type(self.connection_type)
        data = [('4SH', inet_aton(self.destination_address[0]), self.destination_address[1]),
                ('4SH', inet_aton(self.source_lan_address[0]), self.source_lan_address[1]),
                ('4SH', inet_aton(self.source_wan_address[0]), self.source_wan_address[1]),
                ('bits', encoded_connection_type[0], encoded_connection_type[1], 0, 0, 0, 0, 0, self.advice),
                ('H', self.identifier),
                ('raw', self.extra_bytes)]
        return data

    @classmethod
    def from_unpack_list(cls, destination_address, source_lan_address, source_wan_address,
                         connection_type_0, connection_type_1, dflag0, dflag1, dflag2, tunnel, sync, advice,
                         identifier, extra_bytes):
        args = [(inet_ntoa(destination_address[0]), destination_address[1]),
                (inet_ntoa(source_lan_address[0]), source_lan_address[1]),
                (inet_ntoa(source_wan_address[0]), source_wan_address[1]),
                [True, False][advice],
                decode_connection_type(connection_type_0, connection_type_1),
                identifier,
                extra_bytes]

        return IntroductionRequestPayload(*args)


class IntroductionResponsePayload(Payload):

    format_list = ['4SH', '4SH', '4SH', '4SH', '4SH', 'bits', 'H', 'raw']

    def __init__(self, destination_address, source_lan_address, source_wan_address, lan_introduction_address,
                 wan_introduction_address, connection_type, tunnel, identifier, extra_bytes):
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
        creator has.  Currently the following values are supported: u"unknown", u"public", and
        u"symmetric-NAT".

        TUNNEL is a boolean indicating that the connection is tunneled and all messages send to
        the introduced candidate require a ffffffff prefix.

        IDENTIFIER is a number that was given in the associated introduction-request.  This
        number allows to distinguish between multiple introduction-response messages.

        EXTRA_BYTES is a string that can be used to piggyback extra information.

        When the associated request wanted advice the sender will also sent a puncture-request
        message to either the lan_introduction_address or the wan_introduction_address
        (depending on their positions).  The introduced node must sent a puncture message to the
        receiver to punch a hole in its NAT.
        """
        super(IntroductionResponsePayload, self).__init__()
        self.destination_address = destination_address
        self.source_lan_address = source_lan_address
        self.source_wan_address = source_wan_address
        self.lan_introduction_address = lan_introduction_address
        self.wan_introduction_address = wan_introduction_address
        self.connection_type = connection_type
        self.tunnel = tunnel
        self.identifier = identifier % 65536
        self.extra_bytes = extra_bytes

    def to_pack_list(self):
        encoded_connection_type = encode_connection_type(self.connection_type)
        data = [('4SH', inet_aton(self.destination_address[0]), self.destination_address[1]),
                ('4SH', inet_aton(self.source_lan_address[0]), self.source_lan_address[1]),
                ('4SH', inet_aton(self.source_wan_address[0]), self.source_wan_address[1]),
                ('4SH', inet_aton(self.lan_introduction_address[0]), self.lan_introduction_address[1]),
                ('4SH', inet_aton(self.wan_introduction_address[0]), self.wan_introduction_address[1]),
                ('bits', encoded_connection_type[0], encoded_connection_type[1], 0, 0, 0, 0, 0, 0),
                ('H', self.identifier),
                ('raw', self.extra_bytes)]
        return data

    @classmethod
    def from_unpack_list(cls, destination_address, source_lan_address, source_wan_address,
                         introduction_lan_address, introduction_wan_address,
                         connection_type_0, connection_type_1, dflag0, dflag1, dflag2, dflag3, dflag4, dflag5,
                         identifier, extra_bytes):
        args = [(inet_ntoa(destination_address[0]), destination_address[1]),
                (inet_ntoa(source_lan_address[0]), source_lan_address[1]),
                (inet_ntoa(source_wan_address[0]), source_wan_address[1]),
                (inet_ntoa(introduction_lan_address[0]), introduction_lan_address[1]),
                (inet_ntoa(introduction_wan_address[0]), introduction_wan_address[1]),
                decode_connection_type(connection_type_0, connection_type_1),
                False,
                identifier,
                extra_bytes]

        return IntroductionResponsePayload(*args)


class PunctureRequestPayload(Payload):

    format_list = ['4SH', '4SH', 'H']

    def __init__(self, lan_walker_address, wan_walker_address, identifier):
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

        TODO add connection type
        TODO add tunnel bit
        """
        super(PunctureRequestPayload, self).__init__()
        self.lan_walker_address = lan_walker_address
        self.wan_walker_address = wan_walker_address
        self.identifier = identifier % 65536

    def to_pack_list(self):
        data = [('4SH', inet_aton(self.lan_walker_address[0]), self.lan_walker_address[1]),
                ('4SH', inet_aton(self.wan_walker_address[0]), self.wan_walker_address[1]),
                ('H', self.identifier)]

        return data

    @classmethod
    def from_unpack_list(cls, lan_walker_address, wan_walker_address, identifier):
        args = [(inet_ntoa(lan_walker_address[0]), lan_walker_address[1]),
                (inet_ntoa(wan_walker_address[0]), wan_walker_address[1]),
                identifier]

        return PunctureRequestPayload(*args)


class PuncturePayload(Payload):

    format_list = ['4SH', '4SH', 'H']

    def __init__(self, source_lan_address, source_wan_address, identifier):
        """
        Create the payload for a puncture message

        SOURCE_LAN_ADDRESS is the lan address of the sender.  Nodes in the same LAN
        should use this address to communicate.

        SOURCE_WAN_ADDRESS is the wan address of the sender.  Nodes not in the same
        LAN should use this address to communicate.

        IDENTIFIER is a number that was given in the associated introduction-request.  This
        number allows to distinguish between multiple introduction-response messages.
        """
        super(PuncturePayload, self).__init__()
        self.source_lan_address = source_lan_address
        self.source_wan_address = source_wan_address
        self.identifier = identifier % 65536

    def to_pack_list(self):
        data = [('4SH', inet_aton(self.source_lan_address[0]), self.source_lan_address[1]),
                ('4SH', inet_aton(self.source_wan_address[0]), self.source_wan_address[1]),
                ('H', self.identifier)]

        return data

    @classmethod
    def from_unpack_list(cls, lan_walker_address, wan_walker_address, identifier):
        args = [(inet_ntoa(lan_walker_address[0]), lan_walker_address[1]),
                (inet_ntoa(wan_walker_address[0]), wan_walker_address[1]),
                identifier]

        return PuncturePayload(*args)
