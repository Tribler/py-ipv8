from socket import inet_ntoa, inet_aton
import struct

from .bloomfilter import BloomFilter
from ..messaging.serialization import Serializable
from ..peer import Peer


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
                    and attribute not in ['format_list', 'optional_format_list', 'is_list_descriptor']:
                out += '\n| %s: %s' % (attribute, repr(getattr(self, attribute)))
        return out


class IntroductionRequestPayload(Payload):

    format_list = ['4SH', '4SH', '4SH', 'bits', 'H']
    optional_format_list = ['QQHHBH', 'raw']

    def __init__(self, destination_address, source_lan_address, source_wan_address, advice, connection_type,
                 sync, identifier):
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

        SYNC is an optional (TIME_LOW, TIME_HIGH, MODULO, OFFSET, BLOOM_FILTER) tuple.  When
        given the introduction-request will also add this sync bloom filter in the message
        allowing the receiver to respond with missing packets.  No such sync bloom filter will
        be included when SYNC is None.

           TIME_LOW and TIME_HIGH give the global time range that the sync bloomfilter covers.

           Only packets with (global time + OFFSET % MODULO) == 0 will be taken into account,
           allowing for sync ranges to cover much larger ranges without including all the
           packets in that range.

           BLOOM_FILTER is a BloomFilter object containing all packets that the sender has in
           the given sync range.

        IDENTIFIER is a number that must be given in the associated introduction-response.  This
        number allows to distinguish between multiple introduction-response messages.
        """
        super(IntroductionRequestPayload, self).__init__()
        self._destination_address = destination_address
        self._source_lan_address = source_lan_address
        self._source_wan_address = source_wan_address
        self._advice = advice
        self._connection_type = connection_type
        self._identifier = identifier
        if sync:
            self._time_low, self._time_high, self._modulo, self._offset, self._bloom_filter = sync
        else:
            self._time_low, self._time_high, self._modulo, self._offset, self._bloom_filter = 0, 0, 1, 0, None

    def to_pack_list(self):
        encoded_connection_type = encode_connection_type(self._connection_type)
        data = [('4SH', inet_aton(self._destination_address[0]), self._destination_address[1]),
                ('4SH', inet_aton(self._source_lan_address[0]), self._source_lan_address[1]),
                ('4SH', inet_aton(self._source_wan_address[0]), self._source_wan_address[1]),
                ('bits', encoded_connection_type[0], encoded_connection_type[1], 0, 0, 0, 0, self.sync, self._advice),
                ('H', self._identifier)]

        # add optional sync
        if self.sync:
            data.append(('QQHHBH', self._time_low, self._time_high,
                         self._modulo, self._offset,
                         self._bloom_filter.functions,
                         self._bloom_filter.size))
            data.append(('raw', self._bloom_filter.prefix, self._bloom_filter.bytes))

        return data

    @classmethod
    def from_unpack_list(cls, destination_address, source_lan_address, source_wan_address,
                         connection_type_0, connection_type_1, dflag0, dflag1, dflag2, tunnel, sync, advice,
                         identifier, time_low=None, time_high=None, modulo=None, modulo_offset=None,
                         functions=None, size=None, prefix_bytes=None):
        args = [(inet_ntoa(destination_address[0]), destination_address[1]),
                (inet_ntoa(source_lan_address[0]), source_lan_address[1]),
                (inet_ntoa(source_wan_address[0]), source_wan_address[1]),
                [True, False][advice],
                decode_connection_type(connection_type_0, connection_type_1)]

        if sync and prefix_bytes:
            bloomfilter = BloomFilter(prefix_bytes[1:], functions, prefix=prefix_bytes[0])
            args.append((time_low, time_high, modulo, modulo_offset, bloomfilter))
        else:
            args.append(None)

        args.append(identifier)

        return IntroductionRequestPayload(*args)

    @property
    def destination_address(self):
        return self._destination_address

    @property
    def source_lan_address(self):
        return self._source_lan_address

    @property
    def source_wan_address(self):
        return self._source_wan_address

    @property
    def advice(self):
        return self._advice

    @property
    def connection_type(self):
        return self._connection_type

    @property
    def sync(self):
        return True if self._bloom_filter else False

    @property
    def time_low(self):
        return self._time_low

    @property
    def time_high(self):
        return self._time_high

    @property
    def has_time_high(self):
        return self._time_high > 0

    @property
    def modulo(self):
        return self._modulo

    @property
    def offset(self):
        return self._offset

    @property
    def bloom_filter(self):
        return self._bloom_filter

    @property
    def identifier(self):
        return self._identifier


class IntroductionResponsePayload(Payload):

    format_list = ['4SH', '4SH', '4SH', '4SH', '4SH', 'bits', 'H']

    def __init__(self, destination_address, source_lan_address, source_wan_address, lan_introduction_address, wan_introduction_address, connection_type, tunnel, identifier):
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

        When the associated request wanted advice the sender will also sent a puncture-request
        message to either the lan_introduction_address or the wan_introduction_address
        (depending on their positions).  The introduced node must sent a puncture message to the
        receiver to punch a hole in its NAT.
        """
        super(IntroductionResponsePayload, self).__init__()
        self._destination_address = destination_address
        self._source_lan_address = source_lan_address
        self._source_wan_address = source_wan_address
        self._lan_introduction_address = lan_introduction_address
        self._wan_introduction_address = wan_introduction_address
        self._connection_type = connection_type
        self._tunnel = tunnel
        self._identifier = identifier

    def to_pack_list(self):
        encoded_connection_type = encode_connection_type(self._connection_type)
        data = [('4SH', inet_aton(self._destination_address[0]), self._destination_address[1]),
                ('4SH', inet_aton(self._source_lan_address[0]), self._source_lan_address[1]),
                ('4SH', inet_aton(self._source_wan_address[0]), self._source_wan_address[1]),
                ('4SH', inet_aton(self._lan_introduction_address[0]), self._lan_introduction_address[1]),
                ('4SH', inet_aton(self._wan_introduction_address[0]), self._wan_introduction_address[1]),
                ('bits', encoded_connection_type[0], encoded_connection_type[1], 0, 0, 0, 0, 0, 0),
                ('H', self._identifier)]

        return data

    @classmethod
    def from_unpack_list(cls, destination_address, source_lan_address, source_wan_address,
                         introduction_lan_address, introduction_wan_address,
                         connection_type_0, connection_type_1, dflag0, dflag1, dflag2, dflag3, dflag4, dflag5,
                         identifier):
        args = [(inet_ntoa(destination_address[0]), destination_address[1]),
                (inet_ntoa(source_lan_address[0]), source_lan_address[1]),
                (inet_ntoa(source_wan_address[0]), source_wan_address[1]),
                (inet_ntoa(introduction_lan_address[0]), introduction_lan_address[1]),
                (inet_ntoa(introduction_wan_address[0]), introduction_wan_address[1]),
                decode_connection_type(connection_type_0, connection_type_1),
                False,
                identifier]

        return IntroductionResponsePayload(*args)

    @property
    def destination_address(self):
        return self._destination_address

    @property
    def source_lan_address(self):
        return self._source_lan_address

    @property
    def source_wan_address(self):
        return self._source_wan_address

    @property
    def lan_introduction_address(self):
        return self._lan_introduction_address

    @property
    def wan_introduction_address(self):
        return self._wan_introduction_address

    @property
    def connection_type(self):
        return self._connection_type

    @property
    def tunnel(self):
        return self._tunnel

    @property
    def identifier(self):
        return self._identifier


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
        self._lan_walker_address = lan_walker_address
        self._wan_walker_address = wan_walker_address
        self._identifier = identifier

    def to_pack_list(self):
        data = [('4SH', inet_aton(self._lan_walker_address[0]), self._lan_walker_address[1]),
                ('4SH', inet_aton(self._wan_walker_address[0]), self._wan_walker_address[1]),
                ('H', self._identifier)]

        return data

    @classmethod
    def from_unpack_list(cls, lan_walker_address, wan_walker_address, identifier):
        args = [(inet_ntoa(lan_walker_address[0]), lan_walker_address[1]),
                (inet_ntoa(wan_walker_address[0]), wan_walker_address[1]),
                identifier]

        return PunctureRequestPayload(*args)

    @property
    def lan_walker_address(self):
        return self._lan_walker_address

    @property
    def wan_walker_address(self):
        return self._wan_walker_address

    @property
    def identifier(self):
        return self._identifier


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
        self._source_lan_address = source_lan_address
        self._source_wan_address = source_wan_address
        self._identifier = identifier

    def to_pack_list(self):
        data = [('4SH', inet_aton(self._source_lan_address[0]), self._source_lan_address[1]),
                ('4SH', inet_aton(self._source_wan_address[0]), self._source_wan_address[1]),
                ('H', self._identifier)]

        return data

    @classmethod
    def from_unpack_list(cls, lan_walker_address, wan_walker_address, identifier):
        args = [(inet_ntoa(lan_walker_address[0]), lan_walker_address[1]),
                (inet_ntoa(wan_walker_address[0]), wan_walker_address[1]),
                identifier]

        return PuncturePayload(*args)

    @property
    def source_lan_address(self):
        return self._source_lan_address

    @property
    def source_wan_address(self):
        return self._source_wan_address

    @property
    def identifier(self):
        return self._identifier
