from socket import inet_ntoa, inet_aton
from messaging.serialization import Serializable
from peer import Peer
import struct
from .bloomfilter import BloomFilter


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


class PermissionTripletPayload(Payload):

    format_list = ['varlenH', 'varlenBx2']
    is_list_descriptor = True

    def __init__(self, permission_triplets):
        """
        Authorize the given permission_triplets.

        The permissions are given in the permission_triplets list.  Each element is a (Member,
        Message, permission) pair, where permission can either be u"permit", u"authorize", or
        u"revoke".
        """
        super(PermissionTripletPayload, self).__init__()
        self._permission_triplets = permission_triplets

    def to_pack_list(self):
        permission_map = {u"permit": int("0001", 2), u"authorize": int("0010", 2), u"revoke": int("0100", 2),
                          u"undo": int("1000", 2)}
        members = {}
        for peer, message, permission in self.permission_triplets:
            public_key = peer.key
            message_id = message.byte
            permission_bit = permission_map[permission]

            if not public_key in members:
                members[public_key] = {}

            if not message_id in members[public_key]:
                members[public_key][message_id] = 0

            members[public_key][message_id] |= permission_bit

        data = []
        for public_key, messages in members.iteritems():
            data.append(('varlenH', public_key))
            permissions = ['varlenBx2']
            for message_id, permission_bits in messages.iteritems():
                permissions.extend([message_id, chr(permission_bits)])

            data.append(tuple(permissions))

        return data

    @classmethod
    def from_unpack_list(cls, list):
        permission_map = {u"permit": int("0001", 2), u"authorize": int("0010", 2), u"revoke": int("0100", 2),
                          u"undo": int("1000", 2)}
        permission_triples = []

        for public_key, permission_tuples in list:
            peer = Peer(public_key)
            for i in range(0, len(permission_tuples), 2):
                message_byte = permission_tuples[i]
                permission_bits = ord(permission_tuples[i + 1])
                for permission in permission_map:
                    if permission_map[permission] & permission_bits:
                        permission_triples.append((peer, message_byte, permission))

        return cls(permission_triples)

    @property
    def permission_triplets(self):
        return self._permission_triplets


class AuthorizePayload(PermissionTripletPayload):
    """
    Authorize the given permission_triplets.

    The permissions are given in the permission_triplets list.  Each element is a (Member,
    Message, permission) pair, where permission can either be u"permit", u"authorize", or
    u"revoke".
    """
    pass


class RevokePayload(PermissionTripletPayload):
    """
    Revoke the given permission_triplets.

    The permissions are given in the permission_triplets list.  Each element is a (Member,
    Message, permission) pair, where permission can either be u"permit", u"authorize", or
    u"revoke".
    """
    pass


class UndoPayload(Payload):

    def __init__(self, peer=None, global_time=None, packet=None):
        super(UndoPayload, self).__init__()
        self._member = peer
        self._global_time = global_time
        self._packet = packet
        self._process_undo = True

    @property
    def process_undo(self):
        return self._process_undo

    @process_undo.setter
    def process_undo(self, enabled=True):
        self._process_undo = enabled

    @property
    def member(self):
        return self._member

    @property
    def global_time(self):
        return self._global_time

    @property
    def packet(self):
        return self._packet

    @packet.setter
    def packet(self, packet):
        self._packet = packet


class UndoOtherPayload(UndoPayload):

    format_list = ['varlenH', 'Q']

    def to_pack_list(self):
        data = [('varlenH', self.member.public_key),
                ('Q', self.global_time)]

        return data

    @classmethod
    def from_unpack_list(cls, public_key, global_time):
        return UndoOtherPayload(peer=Peer(public_key), global_time=global_time)


class UndoOwnPayload(UndoPayload):

    format_list = ['Q']

    def to_pack_list(self):
        data = [('Q', self.global_time)]

        return data

    @classmethod
    def from_unpack_list(cls, global_time):
        return UndoOwnPayload(global_time=global_time)


class MissingSequencePayload(Payload):

    format_list = ['B', 'B', 'LL']

    def __init__(self, peer_hash, message_byte, missing_low, missing_high):
        """
        We are missing messages of type MESSAGE signed by USER.  We
        are missing sequence numbers >= missing_low to <=
        missing_high.
        """
        super(MissingSequencePayload, self).__init__()
        self._member = peer_hash
        self._message = message_byte
        self._missing_low = missing_low
        self._missing_high = missing_high

    def to_pack_list(self):
        data = [('B', self.member),
                ('B', self.message),
                ('LL', self._missing_low, self._missing_high)]

        return data

    @classmethod
    def from_unpack_list(cls, mid, message_byte, missing_low, missing_high):
        return MissingSequencePayload(mid, message_byte, missing_low, missing_high)

    @property
    def member(self):
        return self._member

    @property
    def message(self):
        return self._message

    @property
    def missing_low(self):
        return self._missing_low

    @property
    def missing_high(self):
        return self._missing_high


class SignaturePayload(Payload):

    format_list = ['H', 'raw']

    def __init__(self, identifier, message):
        super(SignaturePayload, self).__init__()
        self._identifier = identifier
        self._message = message

    def to_pack_list(self):
        data = [('H', self._identifier),
                ('raw', self.message)]

        return data

    @classmethod
    def from_unpack_list(cls, identifier, message):
        return cls(identifier, message)

    @property
    def identifier(self):
        return self._identifier

    @property
    def message(self):
        return self._message


class SignatureRequestPayload(SignaturePayload):
    pass


class SignatureResponsePayload(SignaturePayload):
    pass


class IdentityPayload(Payload):
    pass


class MissingIdentityPayload(Payload):

    format_list = ['20s']

    def __init__(self, mid):
        super(MissingIdentityPayload, self).__init__()
        self._mid = mid

    def to_pack_list(self):
        data = [('20s', self._mid)]

        return data

    @classmethod
    def from_unpack_list(cls, mid):
        return MissingIdentityPayload(mid)

    @property
    def mid(self):
        return self._mid


class DestroyCommunityPayload(Payload):

    format_list = ['B']

    def __init__(self, degree):
        super(DestroyCommunityPayload, self).__init__()
        self._degree = degree

    def to_pack_list(self):
        data = [('B', ord('s') if self.is_soft_kill else ord('h'))]

        return data

    @classmethod
    def from_unpack_list(cls, degree):
        return DestroyCommunityPayload(u"soft-kill" if degree == 's' else u"hard-kill")

    @property
    def degree(self):
        return self._degree

    @property
    def is_soft_kill(self):
        return self._degree == u"soft-kill"

    @property
    def is_hard_kill(self):
        return self._degree == u"hard-kill"


class MissingMessagePayload(Payload):

    format_list = ['varlenH', 'raw']

    def __init__(self, member, global_times):
        super(MissingMessagePayload, self).__init__()
        self._member = member
        self._global_times = global_times

    def to_pack_list(self):
        data = [('varlenH', self.member.public_key),
                ('raw', ''.join([struct.pack('!Q', global_time) for global_time in self.global_times]))]

        return data

    @classmethod
    def from_unpack_list(cls, public_key, global_times):
        peer = Peer(public_key)
        global_time_list = []
        for i in range(0, len(global_times), 8):
            global_time_list.append(struct.unpack_from('!Q', global_times, i))
        return MissingMessagePayload(peer, global_time_list)

    @property
    def member(self):
        return self._member

    @property
    def global_times(self):
        return self._global_times


class MissingProofPayload(Payload):

    format_list = ['Q', 'varlenH']

    def __init__(self, member, global_time):
        super(MissingProofPayload, self).__init__()
        self._member = member
        self._global_time = global_time

    def to_pack_list(self):
        data = [('Q', self._global_time),
                ('varlenH', self._member.public_key)]

        return data

    @classmethod
    def from_unpack_list(cls, global_time, public_key):
        peer = Peer(public_key)
        return MissingProofPayload(peer, global_time)

    @property
    def member(self):
        return self._member

    @property
    def global_time(self):
        return self._global_time


class DynamicSettingsPayload(Payload):

    format_list = ['ccB']
    is_list_descriptor = True

    def __init__(self, policies):
        """
        Create a new payload container for a dispersy-dynamic-settings message.

        This message allows the community to start using different policies for one or more of
        its messages.  Currently only the resolution policy can be dynamically changed.

        The POLICIES is a list containing (meta_message, policy) tuples.  The policy that is
        choosen must be one of the policies defined for the associated meta_message.

        @param policies: A list with the new message policies.
        @type *policies: [(meta_message, policy), ...]
        """
        super(DynamicSettingsPayload, self).__init__()
        self._policies = policies

    def to_pack_list(self):
        data = []
        for message_byte, policy_index in self._policies:
            data.append(('ccB', message_byte, 'r', policy_index))

        return data

    @classmethod
    def from_unpack_list(cls, list):
        policies = []
        for message_byte, policy_type, policy_index in list:
            policies.append(message_byte, policy_index)
        return MissingProofPayload(policies)

    @property
    def policies(self):
        """
        Returns a list or tuple containing the new message policies.
        @rtype: [(meta_message, policy), ...]
        """
        return self._policies
