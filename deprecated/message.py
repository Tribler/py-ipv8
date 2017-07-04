from abc import ABCMeta, abstractmethod, abstractproperty
from time import time


class DelayPacket(Exception):

    """
    Uses an identifier to match request to response.
    """

    __metaclass__ = ABCMeta

    def __init__(self, community, msg):
        super(DelayPacket, self).__init__(msg)
        self._delayed = None
        self._community = community
        self._cid = community.cid
        self._candidate = None
        self._timestamp = time()

    @property
    def delayed(self):
        return self._delayed
    @delayed.setter
    def delayed(self, delayed):
        self._delayed = delayed

    @property
    def candidate(self):
        return self._candidate
    @candidate.setter
    def candidate(self, candidate):
        self._candidate = candidate

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def resume_immediately(self):
        return False

    @abstractproperty
    def match_info(self):
        # return the matchinfo to be used to trigger the resume
        pass

    @abstractmethod
    def send_request(self, community, candidate):
        pass

    def on_success(self):
        return self.candidate, self.delayed

    def on_timeout(self):
        pass


class DelayPacketByMissingMember(DelayPacket):

    def __init__(self, community, missing_member_id):
        super(DelayPacketByMissingMember, self).__init__(community, "Missing member")
        self._missing_member_id = missing_member_id

    @property
    def match_info(self):
        return (self._cid, u"dispersy-identity", self._missing_member_id, None, []),

    def send_request(self, community, candidate):
        return community.create_missing_identity(candidate,
                    community.dispersy.get_member(mid=self._missing_member_id))


class DelayPacketByMissingMessage(DelayPacket):

    def __init__(self, community, member, global_time):
        super(DelayPacketByMissingMessage, self).__init__(community, "Missing message")
        self._member = member
        self._global_time = global_time

    @property
    def match_info(self):
        return (self._cid, None, self._member.mid, self._global_time, []),

    def send_request(self, community, candidate):
        return community.create_missing_message(candidate, self._member, self._global_time)


class DropPacket(Exception):

    """
    Raised by Conversion.decode_message when the packet is invalid.
    I.e. does not conform to valid syntax, contains malicious
    behaviour, etc.
    """
    pass


class DelayMessage(DelayPacket):

    def __init__(self, delayed):
        super(DelayMessage, self).__init__(delayed.community, self.__class__.__name__)
        self._delayed = delayed

    def duplicate(self, delayed):
        """
        Create another instance of the same class with another DELAYED.
        """
        return self.__class__(delayed)

    def on_success(self):
        return self.delayed

class DelayMessageByProof(DelayMessage):

    @property
    def match_info(self):
        return (self._cid, u"dispersy-authorize", None, None, []), (self._cid, u"dispersy-dynamic-settings", None, None, [])

    @property
    def resume_immediately(self):
        return True

    def send_request(self, community, candidate):
        community.create_missing_proof(candidate, self._delayed)


class DelayMessageBySequence(DelayMessage):

    def __init__(self, delayed, missing_low, missing_high):
        super(DelayMessageBySequence, self).__init__(delayed)
        self._missing_low = missing_low
        self._missing_high = missing_high

    def duplicate(self, delayed):
        return self.__class__(delayed, self._missing_low, self._missing_high)

    @property
    def match_info(self):
        return (self._cid, None, self._delayed.authentication.member.mid, None, range(self._missing_low, self._missing_high + 1)),

    def send_request(self, community, candidate):
        community.create_missing_sequence(candidate, self._delayed.authentication.member,
                                          self._delayed.meta, self._missing_low, self._missing_high)


class DelayMessageByMissingMessage(DelayMessage):

    def __init__(self, delayed, member, global_time):
        super(DelayMessageByMissingMessage, self).__init__(delayed)
        self._member = member
        self._global_time = global_time

    def duplicate(self, delayed):
        return self.__class__(delayed, self._member, self._global_time)

    @property
    def match_info(self):
        return (self._cid, None, self._member.mid, self._global_time, []),

    def send_request(self, community, candidate):
        community.create_missing_message(candidate, self._member, self._global_time)


class DropMessage(Exception):

    """
    Raised during Community.on_message.

    Drops a message because it violates 'something'.  More specific
    reasons can be given with by raising a spectific subclass.
    """
    def __init__(self, dropped, msg):
        self._dropped = dropped
        super(DropMessage, self).__init__(msg)

    @property
    def dropped(self):
        return self._dropped

    def duplicate(self, dropped):
        """
        Create another instance of the same class with another DELAYED.
        """
        return self.__class__(dropped, self.message)

    def __str__(self):
        return "".join((super(DropMessage, self).__str__(), " [", self._dropped.name, "]"))


#
# message
#
class Message(object):

    def __init__(self, name, byte, payload, peer, source=u"unknown", database_id=0):
        super(Message, self).__init__()
        self._name = name
        self._byte = byte
        self._database_id = database_id

        self._payload = payload

        self._peer = peer
        self._source = source

        # _RESUME contains the message that caused SELF to be processed after it was delayed
        self._resume = None

    @property
    def byte(self):
        return self._byte

    @property
    def payload(self):
        return self._payload

    @property
    def peer(self):
        return self._peer

    @property
    def source(self):
        return self._source

    @property
    def resume(self):
        return self._resume

    @resume.setter
    def resume(self, message):
        self._resume = message

    @property
    def name(self):
        return self._name

    @property
    def database_id(self):
        return self._database_id

    @property
    def payload(self):
        return self._payload

    def __str__(self):
        return "<%s %s>" % (self.__class__.__name__, self._name)
