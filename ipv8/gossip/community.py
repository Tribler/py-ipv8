from __future__ import absolute_import

from abc import abstractmethod
from binascii import unhexlify
from random import choice, sample
from string import hexdigits

from twisted.internet import reactor
from twisted.internet.base import DelayedCall
from twisted.internet.task import LoopingCall

from ..keyvault.public.libnaclkey import LibNaCLPK
from ..messaging.bloomfilter import BloomFilter
from ..messaging.serialization import PackError, Serializable
from ..overlay import Overlay
from ..peer import Peer

# The time required to gather all the necessary votes for carrying out a vote
VOTE_TIMEOUT = 5

BYTE_HEXDIGITS = [x.encode('utf-8') for x in hexdigits]


class IGossipOverlayListener(object):

    @abstractmethod
    def on_gossip(self, public_key, message):
        """
        Hook method which is called in certain contexts for certain Gossip Messages

        :param public_key: the target_public_key of the message
        :param message: the message itself
        :return: None
        """
        pass


class GossipRule(object):
    SUPPRESS = 0
    DEFAULT = 1
    COLLECT = 2
    SPREAD = 3


class GossipMessage(Serializable):
    format_list = ['64s', '74s', 'B', '74s', 'raw']

    def __init__(self, my_private_key, rule, target_public_key, payload):
        self.public_key = my_private_key.pub().key_to_bin()
        self.payload = payload
        self.rule = rule
        self.target_public_key = target_public_key
        self.signature = my_private_key.signature(
            self.public_key + str(self.rule).encode('utf-8') + self.target_public_key + self.payload)

    def to_pack_list(self):
        return [
            ('64s', self.signature),
            ('74s', self.public_key),
            ('B', self.rule),
            ('74s', self.target_public_key),
            ('raw', self.payload)
        ]

    @classmethod
    def from_unpack_list(cls, signature, public_key, rule, target_public_key, payload):
        key = LibNaCLPK(binarykey=public_key[10:])

        if key.verify(signature, public_key + str(rule).encode('utf-8') + target_public_key + payload):
            out = object.__new__(GossipMessage)
            out.public_key = public_key
            out.signature = signature
            out.payload = payload
            out.rule = rule
            out.target_public_key = target_public_key
            return out
        else:
            raise PackError("Incorrect signature of GossipMessage")


class GossipRuleChangeBallot(object):

    def __init__(self, rule, initial_votes, callback_name, callback, required_majority_param):
        """
        Initializer for GossipRuleChangeBallot.

        :param rule: the GossipRule for which voting is initiated
        :param initial_votes: a set containing the public keys of the peers voting for rule changing
        :param callback_name: the unique identifier of the method being called when the vote fails
        :param callback: a function which is called back when the vote fails. Should have the following signature
                         (target_public_key : str) => None
        :param required_majority_param: the number of votes required for the vote to pass (greater or equal)
        """
        assert isinstance(rule, int) and isinstance(initial_votes, set) and \
            isinstance(callback_name, (str, bytes)) and isinstance(callback, DelayedCall) and \
            isinstance(required_majority_param, int), "Incorrect initialization parameters"

        self._rule = rule
        self._votes = initial_votes
        self._callback_name = callback_name
        self._callback = callback
        self._required_majority = required_majority_param

    @property
    def rule(self):
        return self._rule

    @property
    def callback_name(self):
        return self._callback_name

    @property
    def required_majority(self):
        return self._required_majority

    def add_vote(self, public_key):
        """
        Add a vote to the ballot

        :param public_key: the public key of the peer voting
        :return: None
        """
        self._votes.add(public_key)

    def has_enough_votes(self):
        """
        Checks if there are enough votes for the ballot to pass

        :return: True if there are enough votes, False otherwise
        """
        return len(self._votes) >= self._required_majority

    def cancel_callback(self):
        """
        Cancels the callback function

        :return: None
        """
        self._callback.cancel()

    def reset_callback_timer(self, timeout):
        """
        Reset the timer of the callback to the specified amount

        :param timeout: the timeout period of the callback
        :return: None
        """
        if not self._callback.cancelled:
            self._callback.reset(timeout)


class GossipOverlay(Overlay):
    """
    Interface:
     - listeners: add your callback function here, accepting (public_key : str, message : str)
     - set_rule(public_key : str, rule : GossipRule)
    """

    def get_walkable_addresses(self):
        raise NotImplementedError("One must implement this method before using it")

    master_peer = Peer(unhexlify("3052301006072a8648ce3d020106052b8104001a033e000400d1aaecf1acc0db3aecc0efb07f66f81"
                                 "5d1a4e0804c7aa233bf144ed9cd002e2579265ef30e0a4355460a50f12f5a4a5ad5033095aec4f911"
                                 "1f5376"))

    PREFIX_LENGTH = 22

    def __init__(self, my_peer, endpoint, network, loop_interval=0.5):
        super(GossipOverlay, self).__init__(self.master_peer, my_peer, endpoint, network)

        self.message_db = {}  # Pk: set(messages)
        self.rules_db = {}  # Pk: rule
        self.rule_change_db = {}  # Pk: GossipRuleChangeBallot
        self.listeners = []
        self.prefix = b"\x01\x00GossipCommunity\x00\x00\x00\x00\x00"

        # Avoid conflicts when it comes to naming voting tasks
        self._vote_ballot_names = set()

        # Loops on this, and periodically sends a message based on the rule set it's got
        self.update_list = []
        self.register_task("update_key", LoopingCall(self.take_step)).start(loop_interval)

    def set_rule(self, public_key, rule):
        """
        Sets the gossip rule for a particular peer

        :param public_key: the public key of the peer whose gossip rule needs to be changed
        :param rule: the new gossip rule
        :return: None
        """
        self.rules_db[public_key] = rule

    def take_step(self):
        """
        Trigger the dispatch of a message for a arbitrary peer in our DB

        :return: None
        """
        if not self.update_list:
            self.update_list = list(self.rules_db.keys())
        next_public_key = self.update_list.pop(0) if self.update_list else None
        if next_public_key:
            self.enforce(next_public_key, self.get_rule(next_public_key))

    def enforce(self, public_key, rule):
        """
        Send a message whose action should concern a particular peer, as identified by its public_key

        :param public_key: the public key of the target peer
        :param rule: the rule associated to the target peer, which determines the message type
        :return: None
        """
        if rule == GossipRule.SUPPRESS:
            # Send suppress requests (for the peer associated to the public_key peer) to all our neighbors
            self.send_to_neighbors(rule, public_key, b"")
        elif rule == GossipRule.DEFAULT:
            pass
        elif rule == GossipRule.COLLECT:
            bloomfilter = BloomFilter(128, 0.25)
            # This bloom filter will hold the messages from the public_key peer, as stored in the DB of this peer
            bloomfilter.add_keys(self.message_db.get(public_key, set()))
            # Spread these messages in the Bloom Filter to all our neighbors

            self.send_to_neighbors(rule, public_key,
                                   self.serializer.pack("I", bloomfilter.functions)[0] + bloomfilter.bytes.encode(
                                       'utf-8'))

        elif rule == GossipRule.SPREAD:
            # Send a random message from the DB associated to the public_key peer
            self.send_to_neighbors(rule, public_key, sample(self.message_db[public_key], 1)[0])

    def add_listener(self, listener):
        """
        Add a gossip listener, which should be called on certain Gossip Messages

        :param listener: the listener, which should be an instance of an implementing class of GossipOverlayListener
        :return: None
        """
        assert isinstance(listener, IGossipOverlayListener), "The listener is not an instance of GossipOverlayListener"
        self.listeners.append(listener)

    def get_rule(self, public_key):
        """
        Returns the Gossip rule for the peer identified by the public_key. Defaults to DEFAULT if non-existent

        :param public_key: the public key of the peer whose rule should be retrieved.
        :return: None
        """
        return self.rules_db.get(public_key, GossipRule.DEFAULT)

    def store(self, public_key, message):
        """
        Store a message, associated to a peer's public_key in the local message DB

        :param public_key: the public key of the peer whose message will be stored
        :param message: the message that will be stored
        :return: None
        """
        existing = self.message_db.get(public_key, set())
        existing.add(message)
        self.message_db[public_key] = existing

    def delete(self, public_key, message):
        """
        Remove a message from the DB if it exists

        :param public_key: the public key of the peer whose message has to be removed
        :param message: the message which should be removed
        :return: True if the message could be removed, False otherwise
        """
        existing = self.message_db.get(public_key, set())
        if message in existing:
            existing.remove(message)
            self.message_db[public_key] = existing
            return True

        return False

    def has_message(self, public_key, message):
        """
        Checks to see if the message for the given public_key is stored in this peer

        :param public_key: the public key of the peer whose messages are being checked
        :param message: the message for which we are checking
        :return: True if the message exists, False otherwise
        """
        return message in self.message_db.get(public_key, set())

    def purge(self, public_key):
        """
        Remove the messages associated to a peer

        :param public_key: the peer whose associated messages should be deleted
        :return: None
        """
        self.message_db.pop(public_key, None)

    def update(self, public_key, message):
        """
        Call the hook methods with the associated public_key and message as function parameters

        :param public_key: the (target) public key of the message
        :param message: received the message
        :return: None
        """
        for listener in self.listeners:
            listener.on_gossip(public_key, message)

    def get_neighborhood(self):
        """
        Returns the peers in the neighborhood of this peer.

        :return: the neighborhood of this peer
        """
        return self.get_peers()

    def send_to_neighbors(self, rule, target_public_key, message):
        """
        Constructs and sends a gossip message to all of this peer's neighbors

        :param rule: the message's gossip rule
        :param target_public_key: the target peer public key
        :param message: the message's payload
        :return: None
        """
        packet = self._pack_gossip_message(rule, target_public_key, message)

        for peer in self.get_neighborhood():
            self.endpoint.send(peer.address, packet)

    def send_to_key(self, public_key, rule, target_public_key, message):
        """
        Constructs and sends a gossip message to a particular peer, as identified by its public key

        :param public_key: the public key of the peer to which we are sending this message
        :param rule: the message's gossip rule
        :param target_public_key: the target peer public key
        :param message: the message's payload
        :return: None
        """
        packet = self._pack_gossip_message(rule, target_public_key, message)

        peer = self.network.get_verified_by_public_key_bin(public_key)
        if peer:
            self.endpoint.send(peer.address, packet)

    def on_packet(self, packet):
        # The source_address of this packet is not used in what follows, so we discard it
        _, data = packet

        if data.startswith(self.prefix):
            message = self._unpack_gossip_message(data)
            is_neighbor = message.public_key in [peer.public_key.key_to_bin() for peer in self.get_neighborhood()]
            if is_neighbor:
                neighbor = self.network.get_verified_by_public_key_bin(message.public_key)
                if neighbor:
                    neighbor.update_clock(neighbor.get_lamport_timestamp())
            self.on_message(is_neighbor, message)

    def on_message(self, is_neighbor, message):
        """
        Called towards processing a Gossip Message is received

        :param is_neighbor: boolean which specifies if the source of the message is a neighbor
        :param message: the message itself
        :return: None
        """
        rule = self.get_rule(message.public_key)
        # rule = the rule we have for the peer which sent this message, i.e. the source of the message
        if rule == GossipRule.SUPPRESS:
            # If this peer is suppressed, ignore all messages
            return
        if message.rule == GossipRule.SUPPRESS and is_neighbor:
            # Our neighbor asked us to ignore someone else
            self._vote_suppress(message)
        elif message.rule == GossipRule.DEFAULT or message.rule == GossipRule.SPREAD:
            # Get the true payload of the received message (i.e. the contents of the message)
            (_, data), _ = self.serializer.unpack_multiple(['64s', 'raw'], message.payload)

            # Construct the raw data used for the signature
            signature_check = message.public_key + str(message.rule).encode('utf-8') + message.target_public_key + \
                message.payload

            # Build a key to check the message's signature
            key = LibNaCLPK(binarykey=message.public_key[10:])

            if not key.verify(message.signature, signature_check):
                # Target public key did not actually make the payload
                return
            if rule == GossipRule.DEFAULT and not is_neighbor:
                # Check first if the DB has the message, since the update might add it, and not delete it after
                if not self.has_message(message.target_public_key, data):
                    self.update(message.target_public_key, data)
                    self.delete(message.target_public_key, data)
                else:
                    self.update(message.target_public_key, data)
            else:
                self.update(message.target_public_key, data)
                self.store(message.target_public_key, data)
        elif message.rule == GossipRule.COLLECT:
            bloomfilter = BloomFilter(str(message.payload[4:].decode('utf-8')),
                                      self.serializer.unpack('I', message.payload[:4])[0], "")
            for payload in self.message_db.get(message.target_public_key):
                if payload.decode('utf-8') not in bloomfilter:
                    # We need to sign the payload
                    self.send_to_key(message.public_key, GossipRule.DEFAULT, message.target_public_key,
                                     self.my_peer.key.signature(payload) + payload)

    def _pack_gossip_message(self, rule, target_public_key, message):
        """
        Pack a gossip message

        :param rule: the rule passed in the message
        :param target_public_key: the public key of the target peer
        :param message: the contents of the message
        :return: the packed gossip message
        """
        return self.prefix + self.serializer.pack_multiple(GossipMessage(self.my_peer.key, rule, target_public_key,
                                                                         message).to_pack_list())[0]

    def _unpack_gossip_message(self, data):
        """
        Unpack a gossip message

        :param data: the raw message
        :return: the unpacked message
        """
        return self.serializer.unpack_to_serializables([GossipMessage, ], data[self.PREFIX_LENGTH:])[0]

    def _vote_suppress(self, message):
        """
        Attempt to suppress a give peer, as specified in the message. This method should only be called when the
        message source is indeed a trusted neighbor.

        :param message: the received SUPPRESS message
        :return: None
        """
        self._vote_change_rule(message, GossipRule.SUPPRESS, self._suppress_peer)

    def _suppress_peer(self, target_public_key):
        """
        Suppress a peer identified by its public key

        :param target_public_key: the public key of the peer which should be suppressed
        :return: None
        """
        self.purge(target_public_key)
        self.rules_db[target_public_key] = GossipRule.SUPPRESS

    def _vote_change_rule(self, message, rule, action):
        """
        Attempt to change the gossip rule for a give peer, as specified in the message. This method should only
        be called when the message source is indeed a trusted neighbor.

        :param message: the received SUPPRESS message
        :param rule: the rule to which one should change the peer indicated in the message
        :param action: a function which should be called when the vote passes. It should have the following signature:
                       (target_public_key : str) => None
        :return: None
        """
        assert message.target_public_key not in self.rule_change_db or \
            isinstance(self.rule_change_db[message.target_public_key], GossipRuleChangeBallot), \
            "The contents of the rule_change_db for this target_public_key are not correct."

        if self.rule_change_db.get(message.target_public_key, None) is None:
            callback_id = reactor.callLater(VOTE_TIMEOUT, self._reset_vote, message.target_public_key)

            # Register the task, and assign it a bogus name
            random_task_name = self.generate_vote_name(message.target_public_key)
            self.register_task(random_task_name, callback_id)

            # Add the new ballot
            self.rule_change_db[message.target_public_key] = (
                GossipRuleChangeBallot(rule, {message.public_key}, random_task_name, callback_id,
                                       len(self.get_neighborhood()) // 2 + 1))

        elif self.rule_change_db[message.target_public_key].rule == rule:
            # Reset the reset timer
            self.rule_change_db[message.target_public_key].reset_callback_timer(VOTE_TIMEOUT)
            self.rule_change_db[message.target_public_key].add_vote(message.public_key)

            # If we have a majority, then change the rule
            if self.rule_change_db[message.target_public_key].has_enough_votes():
                # Cancel the reset
                self.rule_change_db[message.target_public_key].cancel_callback()
                self.cancel_pending_task(self.rule_change_db[message.target_public_key].callback_name)
                self.rules_db[message.target_public_key] = rule

                # Reset the rule change
                del self.rule_change_db[message.target_public_key]
                # Execute the associated action
                action(message.target_public_key)

    def _reset_vote(self, public_key):
        """
        Reset the vote in the rule_change_db for a particular public_key

        :param public_key: the public key for which to reset the vote
        :return: None
        """
        try:
            del self.rule_change_db[public_key]
        except KeyError:
            # Should add logger message here
            pass

    def generate_vote_name(self, pk):
        """
        Generate a unique name for the voting ballot, which can be used when registering the voting task

        :param pk: the public key of the peer whose rule change is being voted
        :return: a unique vote task name
        """
        prefix = b'RULE_VOTE_' + pk + b'_'
        suffix = b''.join(choice(BYTE_HEXDIGITS) for _ in range(60))
        joined = prefix + suffix

        while joined in self._vote_ballot_names:
            suffix = b''.join(choice(BYTE_HEXDIGITS) for _ in range(60))
            joined = prefix + suffix

        self._vote_ballot_names.add(joined)
        return joined

    def walk_to(self, address):
        raise NotImplementedError("GossipOverlay should not have a walker")

    def get_new_introduction(self, from_peer=None, service_id=None):
        raise NotImplementedError("GossipOverlay should not have a walker")

    def get_peers(self):
        return self.network.get_peers_for_service(self.prefix)
