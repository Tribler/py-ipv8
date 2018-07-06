from random import choice

from twisted.internet.task import LoopingCall

from ..deprecated.bloomfilter import BloomFilter
from ..keyvault.public.libnaclkey import LibNaCLPK
from ..messaging.serialization import PackError, Serializable
from ..overlay import Overlay


class GossipRule(object):

    SUPPRESS = 0
    DEFAULT = 1
    COLLECT = 2
    SPREAD = 3


class GossipMessage(Serializable):

    format_list = ['32s', '74s', 'c', '74s', 'raw']

    def __init__(self, my_private_key, rule, target_public_key, payload):
        self.public_key = my_private_key.pub().key_to_bin()
        self.payload = payload
        self.rule = rule
        self.target_public_key = target_public_key
        self.signature = my_private_key.signature(self.public_key + self.rule + self.target_public_key + self.payload)

    def to_pack_list(self):
        return [
            ('32s', self.signature),
            ('74s', self.public_key),
            ('c', self.rule),
            ('74s', self.target_public_key),
            ('raw', self.payload)
        ]

    @classmethod
    def from_unpack_list(cls, signature, public_key, rule, target_public_key, payload):
        key = LibNaCLPK(binarykey=public_key)
        if key.verify(signature, public_key+rule+target_public_key+payload):
            out = object.__new__(GossipMessage)
            out.public_key = public_key
            out.signature = signature
            out.payload = payload
            out.rule = rule
            out.target_public_key = target_public_key
            return out
        else:
            raise PackError("Incorrect signature of GossipMessage")


class GossipOverlay(Overlay):
    """
    Interface:
     - listeners: add your callback function here, accepting (public_key : str, message : str)
     - set_rule(public_key : str, rule : GossipRule)
    """

    def __init__(self, my_peer, endpoint, network):
        super(GossipOverlay, self).__init__(my_peer, endpoint, network)

        self.message_db = {} # Pk: set(messages)
        self.rules_db = {} # Pk: rule
        self.listeners = []
        self.prefix = "\x01\x00GossipCommunity\x00\x00\x00\x00\x00"

        self.register_task("update_key", LoopingCall(self.take_step, now=False)).start()
        self.update_list = []

    def set_rule(self, public_key, rule):
        self.rules_db[public_key] = rule

    def take_step(self):
        if not self.update_list:
            self.update_list = self.rules_db.keys()
        next_public_key = self.update_list.pop(0) if self.update_list else None
        if next_public_key:
            self.enforce(next_public_key, self.get_rule(next_public_key))

    def enforce(self, public_key, rule):
        if rule == GossipRule.SUPPRESS:
            self.send_to_neighbors(rule, public_key, "")
        elif rule == GossipRule.DEFAULT:
            pass
        elif rule == GossipRule.COLLECT:
            bloomfilter = BloomFilter(128, 0.25)
            bloomfilter.add_keys(self.message_db.get(public_key, set()))
            self.send_to_neighbors(rule, public_key, self.serializer.pack("I", bloomfilter.functions) +
                                   bloomfilter.bytes)
        elif rule == GossipRule.SPREAD:
            self.send_to_neighbors(rule, public_key, choice(self.message_db[public_key]))

    def get_rule(self, public_key):
        return self.rules_db.get(public_key, GossipRule.DEFAULT)

    def store(self, public_key, message):
        existing = self.message_db.get(public_key, set())
        existing.add(message)
        self.message_db[public_key] = existing

    def delete(self, public_key, message):
        existing = self.message_db.get(public_key, set())
        existing.remove(message)
        self.message_db[public_key] = existing

    def purge(self, public_key):
        self.message_db.pop(public_key, None)

    def update(self, public_key, message):
        for listener in self.listeners:
            listener.on_gossip(public_key, message)

    def get_neighborhood(self):
        return self.get_peers()

    def send_to_neighbors(self, rule, target_public_key, message):
        packet = self.serializer.pack_multiple(GossipMessage(self.my_peer.key, rule, target_public_key,
                                                             message).to_pack_list())
        for peer in self.get_neighborhood():
            self.endpoint.send(peer.address, packet)

    def send_to_key(self, public_key, rule, target_public_key, message):
        packet = self.serializer.pack_multiple(GossipMessage(self.my_peer.key, rule, target_public_key,
                                                             message).to_pack_list())
        peer = self.network.get_verified_by_public_key_bin(public_key)
        if peer:
            self.endpoint.send(peer.address, packet)

    def on_packet(self, (source_address, data)):
        if data.startswith(self.prefix):
            message, = self.serializer.unpack_to_serializables([GossipMessage, ], data)
            is_neighbor = message.public_key in [peer.public_key.key_to_bin() for peer in self.get_neighborhood()]
            if is_neighbor:
                neighbor = self.network.get_verified_by_public_key_bin(message.public_key)
                if neighbor:
                    neighbor.update_clock(neighbor.get_lamport_timestamp())
            self.on_message(is_neighbor, message)

    def on_message(self, is_neighbor, message):
        rule = self.get_rule(message.public_key)
        if rule == GossipRule.SUPPRESS:
            # If this peer is suppressed, ignore all messages
            return
        if message.rule == GossipRule.SUPPRESS:
            if is_neighbor:
                # Our neighbor asked us to ignore someone else
                self.purge(message.target_public_key)
                self.rules_db[message.target_public_key] = GossipRule.SUPPRESS
            else:
                # If I don't trust you, you are not allowed to influence me.
                pass
        elif message.rule == GossipRule.DEFAULT or message.rule == GossipRule.SPREAD:
            signature, data = self.serializer.unpack_multiple(['32s', 'raw'], message.payload)
            key = LibNaCLPK(binarykey=message.target_public_key)
            if not key.verify(signature, data):
                # Target public key did not actually make the payload
                return
            if rule == GossipRule.DEFAULT and not is_neighbor:
                # This message has been forwarded to us
                self.update(message.target_public_key, data)
                self.delete(message.target_public_key, data)
            else:
                # This message is from our neighbor or we care about it
                self.update(message.target_public_key, data)
                self.store(message.target_public_key, data)
        elif message.rule == GossipRule.COLLECT:
            # Someone asked us to give him information of some peer
            bloomfilter = BloomFilter(message.payload[4:], self.serializer.unpack('I', message.payload[:4])[0], "")
            for payload in self.message_db.get(message.target_public_key):
                if payload not in bloomfilter:
                    self.send_to_key(message.public_key, GossipRule.DEFAULT, message.target_public_key, payload)

    def walk_to(self, address):
        raise NotImplementedError("GossipOverlay should not have a walker")

    def get_new_introduction(self, from_peer=None, service_id=None):
        raise NotImplementedError("GossipOverlay should not have a walker")

    def get_peers(self):
        return self.network.get_peers_for_service(self.prefix)
