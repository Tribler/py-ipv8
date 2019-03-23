from __future__ import absolute_import

from binascii import hexlify
import logging
from socket import inet_aton, inet_ntoa
from struct import pack, unpack_from

from ..peer import Peer
from ..messaging.anonymization.tunnel import IntroductionPoint, PEER_SOURCE_DHT


class DHTCommunityProvider(object):
    """
    This class is a wrapper around the DHTCommunity and is used to discover introduction points
    for hidden services.
    """

    def __init__(self, dht_community, port):
        self.dht_community = dht_community
        self.port = port
        self.logger = logging.getLogger(self.__class__.__name__)

    def peer_lookup(self, mid, cb):
        self.dht_community.connect_peer(mid).addCallbacks(cb, lambda _: None)

    def lookup(self, info_hash, cb):
        def callback(values):
            results = []
            for value, _ in values:
                try:
                    ip_bin, port, intro_key_len = unpack_from('!4sHH', value)
                    ip = inet_ntoa(ip_bin)
                    intro_pk = 'LibNaCLPK:' + value[8:8 + intro_key_len]
                    intro_peer = Peer(intro_pk, address=(ip, port))

                    seeder_key_len, = unpack_from('!H', value, 8 + intro_key_len)
                    seeder_pk = 'LibNaCLPK:' + value[8 + intro_key_len:8 + intro_key_len + seeder_key_len]

                    results.append(IntroductionPoint(intro_peer, seeder_pk, PEER_SOURCE_DHT))
                except:
                    pass
            self.logger.info("Looked up %s in the DHTCommunity, got %d results", info_hash.encode('hex'), len(results))
            return info_hash, results
        self.dht_community.find_values(info_hash).addCallback(callback).addCallbacks(cb, lambda _: None)

    def announce(self, info_hash, intro_point):
        def callback(_):
            self.logger.info("Announced %s to the DHTCommunity", hexlify(info_hash))

        def errback(_):
            self.logger.info("Failed to announce %s to the DHTCommunity", hexlify(info_hash))

        intro_pk = intro_point.peer.public_key.key_to_bin()
        value = inet_aton(intro_point.peer.address[0]) + pack("!H", intro_point.peer.address[1])
        # We strip away the LibNaCLPK part of the public key to avoid going over the DHT size limit.
        value += pack('!H', len(intro_pk)) + intro_pk[10:]
        value += pack('!H', len(intro_point.seeder_pk)) + intro_point.seeder_pk[10:]

        self.dht_community.store_value(info_hash, value).addCallbacks(callback, errback)
