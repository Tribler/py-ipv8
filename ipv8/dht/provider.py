import logging
from binascii import hexlify
from socket import inet_aton, inet_ntoa
from struct import pack, unpack_from

from . import DHTError
from ..messaging.anonymization.tunnel import IntroductionPoint, PEER_SOURCE_DHT
from ..peer import Peer
from ..util import cast_to_bin


class DHTCommunityProvider(object):
    """
    This class is a wrapper around the DHTCommunity and is used to discover introduction points
    for hidden services.
    """

    def __init__(self, dht_community, port):
        self.dht_community = dht_community
        self.port = port
        self.logger = logging.getLogger(self.__class__.__name__)

    async def peer_lookup(self, mid, peer=None):
        try:
            await self.dht_community.connect_peer(mid, peer)
        except DHTError as e:
            self.logger.debug("Failed to connect %s using the DHTCommunity (error: %s)", hexlify(mid), e)
            return

    async def lookup(self, info_hash):
        try:
            values = await self.dht_community.find_values(info_hash)
        except DHTError as e:
            self.logger.info("Failed to lookup %s on the DHTCommunity (error: %s)", hexlify(info_hash), e)
            return

        results = []
        for value, _ in values:
            try:
                ip_bin, port, last_seen, intro_key_len = unpack_from('!4sHIH', value)
                ip = inet_ntoa(ip_bin)
                intro_pk = b'LibNaCLPK:' + value[12:12 + intro_key_len]
                intro_peer = Peer(intro_pk, address=(ip, port))

                seeder_key_len, = unpack_from('!H', value, 12 + intro_key_len)
                seeder_pk = b'LibNaCLPK:' + value[14 + intro_key_len:14 + intro_key_len + seeder_key_len]

                results.append(IntroductionPoint(intro_peer, seeder_pk, PEER_SOURCE_DHT, last_seen))
            except Exception as e:
                self.logger.info("Error encountered during lookup %s on the DHTCommunity (error: %s)", hexlify(info_hash), e)
        self.logger.info("Looked up %s in the DHTCommunity, got %d results", hexlify(info_hash), len(results))
        return info_hash, results

    async def announce(self, info_hash, intro_point):
        # We strip away the LibNaCLPK part of the public key to avoid going over the DHT size limit.
        intro_pk = intro_point.peer.public_key.key_to_bin()[10:]
        seeder_pk = intro_point.seeder_pk[10:]

        value = inet_aton(intro_point.peer.address[0]) + pack("!H", intro_point.peer.address[1])
        value += pack('!I', intro_point.last_seen)
        value += pack('!H', len(intro_pk)) + cast_to_bin(intro_pk)
        value += pack('!H', len(seeder_pk)) + cast_to_bin(seeder_pk)

        try:
            await self.dht_community.store_value(info_hash, value)
        except DHTError as e:
            self.logger.info("Failed to announce %s to the DHTCommunity (error: %s)", hexlify(info_hash), e)
        else:
            self.logger.info("Announced %s to the DHTCommunity", hexlify(info_hash))
