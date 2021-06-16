from collections import defaultdict

# Map of info_hash -> peer list
global_dht_services = defaultdict(list)


class MockDHTProvider:

    def __init__(self, peer):
        self.peer = peer
        # DHTDiscoveryCommunity functionality
        global_dht_services[peer.mid].append(peer)

    async def peer_lookup(self, mid, peer=None):  # pylint: disable=W0613
        return await self.lookup(mid)

    async def lookup(self, info_hash):
        return info_hash, global_dht_services.get(info_hash, [])

    async def announce(self, info_hash, intro_point):
        global_dht_services[info_hash].append(intro_point)
