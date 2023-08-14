from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ipv8.types import Peer

# Map of info_hash -> peer list
global_dht_services = defaultdict(list)


class MockDHTProvider:
    """
    A mocked provider for DHT info.
    """

    def __init__(self, peer: Peer) -> None:
        """
        Our peer to register in the mocked DHT.
        """
        self.peer = peer
        # DHTDiscoveryCommunity functionality
        global_dht_services[peer.mid].append(peer)

    async def peer_lookup(self, mid: bytes, peer: Peer = None) -> tuple[bytes, list[Peer]]:
        """
        Look for peers with the corresponding mid.
        """
        return await self.lookup(mid)

    async def lookup(self, info_hash: bytes) -> tuple[bytes, list[Peer]]:
        """
        Look for peers providing generic SHA-1 resources.
        """
        return info_hash, global_dht_services.get(info_hash, [])

    async def announce(self, info_hash: bytes, intro_point: Peer) -> None:
        """
        Announce that a certain peer is serving a given SHA-1 resource.
        """
        global_dht_services[info_hash].append(intro_point)
