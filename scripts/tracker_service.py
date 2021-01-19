"""
Common classes for tracker_plugin.py and tracker_reporter_plugin.py scripts
"""
import os
import random
import signal
import time
import traceback
from asyncio import ensure_future, get_event_loop

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401


from ipv8.community import Community
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint, UDPv4LANAddress
from ipv8.messaging.payload import IntroductionRequestPayload, IntroductionResponsePayload
from ipv8.peer import Peer
from ipv8.peerdiscovery.churn import RandomChurn
from ipv8.peerdiscovery.network import Network
from ipv8.requestcache import NumberCache, RequestCache


class TrackerChurn(RandomChurn):
    def __init__(self, *args, max_peers=100, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_peers = max_peers

    def take_step(self):
        super().take_step()
        if len(self.overlay.network.verified_peers) > self.max_peers:
            to_remove = sorted(self.overlay.network.verified_peers, key=lambda p: p.creation_time)[:-self.max_peers]
            for peer in to_remove:
                self.overlay.network.remove_peer(peer)


class TrackerPing(NumberCache):
    name = "tracker-ping"

    def __init__(self, request_cache, identifier, network, peer, service):
        super().__init__(request_cache, TrackerPing.name, identifier)
        self.network = network
        self.peer = peer
        self.service = service

    @property
    def timeout_delay(self):
        return 5.0

    def on_timeout(self):
        services = self.network.get_services_for_peer(self.peer)
        services.discard(self.service)
        if not services:
            self.network.remove_peer(self.peer)


class EndpointServer(Community):
    """
    Make some small modifications to the Community to allow it a dynamic prefix.
    We will also only answer introduction requests.
    """
    community_id = os.urandom(20)

    def __init__(self, endpoint):
        my_peer = Peer(default_eccrypto.generate_key(u"very-low"))
        self.signature_length = default_eccrypto.get_signature_length(my_peer.public_key)
        super().__init__(my_peer, endpoint, Network())
        self.request_cache = RequestCache()
        self.endpoint.add_listener(self)  # Listen to all incoming packets (not just the fake community_id).
        self.churn_strategy = TrackerChurn(self)
        self.churn_task = self.register_task("churn", self.churn_strategy.take_step, interval=10)

    def on_packet(self, packet, warn_unknown=False):
        source_address, data = packet
        try:
            probable_peer = self.network.get_verified_by_address(source_address)
            if probable_peer:
                probable_peer.last_response = time.time()
            if data[22] == 246:
                self.on_generic_introduction_request(source_address, data, data[:22])
            if data[22] == 245:
                self.on_generic_introduction_response(source_address, data, data[:22])
            elif warn_unknown:
                self.logger.warning("Tracker received unknown message %s", str(data[22]))
        except Exception:
            traceback.print_exc()

    def on_generic_introduction_request(self, source_address, data, prefix):
        auth, dist, payload = self._ez_unpack_auth(IntroductionRequestPayload, data)
        peer = Peer(auth.public_key_bin, source_address)
        peer.address = UDPv4LANAddress(*payload.source_lan_address)
        peer.last_response = time.time()

        service_id = prefix[2:]
        self.on_peer_introduction_request(peer, source_address, service_id)

        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [service_id, ])

        intro_peers = [p for p in self.network.get_peers_for_service(service_id)
                       if not p == peer]
        if intro_peers:
            intro_peer = random.choice(intro_peers)
        else:
            intro_peer = None

        packet = self.create_introduction_response(
            payload.destination_address, peer.address, payload.identifier,
            introduction=intro_peer, prefix=prefix)
        self.endpoint.send(peer.address, packet)

    def send_ping(self, peer):
        service = random.choice(tuple(self.network.get_services_for_peer(peer)))
        prefix = b'\x00' + self.version + service
        packet = self.create_introduction_request(peer.address, prefix=prefix)
        cache = TrackerPing(self.request_cache, self.global_time, self.network, peer, service)
        self.request_cache.add(cache)
        self.endpoint.send(peer.address, packet)

    def on_generic_introduction_response(self, source_address, data, prefix):
        auth, dist, payload = self._ez_unpack_auth(IntroductionResponsePayload, data)
        if not self.request_cache.has('tracker-ping', payload.identifier):
            return

        self.request_cache.pop('tracker-ping', payload.identifier)
        if payload.peer_limit_reached:
            peer = Peer(auth.public_key_bin, source_address)
            services = self.network.get_services_for_peer(peer)
            services.discard(prefix[2:])
            if not services:
                self.network.remove_peer(peer)

    def on_peer_introduction_request(self, peer, source_address, service_id):
        """
        A hook to collect anonymized statistics about total peer count
        """

    def get_peer_for_introduction(self, exclude=None, new_style=False):
        """
        We explicitly provide create_introduction_response with a peer.
        If on_generic_introduction_request provides None, this method should not suggest a peer.
        More so as the get_peer_for_introduction peer would be for the DiscoveryCommunity.
        """
        return None

    async def unload(self):
        await self.request_cache.shutdown()
        await super().unload()


class TrackerService:

    def __init__(self):
        """
        Initialize the variables of the TrackerServiceMaker and the logger.
        """
        self.endpoint = None
        self.stopping = False
        self.overlay = None

    def create_endpoint_server(self):
        return EndpointServer(self.endpoint)

    async def start_tracker(self, listen_port):
        """
        Main method to startup the tracker.
        """
        self.endpoint = UDPEndpoint(listen_port)
        await self.endpoint.open()
        self.overlay = self.create_endpoint_server()

        async def signal_handler(sig):
            print("Received shut down signal %s" % sig)
            if not self.stopping:
                self.stopping = True
                await self.overlay.unload()
                self.endpoint.close()
                get_event_loop().stop()

        signal.signal(signal.SIGINT, lambda sig, _: ensure_future(signal_handler(sig)))
        signal.signal(signal.SIGTERM, lambda sig, _: ensure_future(signal_handler(sig)))

        print("Started tracker")
