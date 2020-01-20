"""
This script enables to start the tracker.

Select the port you want to use by setting the `listen_port` command line argument.
"""
import argparse
import random
import signal
import sys
import time
from asyncio import ensure_future, get_event_loop, sleep

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401


from ipv8.community import Community
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint
from ipv8.messaging.payload import IntroductionRequestPayload
from ipv8.peer import Peer
from ipv8.peerdiscovery.churn import DiscoveryStrategy
from ipv8.peerdiscovery.network import Network


class SimpleChurn(DiscoveryStrategy):
    """
    Remove peers every 120 seconds.
    """

    def take_step(self):
        with self.walk_lock:
            with self.overlay.network.graph_lock:
                for peer in self.overlay.network.verified_peers:
                    if time.time() - peer.last_response > 120:
                        self.overlay.network.remove_peer(peer)


class EndpointServer(Community):
    """
    Make some small modifications to the Community to allow it a dynamic prefix.
    We will also only answer introduction requests.
    """
    master_peer = Peer(default_eccrypto.generate_key(u"very-low"))

    def __init__(self, endpoint):
        my_peer = Peer(default_eccrypto.generate_key(u"very-low"))
        self.signature_length = default_eccrypto.get_signature_length(my_peer.public_key)
        super(EndpointServer, self).__init__(my_peer, endpoint, Network())
        self.churn_strategy = SimpleChurn(self)
        self.churn_task = self.register_task("churn", self.churn_strategy.take_step, interval=30)

    def on_packet(self, packet, warn_unknown=False):
        source_address, data = packet
        try:
            probable_peer = self.network.get_verified_by_address(source_address)
            if probable_peer:
                probable_peer.last_response = time.time()
            if data[22] == 246:
                self.on_generic_introduction_request(source_address, data, data[:22])
            elif warn_unknown:
                self.logger.warning("Tracker received unknown message %s", str(data[22]))
        except Exception:
            import traceback
            traceback.print_exc()

    def on_generic_introduction_request(self, source_address, data, prefix):
        auth, dist, payload = self._ez_unpack_auth(IntroductionRequestPayload, data)
        peer = Peer(auth.public_key_bin, source_address)
        peer.last_response = time.time()

        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [prefix[2:], ])

        intro_peers = [p for p in self.network.get_peers_for_service(prefix[2:]) if not(p == peer)]
        if intro_peers:
            intro_peer = random.choice(intro_peers)
        else:
            intro_peer = None

        packet = self.create_introduction_response(payload.destination_address, peer.address, payload.identifier,
                                                   introduction=intro_peer, prefix=prefix)
        self.endpoint.send(peer.address, packet)

    def get_peer_for_introduction(self, exclude=None):
        """
        We explicitly provide create_introduction_response with a peer.
        If on_generic_introduction_request provides None, this method should not suggest a peer.
        More so as the get_peer_for_introduction peer would be for the DiscoveryCommunity.
        """
        return None


class TrackerService(object):

    def __init__(self):
        """
        Initialize the variables of the TrackerServiceMaker and the logger.
        """
        self.endpoint = None
        self.stopping = False
        self.overlay = None

    async def start_tracker(self, listen_port):
        """
        Main method to startup the tracker.
        """
        self.endpoint = UDPEndpoint(listen_port)
        await self.endpoint.open()
        self.overlay = EndpointServer(self.endpoint)

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


def main(argv):
    parser = argparse.ArgumentParser(add_help=False, description=('IPv8 tracker plugin'))
    parser.add_argument('--help', '-h', action='help', default=argparse.SUPPRESS, help='Show this help message and exit')
    parser.add_argument('--listen_port', '-p', default=8090, type=int, help='Use an alternative port')

    args = parser.parse_args(sys.argv[1:])
    service = TrackerService()

    loop = get_event_loop()
    coro = service.start_tracker(args.listen_port)
    ensure_future(coro)

    if sys.platform == 'win32':
        # Unfortunately, this is needed on Windows for Ctrl+C to work consistently.
        # Should no longer be needed in Python 3.8.
        async def wakeup():
            while True:
                await sleep(1)
        ensure_future(wakeup())

    loop.run_forever()


if __name__ == "__main__":
    main(sys.argv[1:])
