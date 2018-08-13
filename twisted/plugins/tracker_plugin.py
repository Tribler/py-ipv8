"""
This twistd plugin enables to start the tracker using the twistd command.

Select the port you want to use by setting the `listen_port` command line argument.
"""

import os
import random
import signal
import sys
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from twisted.application.service import MultiService, IServiceMaker
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.plugin import IPlugin
from twisted.python import usage
from twisted.python.log import msg
from zope.interface import implements

from ipv8.deprecated.payload import IntroductionRequestPayload
from ipv8.keyvault.crypto import ECCrypto
from ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint
from ipv8.peer import Peer
from ipv8.peerdiscovery.churn import RandomChurn
from ipv8.peerdiscovery.deprecated.discovery import DiscoveryCommunity
from ipv8.peerdiscovery.network import Network


class EndpointServer(DiscoveryCommunity):
    """
    Make some small modifications to the Community to allow it a dynamic prefix.
    We will also only answer introduction requests.
    """

    def __init__(self, endpoint):
        my_peer = Peer(ECCrypto().generate_key(u"very-low"))
        super(EndpointServer, self).__init__(my_peer, endpoint, Network())
        self.churn_lc = self.register_task("churn", LoopingCall(self.do_churn)).start(5.0, now=False)
        self.churn_strategy = RandomChurn(self)
        self.crypto = ECCrypto()

    def on_packet(self, (source_address, data), warn_unknown=False):
        try:
            probable_peer = self.network.get_verified_by_address(source_address)
            if probable_peer:
                probable_peer.last_response = time.time()
            if data[22] == chr(246):
                self.on_generic_introduction_request(source_address, data, data[:22])
            elif warn_unknown:
                self.logger.warning("Tracker received unknown message %s", str(data[22]))
        except:
            import traceback
            traceback.print_exc()

    def on_generic_introduction_request(self, source_address, data, prefix):
        auth, dist, payload = self._ez_unpack_auth(IntroductionRequestPayload, data)
        peer = Peer(auth.public_key_bin, source_address)

        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [prefix[2:], ])

        intro_peers = [p for p in self.network.get_peers_for_service(prefix[2:]) if not(p == peer)]
        if intro_peers:
            intro_peer = random.choice(intro_peers)
            packet = self.create_introduction_response(payload.destination_address, peer.address, payload.identifier,
                                                       introduction=intro_peer)

            signature_length = self.crypto.get_signature_length(self.my_peer.public_key)
            packet = prefix + packet[22:-signature_length]
            signature = self.crypto.create_signature(self.my_peer.key, packet)

            self.endpoint.send(peer.address, packet + signature)

    def do_churn(self):
        """
        Dynamically scale churn to check one fifth of our network every step.
        """
        self.churn_strategy.sample_size = min(len(self.network.verified_peers)/5, 1)
        self.churn_strategy.take_step()


class Options(usage.Options):
    optParameters = [["listen_port", None, None, None, int]]
    optFlags = []


class TrackerServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "tracker"
    description = "IPv8 tracker twistd plugin"
    options = Options

    def __init__(self):
        """
        Initialize the variables of the TrackerServiceMaker and the logger.
        """
        self.endpoint = None
        self.stopping = False
        self.overlay = None

    def start_tracker(self, options):
        """
        Main method to startup the tracker.
        """
        self.endpoint = UDPEndpoint(options["listen_port"])
        self.endpoint.open()
        self.overlay = EndpointServer(self.endpoint)

        def signal_handler(sig, _):
            msg("Received shut down signal %s" % sig)
            if not self.stopping:
                self.stopping = True

                def close_ep():
                    self.endpoint.close().addCallback(lambda *args, **kwargs: reactor.callFromThread(reactor.stop))
                self.overlay.unload()
                close_ep()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        msg("Started tracker")

    def makeService(self, options):
        """
        Construct a tracker service.
        """
        tracker_service = MultiService()
        tracker_service.setName("IPv8Tracker")

        reactor.callWhenRunning(self.start_tracker, options)

        return tracker_service


service_maker = TrackerServiceMaker()
