"""
This twistd plugin enables to start IPv8 headless using the twistd command.
"""
from __future__ import absolute_import

import os
import signal
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from twisted.application.service import IServiceMaker, MultiService
from twisted.internet import reactor
from twisted.plugin import IPlugin
from twisted.python import usage
from twisted.python.log import msg

from zope.interface import implementer

from ipv8.configuration import get_default_configuration
from ipv8_service import IPv8
from ipv8.REST.rest_manager import RESTManager
from ipv8.messaging.anonymization.tunnel import PEER_FLAG_EXIT_IPV8


class ExitnodeOptions(usage.Options):
    optParameters = [["listen_port", None, 8090, "Use an alternative port", int]]
    optFlags = [
        ["no-rest-api", "a", "Autonomous: disable the REST api"],
        ["statistics", "s", "Enable IPv8 overlay statistics"],
    ]


@implementer(IPlugin, IServiceMaker)
class ExitnodeIPv8ServiceMaker(object):
    tapname = "exitnode_ipv8only"
    description = "IPv8-only exit node plugin"
    options = ExitnodeOptions

    def __init__(self):
        """
        Initialize the variables of the IPV8ServiceMaker and the logger.
        """
        self.ipv8 = None
        self.restapi = None
        self._stopping = False

    def start_ipv8(self, options):
        """
        Main method to startup IPv8.
        """
        configuration = get_default_configuration()

        configuration['port'] = options["listen_port"]

        allowed_overlays = ['DHTDiscoveryCommunity', 'DiscoveryCommunity', 'HiddenTunnelCommunity',
                            'TrustChainCommunity']
        configuration['overlays'] = [overlay for overlay in configuration['overlays']
                                     if overlay['class'] in allowed_overlays]

        for overlay in configuration['overlays']:
            if overlay['class'] == 'HiddenTunnelCommunity':
                overlay['initialize']['settings']['min_circuits'] = 0
                overlay['initialize']['settings']['max_circuits'] = 0
                overlay['initialize']['settings']['max_relays_or_exits'] = 1000
                overlay['initialize']['settings']['peer_flags'] = PEER_FLAG_EXIT_IPV8

        self.ipv8 = IPv8(configuration, enable_statistics=options['statistics'])

        def signal_handler(sig, _):
            msg("Received shut down signal %s" % sig)
            if not self._stopping:
                self._stopping = True
                if self.restapi:
                    self.restapi.stop()
                self.ipv8.stop()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        msg("Starting IPv8")

        if not options['no-rest-api']:
            self.restapi = RESTManager(self.ipv8)
            reactor.callLater(0.0, self.restapi.start)

    def makeService(self, options):
        """
        Construct a IPv8 service.
        """
        ipv8_service = MultiService()
        ipv8_service.setName("IPv8Exitnode")

        reactor.callWhenRunning(self.start_ipv8, options)

        return ipv8_service


service_maker = ExitnodeIPv8ServiceMaker()
