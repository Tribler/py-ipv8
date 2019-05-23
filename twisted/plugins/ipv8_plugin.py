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
from ipv8.ipv8 import IPv8
from ipv8.REST.rest_manager import RESTManager


class Options(usage.Options):
    optParameters = []
    optFlags = [
        ["no-rest-api", "a", "Autonomous: disable the REST api"],
        ["statistics", "s", "Enable IPv8 overlay statistics"],
    ]


@implementer(IPlugin, IServiceMaker)
class IPV8ServiceMaker(object):
    tapname = "ipv8"
    description = "IPv8 twistd plugin, starts IPv8 as a service"
    options = Options

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
        self.ipv8 = IPv8(get_default_configuration(), enable_statistics=options['statistics'])

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
        ipv8_service.setName("IPv8")

        reactor.callWhenRunning(self.start_ipv8, options)

        return ipv8_service


service_maker = IPV8ServiceMaker()
