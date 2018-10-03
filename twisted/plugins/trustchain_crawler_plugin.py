"""
This twistd plugin starts a TrustChain crawler.
"""
from __future__ import absolute_import

import os
import signal
import sys

import logging

import yappi

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from twisted.application.service import MultiService, IServiceMaker
from twisted.internet import reactor
from twisted.plugin import IPlugin
from twisted.python import usage
from twisted.python.log import msg
from zope.interface import implements

from ipv8_service import IPv8
from ipv8.attestation.trustchain.settings import TrustChainSettings
from ipv8.REST.rest_manager import RESTManager


class Options(usage.Options):
    optParameters = [
        ["statedir", "s", None, "Use an alternate statedir", str],
        ["apiport", "p", 8085, "Use an alternative port for the REST api", int],
    ]
    optFlags = [
        ["no-rest-api", "a", "Autonomous: disable the REST api"],
        ["testnet", "t", "Join the testnet"],
        ["yappi", "y", "Run the Yappi profiler"]
    ]


tc_settings = TrustChainSettings()
tc_settings.crawler = True
tc_settings.max_db_blocks = 1000000000


crawler_config = {
    'address': '0.0.0.0',
    'port': 8090,
    'keys': [
        {
            'alias': "my peer",
            'generation': u"medium",
            'file': u"ec.pem"
        }
    ],
    'logger': {
        'level': "ERROR"
    },
    'walker_interval': 0.5,
    'overlays': [
        {
            'class': 'DiscoveryCommunity',
            'key': "my peer",
            'walkers': [
                {
                    'strategy': "RandomWalk",
                    'peers': -1,
                    'init': {
                        'timeout': 3.0
                    }
                },
                {
                    'strategy': "RandomChurn",
                    'peers': -1,
                    'init': {
                        'sample_size': 64,
                        'ping_interval': 1.0,
                        'inactive_time': 1.0,
                        'drop_time': 3.0
                    }
                }
            ],
            'initialize': {},
            'on_start': [
                ('resolve_dns_bootstrap_addresses', )
            ]
        }, {
            'class': 'TrustChainCommunity',
            'key': "my peer",
            'walkers': [
                {
                    'strategy': "RandomWalk",
                    'peers': -1,
                    'init': {
                        'timeout': 3.0
                    }
                },
            ],
            'initialize': {
                'settings': tc_settings
            },
            'on_start': [],
        },
    ]
}


class TrustchainCrawlerServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "trustchain_crawler"
    description = "TrustChain crawler"
    options = Options

    def __init__(self):
        """
        Initialize the variables of the TrustChain crawler and the logger.
        """
        self.ipv8 = None
        self.restapi = None
        self._stopping = False

    def start_crawler(self, options):
        """
        Main method to startup the TrustChain crawler.
        """
        root = logging.getLogger()
        root.setLevel(logging.INFO)

        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(logging.INFO)
        stderr_handler.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s:%(message)s"))
        root.addHandler(stderr_handler)

        if options["statedir"]:
            # If we use a custom state directory, update various variables
            for key in crawler_config["keys"]:
                key["file"] = os.path.join(options["statedir"], key["file"])

            for community in crawler_config["overlays"]:
                if community["class"] == "TrustChainCommunity":
                    community["initialize"]["working_directory"] = options["statedir"]

        if 'testnet' in options and options['testnet']:
            for community in crawler_config["overlays"]:
                if community["class"] == "TrustChainCommunity":
                    community["class"] = "TrustChainTestnetCommunity"

        self.ipv8 = IPv8(crawler_config)

        def signal_handler(sig, _):
            msg("Received shut down signal %s" % sig)
            if not self._stopping:
                self._stopping = True
                if self.restapi:
                    self.restapi.stop()
                self.ipv8.stop()

                if options['yappi']:
                    yappi.stop()
                    msg("Yappi has shutdown")
                    yappi_stats = yappi.get_func_stats()
                    yappi_stats.sort("tsub")
                    out_file = 'yappi'
                    if options["statedir"]:
                        out_file = os.path.join(options["statedir"], out_file)
                    yappi_stats.save(out_file, type='callgrind')

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        msg("Starting TrustChain crawler")

        if not options['no-rest-api']:
            self.restapi = RESTManager(self.ipv8)
            reactor.callLater(0.0, self.restapi.start, options["apiport"])

        if options['yappi']:
            yappi.start(builtins=True)

    def makeService(self, options):
        """
        Construct a IPv8 service.
        """
        crawler_service = MultiService()
        crawler_service.setName("TrustChainCrawler")

        reactor.callWhenRunning(self.start_crawler, options)

        return crawler_service


service_maker = TrustchainCrawlerServiceMaker()
