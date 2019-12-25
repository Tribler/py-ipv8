"""
This script starts a TrustChain crawler.
"""
import argparse
import logging
import os
import signal
import sys
from asyncio import all_tasks, ensure_future, gather, get_event_loop, sleep

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ipv8.REST.rest_manager import RESTManager
from ipv8.attestation.trustchain.settings import TrustChainSettings

from ipv8_service import IPv8


tc_settings = TrustChainSettings()
tc_settings.crawler = True
tc_settings.max_db_blocks = 1000000000


crawler_config = {
    'address': '0.0.0.0',
    'port': 8090,
    'keys': [
        {
            'alias': "my peer",
            'generation': u"curve25519",
            'file': u"crawler_key.pem"
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
                        'ping_interval': 10.0,
                        'inactive_time': 30.0,
                        'drop_time': 50.0
                    }
                },
                {
                    'strategy': "PeriodicSimilarity",
                    'peers': -1,
                    'init': {}
                }
            ],
            'initialize': {
                'max_peers': -1
            },
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
                'max_peers': -1,
                'settings': tc_settings
            },
            'on_start': [],
        },
    ]
}


class TrustchainCrawlerService(object):

    def __init__(self):
        """
        Initialize the variables of the TrustChain crawler and the logger.
        """
        self.ipv8 = None
        self.restapi = None
        self._stopping = False

    async def start_crawler(self, statedir, apiport, no_rest_api, testnet, yappi):
        """
        Main method to startup the TrustChain crawler.
        """
        root = logging.getLogger()
        root.setLevel(logging.INFO)

        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(logging.INFO)
        stderr_handler.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s:%(message)s"))
        root.addHandler(stderr_handler)

        if statedir:
            # If we use a custom state directory, update various variables
            for key in crawler_config["keys"]:
                key["file"] = os.path.join(statedir, key["file"])

            for community in crawler_config["overlays"]:
                if community["class"] == "TrustChainCommunity":
                    community["initialize"]["working_directory"] = statedir

        if testnet:
            for community in crawler_config["overlays"]:
                if community["class"] == "TrustChainCommunity":
                    community["class"] = "TrustChainTestnetCommunity"

        self.ipv8 = IPv8(crawler_config)
        await self.ipv8.start()

        async def signal_handler(sig):
            print("Received shut down signal %s" % sig)
            if not self._stopping:
                self._stopping = True
                if self.restapi:
                    await self.restapi.stop()
                await self.ipv8.stop()

                if yappi:
                    yappi.stop()
                    print("Yappi has shutdown")
                    yappi_stats = yappi.get_func_stats()
                    yappi_stats.sort("tsub")
                    out_file = 'yappi'
                    if statedir:
                        out_file = os.path.join(statedir, out_file)
                    yappi_stats.save(out_file, type='callgrind')

                await gather(*all_tasks())
                get_event_loop().stop()

        signal.signal(signal.SIGINT, lambda sig, _: ensure_future(signal_handler(sig)))
        signal.signal(signal.SIGTERM, lambda sig, _: ensure_future(signal_handler(sig)))

        print("Starting TrustChain crawler")

        if not no_rest_api:
            self.restapi = RESTManager(self.ipv8)
            await self.restapi.start(apiport)

        if yappi:
            yappi.start(builtins=True)


def main(argv):
    parser = argparse.ArgumentParser(add_help=False, description=('TrustChain crawler'))
    parser.add_argument('--help', '-h', action='help', default=argparse.SUPPRESS, help='Show this help message and exit')
    parser.add_argument('--statedir', '-s', default=None, type=str, help='Use an alternate statedir')
    parser.add_argument('--apiport', '-p', default=8085, type=int, help='Use an alternative port for the REST api')
    parser.add_argument('--no-rest-api', '-a', action='store_const', default=False, const=True, help='Autonomous: disable the REST api')
    parser.add_argument('--testnet', '-t', action='store_const', default=False, const=True, help='Join the testnet')
    parser.add_argument('--yappi', '-y', action='store_const', default=False, const=True, help='Run the Yappi profiler')

    args = parser.parse_args(sys.argv[1:])
    service = TrustchainCrawlerService()

    loop = get_event_loop()
    coro = service.start_crawler(args.statedir, args.apiport, args.no_rest_api, args.testnet, args.yappi)
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
