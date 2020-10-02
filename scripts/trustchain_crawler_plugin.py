"""
This script starts a TrustChain crawler.
"""
import argparse
import logging
import os
import random
import signal
import sys
from asyncio import all_tasks, ensure_future, gather, get_event_loop, sleep
from binascii import unhexlify

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401


from ipv8.REST.rest_manager import RESTManager
from ipv8.attestation.trustchain.community import TrustChainCommunity
from ipv8.attestation.trustchain.database import TrustChainDB
from ipv8.attestation.trustchain.settings import TrustChainSettings

from ipv8_service import IPv8

logger = logging.getLogger(__name__)

tc_settings = TrustChainSettings()
tc_settings.crawler = True
tc_settings.max_db_blocks = 1000000000


class TrustChainCrawlerCommunity(TrustChainCommunity):
    """
    TrustChain community specifically for the crawler.
    """

    def __init__(self, *args, **kwargs):
        super(TrustChainCrawlerCommunity, self).__init__(*args, **kwargs)
        ensure_future(self.start_crawling())

    async def start_crawling(self):
        self._logger.info("Starting to crawl...")
        while True:
            await sleep(2)
            ensure_future(self.crawl_peer())

    def on_latest_block(self, peer, blocks):
        his_block = None
        if not blocks:
            return

        for block in blocks:
            if block.public_key == peer.public_key.key_to_bin():
                his_block = block
                break

        if his_block:
            self._logger.info("Sending full crawl request to peer %s", peer)
            self.crawl_chain(peer, his_block.sequence_number)

    async def crawl_peer(self):
        """
        Crawl a random peer.
        """
        tc_peers = self.get_peers()
        if not tc_peers:
            self._logger.info("No peers to crawl")
            return

        random_peer = random.choice(self.get_peers())
        try:
            blk = await self.send_crawl_request(random_peer, random_peer.public_key.key_to_bin(), -1, -1)
            self.on_latest_block(random_peer, blk)
        except Exception as exc:
            self._logger.error("Exception occurred while crawling: %s" % exc)
            pass


class TrustChainBackwardsCrawlerCommunity(TrustChainCrawlerCommunity):
    """
    Backwards-compatible TrustChain community.
    """
    community_id = unhexlify('223eb544cd6c4814f4db710618b2ad5bc8b9d541')


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
        'level': "INFO"
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
            'class': 'TrustChainCrawlerCommunity',
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
        }, {
            'class': 'TrustChainBackwardsCrawlerCommunity',
            'key': "my peer",
            'walkers': [],
            'initialize': {
                'max_peers': -1,
                'settings': tc_settings,
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
        self.tc_persistence = None

    async def start_crawler(self, statedir, apiport, no_rest_api, testnet, yappi):
        """
        Main method to startup the TrustChain crawler.
        """

        # Open the database
        self.tc_persistence = TrustChainDB(statedir, 'trustchain')

        if statedir:
            # If we use a custom state directory, update various variables
            for key in crawler_config["keys"]:
                key["file"] = os.path.join(statedir, key["file"])

            for community in crawler_config["overlays"]:
                if community["class"] == "TrustChainCrawlerCommunity" or community["class"] == "TrustChainBackwardsCrawlerCommunity":
                    community["initialize"]["persistence"] = self.tc_persistence

        if testnet:
            for community in crawler_config["overlays"]:
                if community["class"] == "TrustChainCommunity":
                    community["class"] = "TrustChainTestnetCommunity"

        extra_communities = {
            "TrustChainCrawlerCommunity": TrustChainCrawlerCommunity,
            "TrustChainBackwardsCrawlerCommunity": TrustChainBackwardsCrawlerCommunity
        }
        self.ipv8 = IPv8(crawler_config, extra_communities=extra_communities)

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
    parser.add_argument('--statedir', '-s', default='.', type=str, help='Use an alternate statedir')
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
