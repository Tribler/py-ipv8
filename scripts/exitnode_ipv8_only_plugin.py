"""
This script enables to start IPv8 headless.

For error reporting Sentry is used.
If sentry-sdk is not installed or SENTRY_URL is not defined, then no reports
will be sent.

Prerequisites:
    python -m pip install sentry-sdk

Configuring Sentry:
    nix:
    ```
        EXPORT SENTRY_URL=<sentry_url>
    ```
    windows:
    ```
        SETX SENTRY_URL <sentry_url>
    ```
"""
import argparse
import os
import signal
import sys
from asyncio import all_tasks, ensure_future, gather, get_event_loop, sleep

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401

from ipv8.REST.rest_manager import RESTManager
from ipv8.configuration import get_default_configuration
from ipv8.messaging.anonymization.tunnel import PEER_FLAG_EXIT_IPV8

from ipv8_service import IPv8


class ExitnodeIPv8Service(object):

    def __init__(self):
        """
        Initialize the variables of the IPV8Service and the logger.
        """
        self.ipv8 = None
        self.restapi = None
        self._stopping = False
        self.tc_persistence = None

    async def start_ipv8(self, statedir, listen_port, statistics, no_rest_api, max_bps):
        """
        Main method to startup IPv8.
        """
        configuration = get_default_configuration()
        configuration['port'] = listen_port

        if statedir:
            # If we use a custom state directory, update various variables
            for key in configuration["keys"]:
                key["file"] = os.path.join(statedir, key["file"])

        allowed_overlays = ['DHTDiscoveryCommunity', 'DiscoveryCommunity', 'HiddenTunnelCommunity']
        configuration['overlays'] = [overlay for overlay in configuration['overlays']
                                     if overlay['class'] in allowed_overlays]

        for overlay in configuration['overlays']:
            if overlay['class'] == 'HiddenTunnelCommunity':
                overlay['initialize']['settings']['min_circuits'] = 0
                overlay['initialize']['settings']['max_circuits'] = 0
                overlay['initialize']['settings']['max_joined_circuits'] = 1000
                overlay['initialize']['settings']['peer_flags'] = {PEER_FLAG_EXIT_IPV8}
                overlay['initialize']['settings']['max_exit_bps'] = max_bps

        self.ipv8 = IPv8(configuration, enable_statistics=statistics)
        await self.ipv8.start()

        async def signal_handler(sig):
            print("Received shut down signal %s" % sig)
            if not self._stopping:
                self._stopping = True
                if self.restapi:
                    await self.restapi.stop()
                await self.ipv8.stop()
                await gather(*all_tasks())
                get_event_loop().stop()

        signal.signal(signal.SIGINT, lambda sig, _: ensure_future(signal_handler(sig)))
        signal.signal(signal.SIGTERM, lambda sig, _: ensure_future(signal_handler(sig)))

        print("Starting IPv8")

        if not no_rest_api:
            self.restapi = RESTManager(self.ipv8)
            await self.restapi.start()


def main(argv):
    parser = argparse.ArgumentParser(add_help=False, description=('IPv8-only exit node plugin'))
    parser.add_argument('--help', '-h', action='help', default=argparse.SUPPRESS, help='Show this help message and exit')
    parser.add_argument('--listen_port', '-p', default=8090, type=int, help='Use an alternative port')
    parser.add_argument('--no_rest_api', '-a', action='store_const', default=False, const=True, help='Autonomous: disable the REST api')
    parser.add_argument('--statedir', default='.', type=str, help='Use an alternate statedir')
    parser.add_argument('--statistics', '-s', action='store_const', default=False, const=True, help='Enable IPv8 overlay statistics')
    parser.add_argument('--max_bps', '-b', default=0, type=int, help='Maximum bytes per second for exiting traffic.')

    args = parser.parse_args(sys.argv[1:])
    service = ExitnodeIPv8Service()

    loop = get_event_loop()
    coro = service.start_ipv8(args.statedir, args.listen_port, args.statistics, args.no_rest_api, args.max_bps)
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
    try:
        import sentry_sdk
        # If no SENTRY_URL is defined, then no reports are sent
        sentry_sdk.init(os.environ.get('SENTRY_URL'), traces_sample_rate=1.0)
    except ImportError:
        print('sentry-sdk is not installed. To install sentry-sdk run `pip install sentry-sdk`')

    main(sys.argv[1:])
