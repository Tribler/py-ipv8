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
from __future__ import annotations

import argparse
import os
import sys
from asyncio import run

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401

from ipv8.configuration import get_default_configuration
from ipv8.messaging.anonymization.tunnel import PEER_FLAG_EXIT_IPV8
from ipv8.messaging.interfaces.dispatcher.endpoint import INTERFACES
from ipv8.REST.rest_manager import RESTManager
from ipv8.util import run_forever
from ipv8_service import IPv8


class ExitnodeIPv8Service:
    """
    Exit node service that only allows IPv8 community data to be exited.
    """

    def __init__(self) -> None:
        """
        Initialize the variables of the IPV8Service and the logger.
        """
        self.ipv8 = None
        self.restapi = None
        self.tc_persistence = None

    async def start_ipv8(self, statedir: str | None, listen_port: int, statistics: bool, no_rest_api: bool) -> None:
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
                overlay['initialize']['min_circuits'] = 0
                overlay['initialize']['max_circuits'] = 0
                overlay['initialize']['max_joined_circuits'] = 1000
                overlay['initialize']['peer_flags'] = {PEER_FLAG_EXIT_IPV8}

        try:
            from ipv8_rust_tunnels.endpoint import RustEndpoint as UDPEndpoint
        except ImportError:
            from ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint

        INTERFACES["UDPIPv4"] = UDPEndpoint

        print("Starting IPv8")  # noqa: T201

        self.ipv8 = IPv8(configuration, enable_statistics=statistics)
        await self.ipv8.start()

        if not no_rest_api:
            self.restapi = RESTManager(self.ipv8)
            await self.restapi.start()

    async def stop_ipv8(self) -> None:
        """
        Stop IPv8 and its REST API.
        """
        print("Stopping IPv8")  # noqa: T201

        if self.restapi:
            await self.restapi.stop()
        if self.ipv8:
            await self.ipv8.stop()


async def main(argv: list[str]) -> None:
    """
    Start an IPv8 exit service with some given commandline arguments.
    """
    parser = argparse.ArgumentParser(add_help=False, description=('IPv8-only exit node plugin'))
    parser.add_argument('--help', '-h', action='help', default=argparse.SUPPRESS, help='Show this help message and exit')
    parser.add_argument('--listen_port', '-p', default=8090, type=int, help='Use an alternative port')
    parser.add_argument('--no_rest_api', '-a', action='store_const', default=False, const=True, help='Autonomous: disable the REST api')
    parser.add_argument('--statedir', default='.', type=str, help='Use an alternate statedir')
    parser.add_argument('--statistics', '-s', action='store_const', default=False, const=True, help='Enable IPv8 overlay statistics')

    args = parser.parse_args(sys.argv[1:])
    service = ExitnodeIPv8Service()

    await service.start_ipv8(args.statedir, args.listen_port, args.statistics, args.no_rest_api)
    await run_forever()
    await service.stop_ipv8()


if __name__ == "__main__":
    try:
        import sentry_sdk
        # If no SENTRY_URL is defined, then no reports are sent
        sentry_sdk.init(os.environ.get('SENTRY_URL'), traces_sample_rate=1.0)
    except ImportError:
        print('sentry-sdk is not installed. To install sentry-sdk run `pip install sentry-sdk`')  # noqa: T201

    run(main(sys.argv[1:]))
