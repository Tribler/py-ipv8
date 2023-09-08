"""
This script enables to start IPv8 headless.
"""
from __future__ import annotations

import argparse
import ssl
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
from ipv8.REST.rest_manager import RESTManager
from ipv8.util import run_forever
from ipv8_service import IPv8


class IPV8Service:
    """
    Service to orchestrate an IPv8 instance and a REST API.
    """

    def __init__(self) -> None:
        """
        Initialize the variables of the IPV8Service.
        """
        self.ipv8 = None
        self.restapi = None

    async def start_ipv8(self, statistics: bool, no_rest_api: bool, api_key: str | None, cert_file: str) -> None:
        """
        Main method to startup IPv8.
        """
        print("Starting IPv8")  # noqa: T201

        self.ipv8 = IPv8(get_default_configuration(), enable_statistics=statistics)
        await self.ipv8.start()

        if not no_rest_api:
            # Load the certificate/key file. A new one can be generated as follows:
            # openssl req \
            #     -newkey rsa:2048 -nodes -keyout private.key \
            #     -x509 -days 365 -out certfile.pem
            # cat private.key >> certfile.pem
            # rm private.key
            ssl_context = None
            if cert_file:
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_context.load_cert_chain(cert_file)

            self.restapi = RESTManager(self.ipv8)
            await self.restapi.start(api_key=api_key, ssl_context=ssl_context)

    async def stop_ipv8(self) -> None:
        """
        Stop the service.
        """
        print("Stopping IPv8")  # noqa: T201

        if self.restapi:
            await self.restapi.stop()
        if self.ipv8:
            await self.ipv8.stop()


async def main(argv: list[str]) -> None:
    """
    Create a service to run IPv8 and a REST API from some given commandline arguments.
    """
    parser = argparse.ArgumentParser(description='Starts IPv8 as a service')
    parser.add_argument('--statistics', '-s', action='store_true', help='Enable IPv8 overlay statistics')
    parser.add_argument('--no-rest-api', '-a', action='store_true', help='Autonomous: disable the REST api')
    parser.add_argument('--api-key', '-k', help='API key to use. If not given API key protection is disabled.')
    parser.add_argument('--cert-file', '-c', help='Path to combined certificate/key file. If not given HTTP is used.')

    args = parser.parse_args(sys.argv[1:])
    service = IPV8Service()

    await service.start_ipv8(args.statistics, args.no_rest_api, args.api_key, args.cert_file)
    await run_forever()
    await service.stop_ipv8()


if __name__ == "__main__":
    run(main(sys.argv[1:]))
