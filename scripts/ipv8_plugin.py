"""
This script enables to start IPv8 headless.
"""
import argparse
import signal
import ssl
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

from ipv8_service import IPv8


class IPV8Service(object):

    def __init__(self):
        """
        Initialize the variables of the IPV8ServiceMaker and the logger.
        """
        self.ipv8 = None
        self.restapi = None
        self._stopping = False

    async def start_ipv8(self, statistics, no_rest_api, api_key, cert_file):
        """
        Main method to startup IPv8.
        """
        self.ipv8 = IPv8(get_default_configuration(), enable_statistics=statistics)
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


def main(argv):
    parser = argparse.ArgumentParser(description='Starts IPv8 as a service')
    parser.add_argument('--statistics', '-s', action='store_true', help='Enable IPv8 overlay statistics')
    parser.add_argument('--no-rest-api', '-a', action='store_true', help='Autonomous: disable the REST api')
    parser.add_argument('--api-key', '-k', help='API key to use. If not given API key protection is disabled.')
    parser.add_argument('--cert-file', '-c', help='Path to combined certificate/key file. If not given HTTP is used.')

    args = parser.parse_args(sys.argv[1:])
    service = IPV8Service()

    loop = get_event_loop()
    coro = service.start_ipv8(args.statistics, args.no_rest_api, args.api_key, args.cert_file)
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
