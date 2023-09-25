from asyncio import Event, Future, run, sleep, wait_for
from asyncio import TimeoutError as AsyncTimeoutError
from binascii import unhexlify
from os import environ
from random import randint
from socket import gethostbyname
from typing import cast

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401

from ipv8.community import Community, DEFAULT_MAX_PEERS  # noqa: I001
from ipv8.configuration import DISPERSY_BOOTSTRAPPER, get_default_configuration
from ipv8.messaging.payload import IntroductionResponsePayload
from ipv8.messaging.payload_headers import GlobalTimeDistributionPayload
from ipv8.peerdiscovery.network import Network
from ipv8.requestcache import NumberCache, RequestCache
from ipv8.types import Address, Endpoint, Peer
from ipv8.util import create_event_with_signals
from ipv8_service import IPv8


community_id = unhexlify(environ.get('INTRODUCTION_CID', '7e313685c1912a141279f8248fc8db5899c5df5a'))
count = int(environ.get('INTRODUCTION_COUNT', 100))
delay = int(environ.get('INTRODUCTION_DELAY', 10))


class MyCommunity(Community):
    """
    Community to resolve and ping all bootstrap node IPs.
    """

    community_id = community_id

    def __init__(self, my_peer: Peer, endpoint: Endpoint, network: Network,
                 max_peers: int = DEFAULT_MAX_PEERS, anonymize: bool = False) -> None:
        """
        Create a new community for testing.
        """
        super().__init__(my_peer, endpoint, network, max_peers, anonymize)
        self.request_cache = RequestCache()

    def send_intro_request(self, target_addr: Address) -> Future[IntroductionResponsePayload]:
        """
        Send an introduction request and create a future that fires with the corresponding response.
        """
        packet = self.create_introduction_request(target_addr, new_style=self.network.is_new_style(target_addr))
        cache = NumberCache(self.request_cache, 'intro-req', self.global_time)
        cache.future = Future()
        self.request_cache.add(cache)
        self.endpoint.send(target_addr, packet)
        return cache.future

    def introduction_response_callback(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                       payload: IntroductionResponsePayload) -> None:
        """
        Callback for when we receive any introduction response.
        """
        if self.request_cache.has('intro-req', payload.identifier):
            cache = self.request_cache.pop('intro-req', payload.identifier)
            future = cast(Future[IntroductionResponsePayload], cache)
            if not future.done():
                future.set_result(payload)

    async def run_test(self, event: Event) -> None:
        """
        Resolve all bootstrap DNS addresses and sequentially contact all bootstrap nodes.
        """
        self.introductions = {}
        ips = {}
        for _ in range(count):
            for dns_addr in DISPERSY_BOOTSTRAPPER['init']['dns_addresses']:
                if 'tribler.org' not in dns_addr[0] and 'ip-v8.org' not in dns_addr[0]:
                    continue

                try:
                    ip = ips.get(dns_addr[0], gethostbyname(dns_addr[0]))
                except OSError:
                    continue

                try:
                    response = await wait_for(self.send_intro_request((ip, dns_addr[1])), timeout=5)
                except AsyncTimeoutError:
                    continue

                reachable = False
                try:
                    if response.wan_introduction_address != ('0.0.0.0', 0):
                        # Wait some time for puncture to be sent
                        await sleep(.1)
                        await wait_for(self.send_intro_request(response.wan_introduction_address), timeout=5)
                        reachable = True
                except AsyncTimeoutError:
                    pass

                self.introductions[dns_addr] = self.introductions.get(dns_addr, [])
                self.introductions[dns_addr].append([response.wan_introduction_address,
                                                     response.lan_introduction_address,
                                                     reachable])

            await sleep(delay)
        event.set()

    async def unload(self) -> None:
        """
        Shut down the request cache.
        """
        await self.request_cache.shutdown()
        await super().unload()


async def main() -> None:
    """
    Collect all the bootstrap node IPs, then resolve the bootstrap node DNS addresses and then determine their RTT.
    """
    event = create_event_with_signals()
    configuration = get_default_configuration()
    configuration['keys'] = [{
        'alias': "my peer",
        'generation': "curve25519",
        'file': "ec.pem"
    }]
    configuration['port'] = 12000 + randint(0, 10000)
    configuration['overlays'] = []

    ipv8 = IPv8(configuration)
    await ipv8.start()
    overlay = MyCommunity(ipv8.keys['my peer'], ipv8.endpoint, ipv8.network)
    overlay.register_task('run_test', overlay.run_test, event)
    ipv8.overlays.append(overlay)
    await event.wait()
    await ipv8.stop()

    with open('bootstrap_introductions.txt', 'w') as f:  # noqa: ASYNC101
        f.write('Address Peers Type')
        for dns_addr, responses in overlay.introductions.items():
            f.write(f"\n{dns_addr[0]}:{dns_addr[1]} {len([wan for wan, _, _ in responses if wan != ('0.0.0.0', 0)])} 0")
            f.write(f"\n{dns_addr[0]}:{dns_addr[1]} {len({wan for wan, _, _ in responses if wan != ('0.0.0.0', 0)})} 1")
            f.write(f"\n{dns_addr[0]}:{dns_addr[1]} {len({lan for _, lan, _ in responses if lan != ('0.0.0.0', 0)})} 3")
            f.write(f"\n{dns_addr[0]}:{dns_addr[1]} {len({wan for wan, _, reachable in responses if reachable})} 2")


if __name__ == "__main__":
    run(main())
