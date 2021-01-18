from asyncio import Future, TimeoutError as AsyncTimeoutError, get_event_loop, sleep, wait_for
from binascii import unhexlify
from os import environ
from random import randint
from socket import gethostbyname

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401

from ipv8.community import Community
from ipv8.configuration import DISPERSY_BOOTSTRAPPER, get_default_configuration
from ipv8.requestcache import NumberCache, RequestCache

from ipv8_service import IPv8


community_id = unhexlify(environ.get('INTRODUCTION_CID', '7e313685c1912a141279f8248fc8db5899c5df5a'))
count = int(environ.get('INTRODUCTION_COUNT', 100))
delay = int(environ.get('INTRODUCTION_DELAY', 10))


class MyCommunity(Community):
    community_id = community_id

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.request_cache = RequestCache()

    def send_intro_request(self, target_addr):
        packet = self.create_introduction_request(target_addr, new_style=self.network.is_new_style(target_addr))
        cache = NumberCache(self.request_cache, 'intro-req', self.global_time)
        cache.future = Future()
        self.request_cache.add(cache)
        self.endpoint.send(target_addr, packet)
        return cache.future

    def introduction_response_callback(self, peer, dist, payload):
        cache = self.request_cache.get('intro-req', payload.identifier)
        cache.future.set_result(payload)


async def main():
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
    introductions = {}
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
                response = await wait_for(overlay.send_intro_request((ip, dns_addr[1])), timeout=5)
            except AsyncTimeoutError:
                continue

            introductions[dns_addr] = introductions.get(dns_addr, [])
            introductions[dns_addr].append((response.wan_introduction_address, response.lan_introduction_address))
        await sleep(delay)

    with open('bootstrap_introductions.txt', 'w') as f:
        f.write('Address Peers Type')
        for dns_addr, responses in introductions.items():
            f.write(f"\n{dns_addr[0]}:{dns_addr[1]} {len([wan for wan, _ in responses if wan != ('0.0.0.0', 0)])} 0")
            f.write(f"\n{dns_addr[0]}:{dns_addr[1]} {len({wan for wan, _ in responses if wan != ('0.0.0.0', 0)})} 1")
            f.write(f"\n{dns_addr[0]}:{dns_addr[1]} {len({lan for _, lan in responses if lan != ('0.0.0.0', 0)})} 2")


if __name__ == "__main__":
    loop = get_event_loop()
    loop.run_until_complete(main())
