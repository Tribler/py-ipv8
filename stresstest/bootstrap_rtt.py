from __future__ import annotations

import os
import time
from asyncio import Event, run
from random import randint
from socket import gethostbyname
from typing import TYPE_CHECKING

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401

from ipv8.community import Community  # noqa: I001
from ipv8.configuration import DISPERSY_BOOTSTRAPPER, get_default_configuration
from ipv8.messaging.interfaces.udp.endpoint import UDPv4Address
from ipv8.requestcache import RequestCache, NumberCacheWithName
from ipv8.util import create_event_with_signals

from ipv8_service import IPv8, _COMMUNITIES

if TYPE_CHECKING:
    from ipv8.messaging.payload import IntroductionResponsePayload
    from ipv8.messaging.payload_headers import GlobalTimeDistributionPayload
    from ipv8.types import Address, Peer

RESULTS = {}

CONST_REQUESTS = 10


class MyCommunity(Community):
    """
    Community with a random id to send pings to bootstrap servers.
    """

    community_id = os.urandom(20)

    def __init__(self, *args: object, **kwargs) -> None:
        """
        Create a new measuring Community.
        """
        super().__init__(*args, **kwargs)
        self.event = None
        self.request_cache = RequestCache()
        self.check_queue = []

    async def unload(self) -> None:
        """
        Stop the request cache and unload.
        """
        await self.request_cache.shutdown()
        await super().unload()

    def finish_ping(self, cache: PingCache, include: bool = True) -> None:
        """
        Finish off a ping using a given cache. Potentially refrain from including an illegal time (timed out).
        """
        global RESULTS  # noqa: PLW0602
        print(cache.hostname, cache.address, time.time() - cache.starttime)  # noqa: T201
        if include:
            if (cache.hostname, cache.address) in RESULTS:
                RESULTS[(cache.hostname, cache.address)].append(time.time() - cache.starttime)
            else:
                RESULTS[(cache.hostname, cache.address)] = [time.time() - cache.starttime]
        elif (cache.hostname, cache.address) not in RESULTS:
            RESULTS[(cache.hostname, cache.address)] = []

        self.next_ping()

    def next_ping(self) -> None:
        """
        Send the next ping in line.
        """
        if self.check_queue:
            hostname, address = self.check_queue.pop()
            packet = self.create_introduction_request(UDPv4Address(*address))
            self.request_cache.add(PingCache(self, hostname, address, time.time()))
            self.endpoint.send(address, packet)
        elif self.event:
            self.event.set()

    def introduction_response_callback(self,
                                       peer: Peer,
                                       dist: GlobalTimeDistributionPayload,
                                       payload: IntroductionResponsePayload) -> None:
        """
        Got a response. Finish of any ping we might have sent to this peer.
        """
        if self.request_cache.has(PingCache, payload.identifier):
            self.finish_ping(self.request_cache.pop(PingCache, payload.identifier))

    def started(self, event: Event) -> None:
        """
        Perform DNS name resolution and start sending pings.

        :param event: The termination event.
        """
        self.event = event

        dnsmap = {}
        for (address, port) in DISPERSY_BOOTSTRAPPER['init']['dns_addresses']:
            try:
                ip = gethostbyname(address)
                dnsmap[(ip, port)] = address
            except OSError:
                pass

        unknown_name = '*'

        for (ip, port) in DISPERSY_BOOTSTRAPPER['init']['ip_addresses']:
            hostname = dnsmap.get((ip, port), None)
            if not hostname:
                hostname = unknown_name
                unknown_name = unknown_name + '*'
            self.check_queue.append((hostname, (ip, port)))

        self.check_queue = self.check_queue * CONST_REQUESTS

        self.next_ping()


class PingCache(NumberCacheWithName):
    """
    Cache for a single ping to a bootstrap server.
    """

    name = "introping"

    def __init__(self, community: MyCommunity, hostname: str, address: Address, starttime: float) -> None:
        """
        Create a new cache for the ping information.
        """
        super().__init__(community.request_cache, self.name, community.global_time)
        self.hostname = hostname
        self.address = address
        self.starttime = starttime
        self.community = community

    @property
    def timeout_delay(self) -> float:
        """
        Wait 5 seconds to timeout.
        """
        return 5.0

    def on_timeout(self) -> None:
        """
        Finish off the ping in the Community with the failed state.
        """
        self.community.finish_ping(self, False)


_COMMUNITIES['MyCommunity'] = MyCommunity


async def start_communities() -> None:
    """
    Start an IPv8 instance for our measuring Community.
    """
    event = create_event_with_signals()
    configuration = get_default_configuration()
    configuration['keys'] = [{
        'alias': "my peer",
        'generation': "medium",
        'file': "ec1.pem"
    }]
    configuration['port'] = 12000 + randint(0, 10000)
    configuration['overlays'] = [{
        'class': 'MyCommunity',
        'key': "my peer",
        'walkers': [],
        'bootstrappers': [DISPERSY_BOOTSTRAPPER],
        'initialize': {},
        'on_start': [('started', event)]
    }]
    ipv8_instance = IPv8(configuration)
    await ipv8_instance.start()
    await event.wait()
    await ipv8_instance.stop()


run(start_communities())

with open('summary.txt', 'w') as f:
    f.write('HOST_NAME ADDRESS REQUESTS RESPONSES')
    for key in RESULTS:
        r_hostname, r_address = key
        f.write('\n%s %s:%d %d %d' % (r_hostname, r_address[0], r_address[1], CONST_REQUESTS, len(RESULTS[key])))

with open('walk_rtts.txt', 'w') as f:
    f.write('HOST_NAME ADDRESS RTT')
    for key in RESULTS:
        r_hostname, r_address = key
        for rtt in RESULTS[key]:
            f.write('\n%s %s:%d %f' % (r_hostname, r_address[0], r_address[1], rtt))
