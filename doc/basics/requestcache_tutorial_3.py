import os
from asyncio import run, sleep

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper, retrieve_cache
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.requestcache import RandomNumberCacheWithName, RequestCache
from ipv8.types import Peer
from ipv8_service import IPv8

# We'll use this global variable to keep track of the IPv8 instances that finished.
DONE = []


@vp_compile
class MyRequest(VariablePayload):
    msg_id = 1
    format_list = ['I', 'I']
    names = ["value", "identifier"]


@vp_compile
class MyResponse(VariablePayload):
    msg_id = 2
    format_list = ['I', 'I']
    names = ["value", "identifier"]


class MyCache(RandomNumberCacheWithName):
    name = "my-cache"

    def __init__(self, request_cache: RequestCache, value: int) -> None:
        super().__init__(request_cache, self.name)
        self.value = value


class MyCommunity(Community):
    community_id = os.urandom(20)

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(1, self.on_request)
        self.add_message_handler(2, self.on_response)

        # This is where the magic starts: add a ``request_cache`` variable.
        self.request_cache = RequestCache()

    async def unload(self) -> None:
        # Don't forget to shut down the RequestCache when you unload the Community!
        await self.request_cache.shutdown()
        await super().unload()

    def started(self) -> None:
        self.register_task("wait for peers and send a request", self.send)

    async def send(self) -> None:
        # Wait for our local peers to connect to eachother.
        while not self.get_peers():
            await sleep(0.1)
        # Then, create and register our cache.
        cache = self.request_cache.add(MyCache(self.request_cache, 0))
        # If the overlay is shutting down the cache will be None.
        if cache is not None:
            # Finally, send the overlay message to the other peer.
            for peer in self.get_peers():
                self.ez_send(peer, MyRequest(cache.value, cache.number))

    @lazy_wrapper(MyRequest)
    def on_request(self, peer: Peer, payload: MyRequest) -> None:
        # Our service is to increment the value of the request and send this in the response.
        self.ez_send(peer, MyResponse(payload.value + 1, payload.identifier))

    @lazy_wrapper(MyResponse)
    @retrieve_cache(MyCache)
    def on_response(self, peer: Peer, payload: MyResponse, cache: MyCache) -> None:
        print(peer, "responded to:", cache.value, "with:", payload.value)

        # Stop the experiment if both peers reach a value of 10.
        if payload.value == 10:
            DONE.append(True)
            return

        # Otherwise, do the same thing over again and ask for another increment.
        cache = self.request_cache.add(MyCache(self.request_cache, payload.value))
        if cache is not None:
            for peer in self.get_peers():
                self.ez_send(peer, MyRequest(payload.value, cache.number))
                # To spice things up, we'll perform a replay attack.
                # The RequestCache causes this second duplicate message to be ignored.
                self.ez_send(peer, MyRequest(payload.value, cache.number))


async def start_communities() -> None:
    for i in [1, 2]:
        builder = ConfigBuilder().clear_keys().clear_overlays()
        builder.add_key("my peer", "medium", f"ec{i}.pem")
        builder.add_overlay("MyCommunity", "my peer", [WalkerDefinition(Strategy.RandomWalk, 10, {'timeout': 3.0})],
                            default_bootstrap_defs, {}, [('started',)])
        await IPv8(builder.finalize(), extra_communities={'MyCommunity': MyCommunity}).start()

    while len(DONE) < 2:
        await sleep(1)


run(start_communities())
