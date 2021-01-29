import os
from asyncio import ensure_future, get_event_loop, sleep

from pyipv8.ipv8.community import Community
from pyipv8.ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from pyipv8.ipv8.lazy_community import lazy_wrapper, retrieve_cache
from pyipv8.ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from pyipv8.ipv8.requestcache import RandomNumberCache, RequestCache
from pyipv8.ipv8_service import IPv8


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


class MyCache(RandomNumberCache):
    name = "my-cache"

    def __init__(self, request_cache, value):
        super().__init__(request_cache, MyCache.name)
        self.value = value


class MyCommunity(Community):
    community_id = os.urandom(20)

    def __init__(self, my_peer, endpoint, network):
        super().__init__(my_peer, endpoint, network)
        self.add_message_handler(1, self.on_request)
        self.add_message_handler(2, self.on_response)

        # This is where the magic starts: add a ``request_cache`` variable.
        self.request_cache = RequestCache()

    async def unload(self):
        # Don't forget to shut down the RequestCache when you unload the Community!
        await self.request_cache.shutdown()
        await super().unload()

    def started(self):
        self.register_task("wait for peers and send a request", self.send)

    async def send(self):
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
    def on_request(self, peer, payload):
        # Our service is to increment the value of the request and send this in the response.
        self.ez_send(peer, MyResponse(payload.value + 1, payload.identifier))

    @lazy_wrapper(MyResponse)
    @retrieve_cache(MyCache)
    def on_response(self, peer, payload, cache):
        print(peer, "responded to:", cache.value, "with:", payload.value)

        # Stop the experiment if both peers reach a value of 10.
        if payload.value == 10:
            DONE.append(True)
            if len(DONE) == 2:
                get_event_loop().stop()
            return

        # Otherwise, do the same thing over again and ask for another increment.
        cache = self.request_cache.add(MyCache(self.request_cache, payload.value))
        if cache is not None:
            for peer in self.get_peers():
                self.ez_send(peer, MyRequest(payload.value, cache.number))
                # To spice things up, we'll perform a replay attack.
                # The RequestCache causes this second duplicate message to be ignored.
                self.ez_send(peer, MyRequest(payload.value, cache.number))


async def start_communities():
    for i in [1, 2]:
        builder = ConfigBuilder().clear_keys().clear_overlays()
        builder.add_key("my peer", "medium", f"ec{i}.pem")
        builder.add_overlay("MyCommunity", "my peer", [WalkerDefinition(Strategy.RandomWalk, 10, {'timeout': 3.0})],
                            default_bootstrap_defs, {}, [('started',)])
        await IPv8(builder.finalize(), extra_communities={'MyCommunity': MyCommunity}).start()


ensure_future(start_communities())
get_event_loop().run_forever()
