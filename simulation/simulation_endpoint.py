from asyncio import get_event_loop
from collections import defaultdict

from ipv8.test.mocking.endpoint import AutoMockEndpoint
from ipv8.util import succeed


class SimulationEndpoint(AutoMockEndpoint):
    """
    Endpoint used in a simulated IPv8 environment. We make the open function async since this is expected by
    the IPv8 service.
    """

    def __init__(self):
        super().__init__()
        self.latencies = defaultdict(int)

    async def open(self):
        self._open = True
        return succeed(None)

    def get_link_latency(self, to_address):
        """
        Return the link latency to a particular destination address, in seconds.
        """
        return self.latencies[to_address]

    def send(self, socket_address, packet):
        get_event_loop().call_later(self.get_link_latency(socket_address), super().send,
                                    socket_address, packet)
