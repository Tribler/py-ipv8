from ipv8.test.mocking.endpoint import AutoMockEndpoint
from ipv8.util import succeed


class SimulationEndpoint(AutoMockEndpoint):
    """
    Endpoint used in a simulated IPv8 environment. We make the open function async since this is expected by
    the IPv8 service.
    """

    async def open(self):
        self._open = True
        return succeed(None)
