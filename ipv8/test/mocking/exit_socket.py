from ..mocking.endpoint import AutoMockEndpoint
from ...messaging.anonymization.tunnel import DataChecker, TunnelExitSocket
from ...messaging.interfaces.endpoint import EndpointListener
from ...util import succeed


class MockTunnelExitSocket(TunnelExitSocket, EndpointListener):

    def __init__(self, parent):
        self.endpoint = AutoMockEndpoint()
        self.endpoint.open()

        TunnelExitSocket.__init__(self, parent.circuit_id, parent.peer, parent.overlay)
        EndpointListener.__init__(self, self.endpoint, main_thread=False)

        self.endpoint.add_listener(self)

    def enable(self):
        self.enabled = True

    def sendto(self, data, destination):
        if DataChecker.is_allowed(data):
            self.endpoint.send(destination, data)
        else:
            raise AssertionError("Attempted to exit data which is not allowed" % repr(data))

    def on_packet(self, packet):
        source_address, data = packet
        self.datagram_received(data, source_address)

    async def close(self):
        await self.shutdown_task_manager()
        return succeed(True)
