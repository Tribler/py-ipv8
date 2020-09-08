from ..mocking.endpoint import AutoMockEndpoint
from ...messaging.anonymization.tunnel import DataChecker, TunnelExitSocket
from ...messaging.interfaces.endpoint import EndpointListener


class MockTunnelExitSocket(TunnelExitSocket, EndpointListener):

    def __init__(self, parent):
        self.endpoint = AutoMockEndpoint()
        self.endpoint.open()
        self.parent = parent

        TunnelExitSocket.__init__(self, parent.circuit_id, parent.peer, parent.overlay)
        EndpointListener.__init__(self, self.endpoint, main_thread=False)

        self.endpoint.add_listener(self)

    def enable(self):
        self.enabled = True

    def sendto(self, data, destination):
        if DataChecker.could_be_bt(data) or DataChecker.could_be_ipv8(data):
            self.endpoint.send(destination, data)
        else:
            raise AssertionError("Attempted to exit data which is not allowed: %s" % repr(data))

    def on_packet(self, packet):
        source_address, data = packet
        self.datagram_received(data, source_address)

    async def close(self):
        await self.shutdown_task_manager()
        await self.parent.close()
