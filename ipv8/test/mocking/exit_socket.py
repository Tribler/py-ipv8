from __future__ import absolute_import

from twisted.internet.defer import succeed

from ...messaging.interfaces.endpoint import EndpointListener
from ...messaging.anonymization.tunnel import DataChecker, TunnelExitSocket
from ..mocking.endpoint import AutoMockEndpoint


class MockTunnelExitSocket(TunnelExitSocket, EndpointListener):

    def __init__(self, parent):
        self.endpoint = AutoMockEndpoint()
        self.endpoint.open()

        TunnelExitSocket.__init__(self, parent.circuit_id, parent.peer, parent.overlay)
        parent.close()
        EndpointListener.__init__(self, self.endpoint, main_thread=False)

        self.endpoint.add_listener(self)

    def enable(self):
        pass

    @property
    def enabled(self):
        return True

    def sendto(self, data, destination):
        if DataChecker.is_allowed(data):
            self.endpoint.send(destination, data)
        else:
            raise AssertionError("Attempted to exit data which is not allowed" % repr(data))

    def on_packet(self, packet):
        source_address, data = packet
        self.datagramReceived(data, source_address)

    def close(self):
        self.shutdown_task_manager()
        return succeed(True)
