from __future__ import annotations

from typing import TYPE_CHECKING

from ...messaging.anonymization.exit_socket import DataChecker, TunnelExitSocket
from ...messaging.interfaces.endpoint import EndpointListener
from ..mocking.endpoint import AutoMockEndpoint

if TYPE_CHECKING:
    from ...types import Address


class MockTunnelExitSocket(TunnelExitSocket, EndpointListener):
    """
    Mocked TunnelExitsocket that uses a mock endpoint.
    """

    def __init__(self, parent: TunnelExitSocket) -> None:
        """
        Wrap a tunnel exit socket to route it through the fake IPv8-only internet.
        """
        self.endpoint = AutoMockEndpoint()
        self.endpoint.open()
        self.parent = parent

        TunnelExitSocket.__init__(self, parent.circuit_id, parent.hop, parent.overlay)
        EndpointListener.__init__(self, self.endpoint, main_thread=False)

        self.endpoint.add_listener(self)

    def enable(self) -> None:
        """
        Set this exit node to enabled.
        """
        self.enabled = True

    def sendto(self, data: bytes, destination: Address) -> None:
        """
        Send data through to another mock endpoint's address.
        """
        if DataChecker.could_be_bt(data) or DataChecker.could_be_ipv8(data):
            self.endpoint.send(destination, data)
        else:
            raise AssertionError("Attempted to exit data which is not allowed: %s" % repr(data))

    def on_packet(self, packet: tuple[Address, bytes]) -> None:
        """
        Callback for when data is received.
        """
        source_address, data = packet
        self.datagram_received(data, source_address)

    async def close(self) -> None:
        """
        Close our fake exit socket.
        """
        await self.shutdown_task_manager()
        await self.parent.close()
