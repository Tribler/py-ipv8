from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Any, cast

from .tunnel import CIRCUIT_STATE_READY, PEER_FLAG_EXIT_IPV8

if TYPE_CHECKING:
    from ...types import Address
    from ..interfaces.endpoint import Endpoint
    from .community import TunnelCommunity


class TunnelEndpoint:
    """
    Endpoint implementation that routes all data through a TunnelCommunity.
    """

    def __init__(self, endpoint: Endpoint) -> None:
        """
        Create a new tunneled endpoint that uses the given endpoint for Internet communication.
        """
        super().__init__()

        self.endpoint = endpoint
        self.hops = 0
        self.tunnel_community: TunnelCommunity | None = None
        self.settings: dict[bytes, bool] = {}
        self.send_queue: deque[tuple[Address, bytes]] = deque(maxlen=100)

    def set_tunnel_community(self, tunnel_community: TunnelCommunity | None, hops: int = 1) -> None:
        """
        Configure this endpoint to create tunnels of a given number of hops over the given community.
        """
        self.tunnel_community = tunnel_community
        self.hops = hops

    def set_anonymity(self, prefix: bytes, enable: bool) -> None:
        """
        Enable or disable tunneling for the given community id.
        """
        self.settings[prefix] = enable

    def send(self, address: Address, packet: bytes) -> None:
        """
        Send the given packet to a certain address.
        """
        prefix = packet[:22]
        if not self.settings.get(prefix, False):
            self.endpoint.send(address, packet)
            return

        if self.tunnel_community is not None:
            tunnel_community = self.tunnel_community
            circuits = tunnel_community.find_circuits(exit_flags=[PEER_FLAG_EXIT_IPV8], hops=self.hops, state=None)
            circuit = circuits[0] if circuits else None
            if not circuit or circuit.state != CIRCUIT_STATE_READY:
                # Recreate tunnel when needed
                if not circuit:
                    tunnel_community.create_circuit(self.hops, exit_flags=[PEER_FLAG_EXIT_IPV8])
                self.send_queue.append((address, packet))
                return

            circuit_id = circuit.circuit_id
            tunnel_community.send_data(circuit.hop.address, circuit_id, address, ('0.0.0.0', 0), packet)

            # Any packets still need sending?
            while self.send_queue:
                address, packet = self.send_queue.popleft()
                tunnel_community.send_data(circuit.hop.address, circuit_id, address, ('0.0.0.0', 0), packet)

    def notify_listeners(self, packet: tuple[Address, bytes], from_tunnel: bool = False) -> None:
        """
        Ensure packets are only delivered if they follow they are properly encrypted.
        """
        for listener in self._listeners:
            # Anonymized communities should ignore traffic received from the socket
            # Non-anonymized communities should ignore traffic received from the TunnelCommunity
            if getattr(listener, 'anonymize', False) != from_tunnel:
                continue
            self._deliver_later(listener, packet)

    def __getattribute__(self, item: str) -> Any:  # noqa: ANN401
        """
        Forward anything that is not inside of this class to our wrapped endpoint.
        """
        try:
            return object.__getattribute__(self, item)
        except AttributeError:
            try:
                return object.__getattribute__(self.endpoint, item)
            except AttributeError:
                return object.__getattribute__(cast(TunnelEndpoint, self.endpoint).endpoint, item)
