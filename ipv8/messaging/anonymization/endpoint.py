from collections import deque

from .tunnel import CIRCUIT_STATE_READY, CIRCUIT_TYPE_IPV8


class TunnelEndpoint(object):

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.hops = 0
        self.tunnel_community = None
        self.settings = {}
        self.send_queue = deque(maxlen=100)

    def set_tunnel_community(self, tunnel_community, hops=1):
        self.tunnel_community = tunnel_community
        self.hops = hops

    def set_anonymity(self, prefix, enable):
        self.settings[prefix] = enable

    def send(self, address, packet):
        prefix = packet[:22]
        if not self.settings.get(prefix, False):
            self.endpoint.send(address, packet)
            return

        if self.tunnel_community:
            circuits = self.tunnel_community.find_circuits(ctype=CIRCUIT_TYPE_IPV8, hops=self.hops, state=None)
            circuit = circuits[0] if circuits else None
            if not circuit or circuit.state != CIRCUIT_STATE_READY:
                # Recreate tunnel when needed
                if not circuit:
                    self.tunnel_community.create_circuit(self.hops, ctype=CIRCUIT_TYPE_IPV8)
                self.send_queue.append((address, packet))
                return

            circuit_address = circuit.peer.address
            circuit_id = circuit.circuit_id
            self.tunnel_community.send_data((circuit_address,), circuit_id, address, ('0.0.0.0', 0), packet)

            # Any packets still need sending?
            while self.send_queue:
                address, packet = self.send_queue.popleft()
                self.tunnel_community.send_data((circuit_address,), circuit_id, address, ('0.0.0.0', 0), packet)

    def notify_listeners(self, packet, from_tunnel=False):
        for listener in self._listeners:
            # Anonymized communities should ignore traffic received from the socket
            # Non-anonymized communities should ignore traffic received from the TunnelCommunity
            if getattr(listener, 'anonymize', False) != from_tunnel:
                continue
            self._deliver_later(listener, packet)

    def __getattribute__(self, item):
        try:
            return object.__getattribute__(self, item)
        except AttributeError:
            try:
                return object.__getattribute__(self.endpoint, item)
            except AttributeError:
                return object.__getattribute__(self.endpoint.endpoint, item)
