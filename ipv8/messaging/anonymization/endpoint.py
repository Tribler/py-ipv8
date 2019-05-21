from __future__ import absolute_import
from __future__ import division

import time
from collections import deque

from twisted.internet import reactor

from .tunnel import CIRCUIT_STATE_CLOSING, CIRCUIT_STATE_READY


class TunnelEndpoint(object):

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.hops = 0
        self.destinations = {}
        self.destinations_cleanup = time.time()
        self.tunnel_community = None
        self.settings = {}
        self.send_queue = deque(maxlen=100)

    def set_tunnel_community(self, tunnel_community, hops=1, circuits=1):
        self.tunnel_community = tunnel_community
        self.tunnel_community.circuits_needed[hops] = circuits
        self.hops = hops

    def set_anonymity(self, prefix, enable):
        self.settings[prefix] = enable

    def send(self, address, packet):
        prefix = packet[:22]
        if not self.settings.get(prefix, False):
            self.endpoint.send(address, packet)
            return

        # Cleanup destinations
        if self.destinations_cleanup + 300 < time.time():
            self.destinations = {addr: c for addr, c in self.destinations.items() if c.ctype != CIRCUIT_STATE_CLOSING}

        if self.tunnel_community:
            circuit = self.destinations.get(address)
            if not circuit or circuit.state != CIRCUIT_STATE_READY:
                circuit = self.tunnel_community.select_circuit(address, self.hops)
                if not circuit:
                    self.send_queue.append((address, packet))
                    return
                self.destinations[address] = circuit

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
            if listener.use_main_thread:
                reactor.callFromThread(self._deliver_later, listener, packet)
            elif reactor.running:
                reactor.callInThread(self._deliver_later, listener, packet)

    def __getattribute__(self, item):
        try:
            return object.__getattribute__(self, item)
        except AttributeError:
            try:
                return object.__getattribute__(self.endpoint, item)
            except AttributeError:
                return object.__getattribute__(self.endpoint.endpoint, item)
