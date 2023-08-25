from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from ...messaging.interfaces.endpoint import EndpointListener
from .network_stats import NetworkStat

if TYPE_CHECKING:
    from ...types import Address, Endpoint


class StatisticsEndpoint(EndpointListener):
    """
    This class is responsible for keeping stats regarding community.
    The stats are basically of the messages that the community can handle.

    This endpoint acts both as wrapper for IPv8 Endpoint, and EndpointListener.
    It inherits from EndpointListener directly and implements on_packet(self, packet)
    to measure statistics about received data. But, all the functionality of Endpoint
    itself is delegated to the existing IPv8 UDPEndpoint.
    """

    IDS_INTRODUCTION = [245, 246]
    IDS_PUNCTURE = [249, 250]
    IDS_DEPRECATED = [235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 247, 248, 251, 252, 253, 254, 255]

    def __init__(self, endpoint: Endpoint) -> None:
        """
        Create a new statistics endpoint decorator for the given endpoint.
        """
        EndpointListener.__init__(self, endpoint)
        self.endpoint = endpoint
        self.endpoint.add_listener(self)
        self.statistics: dict[bytes, dict] = {}

    def __getattribute__(self, item: str) -> Any:  # noqa: ANN401
        """
        Forward any non-intercepted call from this decorator directly to the underlying endpoint.
        """
        try:
            return object.__getattribute__(self, item)
        except AttributeError:
            return object.__getattribute__(self.endpoint, item)

    # Endpoint methods
    def send(self, socket_address: Address, packet: bytes) -> None:
        """
        Send the packet to an address and update our stats if we are tracking the packet's prefix.
        """
        self.endpoint.send(socket_address, packet)

        prefix = packet[:22]
        if prefix not in list(self.statistics.keys()) or len(packet) < 22:
            return

        self.add_sent_stat(prefix, packet[22], len(packet))

    def enable_community_statistics(self, community_prefix: bytes, enabled: bool) -> None:
        """
        Start tracking stats for packets with the given prefix.
        """
        if community_prefix not in self.statistics and enabled:
            self.statistics[community_prefix] = {}
        elif community_prefix in self.statistics and not enabled:
            self.statistics.pop(community_prefix)

    # EndpointListener methods
    def on_packet(self, packet: tuple[Address, bytes]) -> None:
        """
        Callback for when a packet is received through our underlying endpoint.
        """
        _, data = packet

        prefix = data[:22]
        if prefix not in list(self.statistics.keys()) or len(data) < 22:
            return

        message_id = data[22]
        self.add_received_stat(prefix, message_id, len(data))

    # Statistics methods
    def add_sent_stat(self, prefix: bytes, identifier: int, num_bytes: int, timestamp: float | None = None) -> None:
        """
        Update the sending stats of a given prefix and message identifier.
        """
        if prefix not in self.statistics:
            self.statistics[prefix] = {}
        if identifier not in self.statistics[prefix]:
            self.statistics[prefix][identifier] = NetworkStat(identifier)
        self.statistics[prefix][identifier].add_sent_stat(timestamp if timestamp else time.time(), num_bytes)

    def add_received_stat(self, prefix: bytes, identifier: int, num_bytes: int, timestamp: float | None = None) -> None:
        """
        Update the receiving stats of a given prefix and message identifier.
        """
        if prefix not in self.statistics:
            self.statistics[prefix] = {}
        if identifier not in self.statistics[prefix]:
            self.statistics[prefix][identifier] = NetworkStat(identifier)
        self.statistics[prefix][identifier].add_received_stat(timestamp if timestamp else time.time(), num_bytes)

    def get_statistics(self, prefix: bytes) -> dict[int, NetworkStat]:
        """
        Get the message statistics per message identifier for the given prefix.
        """
        if prefix in self.statistics:
            return self.statistics[prefix]
        return {}

    def get_aggregate_statistics(self, prefix: bytes) -> dict[str, int | float]:
        """
        Add all the individual message statistics together for a given prefix.
        """
        def min_positive(a: float, b: float) -> float:
            return a if not b else b if b < a or not a else a

        aggregate_stats = {
            "num_up": 0,
            "num_down": 0,
            "bytes_up": 0,
            "bytes_down": 0,
            "diff_time": 0.0
        }

        if prefix in self.statistics:
            first_ts = last_ts = 0.0
            for network_stat in self.statistics[prefix].values():
                aggregate_stats['num_up'] += network_stat.num_up
                aggregate_stats['num_down'] += network_stat.num_down
                aggregate_stats['bytes_up'] += network_stat.bytes_up
                aggregate_stats['bytes_down'] += network_stat.bytes_down

                first_ts = min_positive(first_ts, min_positive(network_stat.first_measured_up,
                                                               network_stat.first_measured_down))
                last_ts = max(last_ts, network_stat.last_measured_up, network_stat.last_measured_down)

            aggregate_stats["diff_time"] = last_ts - first_ts
        return aggregate_stats

    def get_message_sent(self, prefix: bytes, include_introduction: bool = False, include_puncture: bool = False,
                         include_deprecated: bool = False) -> int:
        """
        Calculate the number of sent messages for a given community prefix.
        """
        num_sent = 0
        if prefix in self.statistics:
            for identifier in self.statistics[prefix]:
                if not self.is_excluded(identifier, include_introduction, include_puncture, include_deprecated):
                    num_sent += self.statistics[prefix][identifier].num_up
        return num_sent

    def get_message_received(self, prefix: bytes, include_introduction: bool = False, include_puncture: bool = False,
                             include_deprecated: bool = False) -> int:
        """
        Calculate the number of received messages for a given community prefix.
        """
        num_received = 0
        if prefix in self.statistics:
            for identifier in self.statistics[prefix]:
                if not self.is_excluded(identifier, include_introduction, include_puncture, include_deprecated):
                    num_received += self.statistics[prefix][identifier].num_down
        return num_received

    def get_bytes_sent(self, prefix: bytes, include_introduction: bool = False, include_puncture: bool = False,
                       include_deprecated: bool = False) -> int:
        """
        Calculate the number of sent bytes for a given community prefix.
        """
        bytes_sent = 0
        if prefix in self.statistics:
            for identifier in self.statistics[prefix]:
                if not self.is_excluded(identifier, include_introduction, include_puncture, include_deprecated):
                    bytes_sent += self.statistics[prefix][identifier].bytes_up
        return bytes_sent

    def get_bytes_received(self, prefix: bytes, include_introduction: bool = False, include_puncture: bool = False,
                       include_deprecated: bool = False) -> int:
        """
        Calculate the number of received bytes for a given community prefix.
        """
        bytes_received = 0
        if prefix in self.statistics:
            for identifier in self.statistics[prefix]:
                if not self.is_excluded(identifier, include_introduction, include_puncture, include_deprecated):
                    bytes_received += self.statistics[prefix][identifier].bytes_down
        return bytes_received

    def is_excluded(self, identifier: int, include_introduction: bool, include_puncture: bool,
                    include_deprecated: bool) -> bool:
        """
        Whether a given message identifier should be counted with the given filters.
        """
        return (identifier in StatisticsEndpoint.IDS_DEPRECATED and not include_deprecated
                or identifier in StatisticsEndpoint.IDS_INTRODUCTION and not include_introduction
                or identifier in StatisticsEndpoint.IDS_PUNCTURE and not include_puncture)
