import time

from .network_stats import NetworkStat
from ...messaging.interfaces.endpoint import EndpointListener


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

    def __init__(self, ipv8, ipv8_endpoint):
        EndpointListener.__init__(self, ipv8_endpoint)
        self.ipv8 = ipv8
        self.endpoint = ipv8_endpoint
        self.endpoint.add_listener(self)
        self.statistics = {}

    def __getattribute__(self, item):
        try:
            return object.__getattribute__(self, item)
        except AttributeError:
            return object.__getattribute__(self.endpoint, item)

    # Endpoint methods
    def send(self, socket_address, packet):
        self.endpoint.send(socket_address, packet)

        prefix = packet[:22]
        if prefix not in list(self.statistics.keys()) or len(packet) < 22:
            return

        self.add_sent_stat(prefix, ord(packet[22:23]), len(packet))

    def enable_community_statistics(self, community_prefix, enabled):
        if community_prefix not in self.statistics and enabled:
            self.statistics[community_prefix] = {}
        elif community_prefix in self.statistics and not enabled:
            self.statistics.pop(community_prefix)

    # EndpointListener methods
    def on_packet(self, packet):
        _, data = packet

        prefix = data[:22]
        if prefix not in list(self.statistics.keys()) or len(data) < 22:
            return

        message_id = ord(data[22:23])
        self.add_received_stat(prefix, message_id, len(data))

    # Statistics methods
    def add_sent_stat(self, prefix, identifier, num_bytes, timestamp=None):
        if prefix not in self.statistics:
            self.statistics[prefix] = {}
        if identifier not in self.statistics[prefix]:
            self.statistics[prefix][identifier] = NetworkStat(identifier)
        self.statistics[prefix][identifier].add_sent_stat(timestamp if timestamp else time.time(), num_bytes)

    def add_received_stat(self, prefix, identifier, num_bytes, timestamp=None):
        if prefix not in self.statistics:
            self.statistics[prefix] = {}
        if identifier not in self.statistics[prefix]:
            self.statistics[prefix][identifier] = NetworkStat(identifier)
        self.statistics[prefix][identifier].add_received_stat(timestamp if timestamp else time.time(), num_bytes)

    def get_statistics(self, prefix):
        if prefix in self.statistics:
            return self.statistics[prefix]
        return {}

    def get_aggregate_statistics(self, prefix):
        def min_positive(a, b):
            return a if not b else b if b < a or not a else a

        aggregate_stats = {
            "num_up": 0,
            "num_down": 0,
            "bytes_up": 0,
            "bytes_down": 0,
            "diff_time": 0
        }

        if prefix in self.statistics:
            first_ts = last_ts = 0
            for _, network_stat in self.statistics[prefix].items():
                aggregate_stats['num_up'] += network_stat.num_up
                aggregate_stats['num_down'] += network_stat.num_down
                aggregate_stats['bytes_up'] += network_stat.bytes_up
                aggregate_stats['bytes_down'] += network_stat.bytes_down

                first_ts = min_positive(first_ts, min_positive(network_stat.first_measured_up,
                                                               network_stat.first_measured_down))
                last_ts = max(last_ts, max(network_stat.last_measured_up, network_stat.last_measured_down))

            aggregate_stats["diff_time"] = last_ts - first_ts
        return aggregate_stats

    def get_message_sent(self, prefix, include_introduction=False, include_puncture=False, include_deprecated=False):
        num_sent = 0
        if prefix in self.statistics:
            for identifier in self.statistics[prefix]:
                if not self.is_excluded(identifier, include_introduction, include_puncture, include_deprecated):
                    num_sent += self.statistics[prefix][identifier].num_up
        return num_sent

    def get_message_received(self, prefix, include_introduction=False, include_puncture=False,
                             include_deprecated=False):
        num_received = 0
        if prefix in self.statistics:
            for identifier in self.statistics[prefix]:
                if not self.is_excluded(identifier, include_introduction, include_puncture, include_deprecated):
                    num_received += self.statistics[prefix][identifier].num_down
        return num_received

    def get_bytes_sent(self, prefix, include_introduction=False, include_puncture=False, include_deprecated=False):
        bytes_sent = 0
        if prefix in self.statistics:
            for identifier in self.statistics[prefix]:
                if not self.is_excluded(identifier, include_introduction, include_puncture, include_deprecated):
                    bytes_sent += self.statistics[prefix][identifier].bytes_up
        return bytes_sent

    def get_bytes_received(self, prefix, include_introduction=False, include_puncture=False, include_deprecated=False):
        bytes_received = 0
        if prefix in self.statistics:
            for identifier in self.statistics[prefix]:
                if not self.is_excluded(identifier, include_introduction, include_puncture, include_deprecated):
                    bytes_received += self.statistics[identifier].bytes_down
        return bytes_received

    def is_excluded(self, identifier, include_introduction, include_puncture, include_deprecated):
        return (identifier in StatisticsEndpoint.IDS_DEPRECATED and not include_deprecated
                or identifier in StatisticsEndpoint.IDS_INTRODUCTION and not include_introduction
                or identifier in StatisticsEndpoint.IDS_PUNCTURE and not include_puncture)
