from __future__ import absolute_import

from binascii import hexlify
import json

from twisted.web import http

from .base_endpoint import BaseEndpoint
from ..messaging.interfaces.statistics_endpoint import StatisticsEndpoint


class OverlaysEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handing all requests regarding the status of overlays.
    """

    def __init__(self, session):
        super(OverlaysEndpoint, self).__init__()
        self.session = session
        self.putChild("statistics", OverlayStatisticsEndpoint(session))

    def get_overlays(self):
        overlay_stats = []
        for overlay in self.session.overlays:
            peers = overlay.get_peers()
            statistics = self.session.endpoint.get_aggregate_statistics(overlay.get_prefix()) \
                if isinstance(self.session.endpoint, StatisticsEndpoint) else {}
            overlay_stats.append({
                "master_peer": hexlify(overlay.master_peer.public_key.key_to_bin()),
                "my_peer": hexlify(overlay.my_peer.public_key.key_to_bin()),
                "global_time": overlay.global_time,
                "peers": [str(peer) for peer in peers],
                "overlay_name": overlay.__class__.__name__,
                "statistics": statistics
            })
        return overlay_stats

    def render_GET(self, request):
        return json.dumps({"overlays": self.get_overlays()})


class OverlayStatisticsEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handing all requests regarding the statistics of overlays.
    """

    def __init__(self, session):
        super(OverlayStatisticsEndpoint, self).__init__()
        self.session = session
        self.statistics_supported = isinstance(self.session.endpoint, StatisticsEndpoint)

    def get_statistics(self):
        overlay_stats = []
        for overlay in self.session.overlays:
            statistics = self.session.endpoint.get_statistics(overlay.get_prefix()) if self.statistics_supported else {}
            overlay_stats.append({
                overlay.__class__.__name__: self.statistics_by_name(statistics, overlay)
            })
        return overlay_stats

    def statistics_by_name(self, statistics, overlay):
        named_statistics = {}
        for message_id, network_stats in statistics.items():
            if overlay.decode_map.get(chr(message_id)):
                mapped_name = str(message_id) + ":" + overlay.decode_map[chr(message_id)].__name__
            else:
                mapped_name = str(message_id) + ":unknown"
            mapped_value = network_stats.to_dict()
            named_statistics[mapped_name] = mapped_value
        return named_statistics

    def render_GET(self, _):
        return json.dumps({"statistics": self.get_statistics()})

    def render_POST(self, request):
        """
        .. http:post:: /overlays/statistics

        A POST request to this endpoint will enable statistics on the given overlay.
        - enable: whether to enable or disable the statistics (True/False)
        - overlay_name: class name of the overlay
        - all: if set to True, update applies to all overlays

            **Example request**:

                .. sourcecode:: none

                    curl -X PUT http://localhost:8085/ipv8/overlays/statistics
                    --data "enable=True&overlay_name=overlay_name&all=True

            **Example response**:

                .. sourcecode:: javascript

                    {"success": True}
        """

        if not self.statistics_supported:
            request.setResponseCode(http.PRECONDITION_FAILED)
            return json.dumps({"success": False, "error": "StatisticsEndpoint is not enabled."})

        all_overlays = False
        overlay_name = None

        if 'enable' not in request.args or not request.args['enable']:
            request.setResponseCode(http.BAD_REQUEST)
            return json.dumps({"success": False, "error": "Parameter 'enable' is required"})
        else:
            enable = request.args['enable'][0] == 'True'

        if 'all' in request.args and request.args['all']:
            all_overlays = request.args['all'][0] == 'True'
        elif 'overlay_name' in request.args and request.args['overlay_name']:
            overlay_name = request.args['overlay_name'][0]
        else:
            request.setResponseCode(http.PRECONDITION_FAILED)
            return json.dumps({"success": False, "error": "Parameter 'all' or 'overlay_name' is required"})

        self.enable_overlay_statistics(enable=enable, class_name=overlay_name, all_overlays=all_overlays)
        return json.dumps({"success": True})

    def enable_overlay_statistics(self, enable=False, class_name=None, all_overlays=False):
        if all_overlays:
            for overlay in self.session.overlays:
                self.session.endpoint.enable_community_statistics(overlay.get_prefix(), enable)
        elif class_name:
            for overlay in self.session.overlays:
                if overlay.__class__.__name__ == class_name:
                    self.session.endpoint.enable_community_statistics(overlay.get_prefix(), enable)
