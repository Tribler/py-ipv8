from binascii import hexlify

from aiohttp import web

from .base_endpoint import BaseEndpoint, HTTP_BAD_REQUEST, HTTP_PRECONDITION_FAILED, Response
from ..messaging.interfaces.statistics_endpoint import StatisticsEndpoint


class OverlaysEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handing all requests regarding the status of overlays.
    """

    def __init__(self):
        super(OverlaysEndpoint, self).__init__()
        self.statistics_supported = None

    def setup_routes(self):
        self.app.add_routes([web.get('', self.get_overlays),
                             web.get('/statistics', self.get_statistics),
                             web.post('/statistics', self.enable_statistics)])

    def initialize(self, session):
        super(OverlaysEndpoint, self).initialize(session)
        self.statistics_supported = isinstance(session.endpoint, StatisticsEndpoint)

    def get_overlays(self, request):
        overlay_stats = []
        for overlay in self.session.overlays:
            peers = overlay.get_peers()
            statistics = self.session.endpoint.get_aggregate_statistics(overlay.get_prefix()) \
                if isinstance(self.session.endpoint, StatisticsEndpoint) else {}
            overlay_stats.append({
                "master_peer": hexlify(overlay.master_peer.public_key.key_to_bin()).decode('utf-8'),
                "my_peer": hexlify(overlay.my_peer.public_key.key_to_bin()).decode('utf-8'),
                "global_time": overlay.global_time,
                "peers": [str(peer) for peer in peers],
                "overlay_name": overlay.__class__.__name__,
                "statistics": statistics
            })
        return Response({"overlays": overlay_stats})

    def get_statistics(self, request):
        overlay_stats = []
        for overlay in self.session.overlays:
            statistics = self.session.endpoint.get_statistics(overlay.get_prefix()) if self.statistics_supported else {}
            overlay_stats.append({
                overlay.__class__.__name__: self.statistics_by_name(statistics, overlay)
            })
        return Response({"statistics": overlay_stats})

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

    def enable_statistics(self, request):
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
            return Response({"success": False, "error": "StatisticsEndpoint is not enabled."},
                            status=HTTP_PRECONDITION_FAILED)

        all_overlays = False
        overlay_name = None

        if 'enable' not in request.query or not request.query['enable']:
            return Response({"success": False, "error": "Parameter 'enable' is required"}, status=HTTP_BAD_REQUEST)
        enable = request.query['enable'] == 'True'

        if 'all' in request.query and request.query['all']:
            all_overlays = request.query['all'] == 'True'
        elif 'overlay_name' in request.query and request.query['overlay_name']:
            overlay_name = request.query['overlay_name']
        else:
            return Response({"success": False, "error": "Parameter 'all' or 'overlay_name' is required"},
                            status=HTTP_PRECONDITION_FAILED)

        self.enable_overlay_statistics(enable=enable, class_name=overlay_name, all_overlays=all_overlays)
        return Response({"success": True})

    def enable_overlay_statistics(self, enable=False, class_name=None, all_overlays=False):
        if all_overlays:
            for overlay in self.session.overlays:
                self.session.endpoint.enable_community_statistics(overlay.get_prefix(), enable)
        elif class_name:
            for overlay in self.session.overlays:
                if overlay.__class__.__name__ == class_name:
                    self.session.endpoint.enable_community_statistics(overlay.get_prefix(), enable)
