from binascii import hexlify

from aiohttp import web

from aiohttp_apispec import docs, json_schema

from marshmallow.fields import Boolean, Dict, List, Nested, String

from .base_endpoint import BaseEndpoint, HTTP_BAD_REQUEST, HTTP_PRECONDITION_FAILED, Response
from .schema import DefaultResponseSchema, OverlaySchema, OverlayStatisticsSchema, schema
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
        self.statistics_supported = isinstance(session.endpoint, StatisticsEndpoint) \
            or isinstance(getattr(session.endpoint, 'endpoint', None), StatisticsEndpoint)

    @docs(
        tags=["Overlays"],
        summary="Return information about all currently loaded overlays.",
        responses={
            200: {
                "schema": schema(OverlayResponse={
                    "overlays": [OverlaySchema]
                })
            }
        }
    )
    async def get_overlays(self, _):
        overlay_stats = []
        for overlay in self.session.overlays:
            peers = overlay.get_peers()
            statistics = self.session.endpoint.get_aggregate_statistics(overlay.get_prefix()) \
                if isinstance(self.session.endpoint, StatisticsEndpoint) else {}
            overlay_stats.append({
                "master_peer": hexlify(overlay.master_peer.public_key.key_to_bin()).decode('utf-8'),
                "my_peer": hexlify(overlay.my_peer.public_key.key_to_bin()).decode('utf-8'),
                "global_time": overlay.global_time,
                "peers": [{'ip': peer.address[0],
                           'port': peer.address[1],
                           'public_key': hexlify(peer.public_key.key_to_bin()).decode('utf-8')} for peer in peers],
                "overlay_name": overlay.__class__.__name__,
                "statistics": statistics
            })
        return Response({"overlays": overlay_stats})

    @docs(
        tags=["Overlays"],
        summary="Return statistics for all currently loaded overlays.",
        responses={
            200: {
                "schema": schema(StatisticsResponse={
                    "statistics": List(Dict(keys=String, values=Nested(OverlayStatisticsSchema))),
                }),
                "examples": {'Success': {"statistics": [{"DiscoveryCommunity": {'num_up': 0, 'num_down': 0,
                                                                                'bytes_up': 0, 'bytes_down': 0,
                                                                                'diff_time': 0}}]}}
            }
        }
    )
    async def get_statistics(self, _):
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

    @docs(
        tags=["Overlays"],
        summary="Enable/disable statistics for a given overlay.",
        responses={
            200: {
                "schema": DefaultResponseSchema,
                "examples": {'Success': {"success": True}}
            },
            HTTP_PRECONDITION_FAILED: {
                "schema": DefaultResponseSchema,
                "examples": {'Statistics disabled': {"success": False, "error": "StatisticsEndpoint is not enabled."}}
            },
            HTTP_BAD_REQUEST: {
                "schema": DefaultResponseSchema,
                "examples": {'Missing parameter': {"success": False, "error": "Parameter 'enable' is required."}}
            }
        }
    )
    @json_schema(schema(EnableStatisticsRequest={
        'enable*': (Boolean, 'Whether to enable or disable the statistics'),
        'all': (Boolean, 'Whether update applies to all overlays'),
        'overlay_name': (String, 'Class name of the overlay'),
    }))
    async def enable_statistics(self, request):
        if not self.statistics_supported:
            return Response({"success": False, "error": "StatisticsEndpoint is not enabled."},
                            status=HTTP_PRECONDITION_FAILED)

        all_overlays = False
        overlay_name = None

        args = await request.json()
        if 'enable' not in args or not args['enable']:
            return Response({"success": False, "error": "Parameter 'enable' is required"}, status=HTTP_BAD_REQUEST)
        enable = args['enable'].lower() == 'true'

        if 'all' in args and args['all']:
            all_overlays = args['all'].lower() == 'true'
        elif 'overlay_name' in args and args['overlay_name']:
            overlay_name = args['overlay_name']
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
