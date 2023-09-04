from __future__ import annotations

from binascii import hexlify
from typing import TYPE_CHECKING, Any, Callable, cast

from aiohttp import web
from aiohttp_apispec import docs, json_schema
from marshmallow.base import SchemaABC
from marshmallow.fields import Boolean, Dict, List, Nested, String

from ..messaging.interfaces.statistics_endpoint import StatisticsEndpoint
from ..types import Community, IPv8
from .base_endpoint import HTTP_BAD_REQUEST, HTTP_PRECONDITION_FAILED, BaseEndpoint, Response
from .schema import DefaultResponseSchema, OverlaySchema, OverlayStatisticsSchema, schema

if TYPE_CHECKING:
    from aiohttp.abc import Request

    from ..messaging.interfaces.network_stats import NetworkStat


class OverlaysEndpoint(BaseEndpoint[IPv8]):
    """
    This endpoint is responsible for handing all requests regarding the status of overlays.
    """

    def __init__(self) -> None:
        """
        Create new unregistered and uninitialized REST endpoint.
        """
        super().__init__()
        self.statistics_supported: bool = False

    def setup_routes(self) -> None:
        """
        Register the names to make this endpoint callable.
        """
        self.app.add_routes([web.get('', self.get_overlays),
                             web.get('/statistics', self.get_statistics),
                             web.post('/statistics', self.enable_statistics)])

    def initialize(self, session: IPv8) -> None:
        """
        Initialize this endpoint for the given session instance.
        """
        super().initialize(session)
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
    async def get_overlays(self, _: Request) -> Response:
        """
        Return information about all currently loaded overlays.
        """
        overlay_stats: list[dict[str, Any]] = []
        if self.session is None:
            return Response({"overlays": overlay_stats})
        self.session = cast(IPv8, self.session)
        for overlay in self.session.overlays:
            peers = overlay.get_peers()
            statistics = self.session.endpoint.get_aggregate_statistics(overlay.get_prefix()) \
                if isinstance(self.session.endpoint, StatisticsEndpoint) else {}
            overlay_stats.append({
                "id": hexlify(overlay.community_id).decode('utf-8'),
                "my_peer": hexlify(overlay.my_peer.public_key.key_to_bin()).decode('utf-8'),
                "global_time": overlay.global_time,
                "peers": [{'ip': peer.address[0],
                           'port': peer.address[1],
                           'public_key': hexlify(peer.public_key.key_to_bin()).decode('utf-8')} for peer in peers],
                "overlay_name": overlay.__class__.__name__,
                "statistics": statistics,
                "max_peers": overlay.max_peers,
                "is_isolated": self.session.network != overlay.network,
                "my_estimated_wan": {"ip": overlay.my_estimated_wan[0], "port": overlay.my_estimated_wan[1]},
                "my_estimated_lan": {"ip": overlay.my_estimated_lan[0], "port": overlay.my_estimated_lan[1]},
                "strategies": [{'name': strategy.__class__.__name__,
                                'target_peers': target_peers}
                               for strategy, target_peers in self.session.strategies if strategy.overlay == overlay]
            })
        return Response({"overlays": overlay_stats})

    @docs(
        tags=["Overlays"],
        summary="Return statistics for all currently loaded overlays.",
        responses={
            200: {
                "schema": schema(StatisticsResponse={
                    "statistics": List(Dict(keys=String, values=Nested(cast(SchemaABC, OverlayStatisticsSchema)))),
                }),
                "examples": {'Success': {"statistics": [{"DiscoveryCommunity": {'num_up': 0, 'num_down': 0,
                                                                                'bytes_up': 0, 'bytes_down': 0,
                                                                                'diff_time': 0}}]}}
            }
        }
    )
    async def get_statistics(self, _: Request) -> Response:
        """
        Return statistics for all currently loaded overlays.
        """
        overlay_stats: list[dict[str, Any]] = []
        if self.session is None:
            return Response({"statistics": overlay_stats})
        self.session = cast(IPv8, self.session)
        for overlay in self.session.overlays:
            statistics = self.session.endpoint.get_statistics(overlay.get_prefix()) if self.statistics_supported else {}
            overlay_stats.append({
                overlay.__class__.__name__: self.statistics_by_name(statistics, overlay)
            })
        return Response({"statistics": overlay_stats})

    def statistics_by_name(self, statistics: dict[int, NetworkStat],
                           overlay: Community) -> dict[str, dict[str, int | float]]:
        """
        Convert the captured statistics to a human-readable dict.
        """
        named_statistics: dict[str, dict[str, int | float]] = {}
        for message_id, network_stats in statistics.items():
            if overlay.decode_map[message_id]:
                mapped_name = str(message_id) + ":" + cast(Callable, overlay.decode_map[message_id]).__name__
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
    async def enable_statistics(self, request: Request) -> Response:
        """
        Enable/disable statistics for a given overlay.
        """
        if self.session is None:
            return Response({"success": False, "error": "IPv8 is not running"}, status=HTTP_PRECONDITION_FAILED)
        if not self.statistics_supported:
            return Response({"success": False, "error": "StatisticsEndpoint is not enabled."},
                            status=HTTP_PRECONDITION_FAILED)

        args = await request.json()
        if 'enable' not in args:
            return Response({"success": False, "error": "Parameter 'enable' is required"}, status=HTTP_BAD_REQUEST)
        if 'all' not in args and 'overlay_name' not in args:
            return Response({"success": False, "error": "Parameter 'all' or 'overlay_name' is required"},
                            status=HTTP_PRECONDITION_FAILED)

        self.enable_overlay_statistics(enable=args['enable'],
                                       class_name=args.get('overlay_name', None),
                                       all_overlays=args.get('all', False))
        return Response({"success": True})

    def enable_overlay_statistics(self, enable: bool = False, class_name: str | None = None,
                                  all_overlays: bool = False) -> None:
        """
        Enable statistics for the specified overlays.
        """
        self.session = cast(IPv8, self.session)
        if all_overlays:
            for overlay in self.session.overlays:
                self.session.endpoint.enable_community_statistics(overlay.get_prefix(), enable)
        elif class_name:
            for overlay in self.session.overlays:
                if overlay.__class__.__name__ == class_name:
                    self.session.endpoint.enable_community_statistics(overlay.get_prefix(), enable)
