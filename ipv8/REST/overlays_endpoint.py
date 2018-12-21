from __future__ import absolute_import

from binascii import hexlify
import json

from twisted.web import http

from .formal_endpoint import FormalEndpoint
from ..messaging.interfaces.statistics_endpoint import StatisticsEndpoint
from .validation.annotations import RESTInput, RESTOutput
from .validation.types import BOOLEAN_TYPE, NUMBER_TYPE, STR_TYPE


class OverlaysEndpoint(FormalEndpoint):
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
            overlay_stats.append({
                "master_peer": hexlify(overlay.master_peer.public_key.key_to_bin()),
                "my_peer": hexlify(overlay.my_peer.public_key.key_to_bin()),
                "global_time": overlay.global_time,
                "peers": [str(peer) for peer in peers],
                "overlay_name": overlay.__class__.__name__
            })
        return overlay_stats

    @RESTOutput(lambda request: True,
                ({
                     "overlays": [
                         {
                             "master_peer": (STR_TYPE["HEX"], "Public key of the overlay Community."),
                             "my_peer": (STR_TYPE["HEX"], "Public key of my member."),
                             "global_time": NUMBER_TYPE,
                             "peers": ([STR_TYPE["ASCII"]], "Pretty printed list of peers in this overlay."),
                             "overlay_name": STR_TYPE["ASCII"]
                         }
                     ]
                 },
                 "All of the known overlays and their state."))
    def render_GET(self, request):
        return json.dumps({"overlays": self.get_overlays()})


class OverlayStatisticsEndpoint(FormalEndpoint):
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
            mapped_name = str(message_id) + ":" + overlay.decode_map[chr(message_id)].__name__
            mapped_value = network_stats.to_dict()
            named_statistics[mapped_name] = mapped_value
        return named_statistics

    @RESTOutput(lambda request: True,
                ({
                     "statistics": [
                         {
                             (STR_TYPE["ASCII"], "The Community name."): {
                                 (STR_TYPE["ASCII"], "The message name."): {
                                     "identifier": (NUMBER_TYPE, "The message number."),
                                     "num_up": NUMBER_TYPE,
                                     "num_down": NUMBER_TYPE,
                                     "bytes_up": NUMBER_TYPE,
                                     "bytes_down": NUMBER_TYPE,
                                     "first_measured_up": NUMBER_TYPE,
                                     "first_measured_down": NUMBER_TYPE,
                                     "last_measured_up": NUMBER_TYPE,
                                     "last_measured_down": NUMBER_TYPE
                                 }
                             }
                         }
                     ]
                 },
                 "The statistics per message per community, if available."))
    def render_GET(self, _):
        return json.dumps({"statistics": self.get_statistics()})

    @RESTInput("enable", (BOOLEAN_TYPE, "Whether to enable or disable the statistics."))
    @RESTInput("overlay_name", (STR_TYPE["ASCII"], "Class name of the overlay."))
    @RESTInput("all", (BOOLEAN_TYPE, "Update applies to all overlays."))
    @RESTOutput(lambda request: True,
                {
                    "success": (BOOLEAN_TYPE, "Whether the request succeeded, see error.")
                },
                http.OK)
    @RESTOutput(lambda request: True,
                {
                    "success": (BOOLEAN_TYPE, "Whether the request succeeded, see error."),
                    "error": (STR_TYPE["ASCII"], "The available information in case of no success.")
                },
                [http.BAD_REQUEST, http.PRECONDITION_FAILED])
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
