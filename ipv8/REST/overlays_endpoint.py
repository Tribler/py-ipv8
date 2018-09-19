from __future__ import absolute_import

from binascii import hexlify
import json

from twisted.web import resource


class OverlaysEndpoint(resource.Resource):
    """
    This endpoint is responsible for handing all requests regarding the status of overlays.
    """

    def __init__(self, session):
        resource.Resource.__init__(self)
        self.session = session

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

    def render_GET(self, request):
        return json.dumps({"overlays": self.get_overlays()})
