from base64 import b64encode
import json

from twisted.web import resource


class CrawlerPeersEndpoint(resource.Resource):
    """
    This endpoint is responsible for handing all requests regarding the crawler peers lookup.
    """

    def __init__(self, session):
        resource.Resource.__init__(self)
        self.session = session

    def render_GET(self, request):
        network = self.session.network
        peer_list = network.verified_peers[:]
        return json.dumps([b64encode(p.mid) for p in peer_list])
