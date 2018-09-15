from base64 import b64encode
import json

from twisted.web import resource


class ServiceEndpoint(resource.Resource):
    """
    This endpoint is responsible for handing all requests regarding service lookup.
    """

    def __init__(self, session):
        resource.Resource.__init__(self)
        self.session = session

    def render_GET(self, request):
        network = self.session.network
        peer_list = network.verified_peers[:]
        filter_cid = None
        if request.args and ('id' in request.args):
            filter_cid = request.args['id'][0]
        services_dict = {}
        for p in peer_list:
            for cid in network.get_services_for_peer(p):
                b64cid = b64encode(cid)
                if filter_cid and filter_cid != b64cid:
                    continue
                services_dict[b64cid] = 1 + services_dict.get(b64cid, 0)
        return json.dumps(services_dict)
