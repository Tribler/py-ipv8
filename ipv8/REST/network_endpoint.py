from __future__ import absolute_import

from base64 import b64encode

from .base_endpoint import BaseEndpoint


class NetworkEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handing all requests regarding the state of the network.
    """

    def __init__(self, session):
        super(NetworkEndpoint, self).__init__()
        self.session = session

    def retrieve_peers(self):
        network = self.session.network
        peer_list = network.verified_peers
        return {
            b64encode(peer.mid).decode('utf-8'): {
                "ip": peer.address[0],
                "port": peer.address[1],
                "public_key": b64encode(peer.public_key.key_to_bin()).decode('utf-8'),
                "services": [b64encode(s).decode('utf-8') for s in network.get_services_for_peer(peer)]
            }
            for peer in peer_list
        }

    def render_GET(self, request):
        return self.twisted_dumps({"peers": self.retrieve_peers()})
