from __future__ import absolute_import

from base64 import b64encode
import json

from .formal_endpoint import FormalEndpoint
from .validation.annotations import RESTOutput
from .validation.types import NUMBER_TYPE, STR_TYPE


class NetworkEndpoint(FormalEndpoint):
    """
    This endpoint is responsible for handing all requests regarding the state of the network.
    """

    def __init__(self, session):
        super(NetworkEndpoint, self).__init__()
        self.session = session

    def render_peers(self):
        network = self.session.network
        peer_list = network.verified_peers[:]
        return {
                b64encode(peer.mid): {
                            "ip": peer.address[0],
                            "port": peer.address[1],
                            "public_key": b64encode(peer.public_key.key_to_bin()),
                            "services": [b64encode(s) for s in network.get_services_for_peer(peer)]
                }
            for peer in peer_list
        }

    @RESTOutput(lambda request: True,
                ({
                    "peers": {
                        (STR_TYPE["BASE64"], "The sha1 of the peer's public key."): {
                            "ip": STR_TYPE["BASE64"],
                            "port": NUMBER_TYPE,
                            "public_key": STR_TYPE["BASE64"],
                            "services": [(STR_TYPE["BASE64"], "The sha1 of the Community's public key.")]
                        }
                    }
                 },
                 "All of the known peers and their services."))
    def render_GET(self, request):
        return json.dumps({"peers": self.render_peers()})
