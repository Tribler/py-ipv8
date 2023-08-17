from .asyncio_endpoint import AsyncioEndpoint
from .attestation_endpoint import AttestationEndpoint
from .base_endpoint import BaseEndpoint
from .dht_endpoint import DHTEndpoint
from .identity_endpoint import IdentityEndpoint
from .isolation_endpoint import IsolationEndpoint
from .network_endpoint import NetworkEndpoint
from .noblock_dht_endpoint import NoBlockDHTEndpoint
from .overlays_endpoint import OverlaysEndpoint
from .tunnel_endpoint import TunnelEndpoint


class RootEndpoint(BaseEndpoint):
    """
    The root endpoint of the HTTP API is the root resource in the request tree.
    It will dispatch requests regarding torrents, channels, settings etc to the right child endpoint.
    """

    def setup_routes(self) -> None:
        """
        Register the names to make this endpoint callable.
        """
        endpoints = {'/asyncio': AsyncioEndpoint,
                     '/attestation': AttestationEndpoint,
                     '/dht': DHTEndpoint,
                     '/identity': IdentityEndpoint,
                     '/isolation': IsolationEndpoint,
                     '/network': NetworkEndpoint,
                     '/noblockdht': NoBlockDHTEndpoint,
                     '/overlays': OverlaysEndpoint,
                     '/tunnel': TunnelEndpoint}
        for path, ep_cls in endpoints.items():
            self.add_endpoint(path, ep_cls())
