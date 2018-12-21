from __future__ import absolute_import

from .attestation_endpoint import AttestationEndpoint
from .dht_endpoint import DHTEndpoint
from .formal_endpoint import FormalEndpoint
from .network_endpoint import NetworkEndpoint
from .overlays_endpoint import OverlaysEndpoint, StatisticsEndpoint
from .trustchain_endpoint import TrustchainEndpoint
from .tunnel_endpoint import TunnelEndpoint


class RootEndpoint(FormalEndpoint):
    """
    The root endpoint of the HTTP API is the root resource in the request tree.
    It will dispatch requests regarding torrents, channels, settings etc to the right child endpoint.
    """

    def __init__(self, session):
        """
        During the initialization of the REST API, we only start the event sockets and the state endpoint.
        We enable the other endpoints after completing the starting procedure.
        """
        super(RootEndpoint, self).__init__()
        self.session = session
        self.putChild(b'attestation', AttestationEndpoint(session))
        self.putChild(b'network', NetworkEndpoint(session))
        self.putChild(b'trustchain', TrustchainEndpoint(session))
        self.putChild(b'overlays', OverlaysEndpoint(session))
        self.putChild(b'statistics', StatisticsEndpoint(session, session.endpoint))
        self.putChild(b'dht', DHTEndpoint(session))
        self.putChild(b'tunnel', TunnelEndpoint(session))
        self.generate_documentation()
