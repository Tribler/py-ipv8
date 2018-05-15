from base64 import b64decode, b64encode
import json

from twisted.internet.defer import Deferred, inlineCallbacks, returnValue
from twisted.web import resource

from ..attestation.identity.community import IdentityCommunity
from ..attestation.wallet.community import AttestationCommunity
from ..attestation.wallet.primitives.attestation import binary_relativity_sha256_4
from ..attestation.wallet.primitives.cryptosystem.boneh import generate_keypair


class AttestationEndpoint(resource.Resource):
    """
    This endpoint is responsible for handing all requests regarding attestation.
    """

    def __init__(self, session):
        resource.Resource.__init__(self)
        self.session = session
        attestation_overlays = [overlay for overlay in session.overlays if isinstance(overlay, AttestationCommunity)]
        identity_overlays = [overlay for overlay in session.overlays if isinstance(overlay, IdentityCommunity)]
        if attestation_overlays and identity_overlays:
            self.attestation_overlay = attestation_overlays[0]
            self.attestation_overlay.set_attestation_request_callback(self.on_request_attestation)
            self.attestation_overlay.set_attestation_request_complete_callback(self.on_attestation_complete)
            self.identity_overlay = identity_overlays[0]
        self.attestation_requests = {}
        self.verification_output = {}

    @inlineCallbacks
    def on_request_attestation(self, peer, attribute_name):
        """
        Return the measurement of an attribute for a certain peer.
        """
        deferred = Deferred()
        self.attestation_requests[(b64encode(peer.mid), attribute_name)] = deferred
        out = yield deferred
        returnValue(out)

    def on_attestation_complete(self, peer, attribute_name, hash, signer=None):
        """
        Callback for when an attestation has been completed for another peer.
        We can now sign for it.
        """
        if peer.mid == self.identity_overlay.my_peer.mid:
            self.identity_overlay.request_attestation_advertisement(signer, hash, attribute_name)
        else:
            self.identity_overlay.add_known_hash(hash, attribute_name, peer.public_key.key_to_bin())

    def on_verification_results(self, hash, values):
        """
        Callback for when verification has concluded.
        """
        references = self.verification_output[hash]
        out = []
        for i in range(len(references)):
            out[i] = (references[i], values[i])
        self.verification_output[hash] = out

    def get_peer_from_mid(self, mid_b64):
        """
        Find a peer by base64 encoded mid.
        """
        mid = b64decode(mid_b64)
        peers = self.session.network.verified_peers[:]
        matches = [p for p in peers if p.mid == mid]
        return matches[0] if matches else None

    def render_GET(self, request):
        """
        type=outstanding -> [(mid_b64, attribute_name)]
        type=verification_output -> {hash_b64: [(value_b64, match)]}
        type=peers -> [mid_b64]
        type=attributes&mid=mid_b64 -> [(attribute_name, attribute_hash)]
        """
        if not request.args or 'type' not in request.args:
            return ""
        if request.args['type'][0] == 'outstanding':
            return json.dumps(self.attestation_requests.keys())
        if request.args['type'][0] == 'verification_output':
            return json.dumps(self.verification_output)
        if request.args['type'][0] == 'peers':
            peers = self.session.network.get_peers_for_service(self.identity_overlay.master_peer.mid)
            return json.dumps([b64encode(p.mid) for p in peers])
        if request.args['type'][0] == 'attributes':
            if 'mid' in request.args:
                mid_b64 = request.args['mid'][0]
                peer = self.get_peer_from_mid(mid_b64)
            else:
                peer = self.identity_overlay.my_peer
            if peer:
                blocks = self.identity_overlay.persistence.get_latest_blocks(peer.public_key.key_to_bin(), 200)
                return json.dumps([(b.transaction["name"], b64encode(b.transaction["hash"])) for b in blocks])
        return ""

    def render_POST(self, request):
        """
        type=request&mid=mid_b64&attibute_name=attribute_name
        type=attest&mid=mid_b64&attribute_name=attribute_name&attribute_value=attribute_value_b64
        type=verify&mid=mid_b64&attribute_hash=attribute_hash_b64&attribute_values=attribute_value_b64,...
        """
        if not request.args or 'type' not in request.args:
            return ""
        if request.args['type'][0] == 'request':
            mid_b64 = request.args['mid'][0]
            attribute_name = request.args['attribute_name'][0]
            peer = self.get_peer_from_mid(mid_b64)
            if peer:
                _, key = generate_keypair()
                self.attestation_overlay.request_attestation(peer, attribute_name, key)
            return ""
        if request.args['type'][0] == 'attest':
            mid_b64 = request.args['mid'][0]
            attribute_name = request.args['attribute_name'][0]
            attribute_value_b64 = request.args['attribute_value'][0]
            self.attestation_requests[(mid_b64, attribute_name)].callback(b64decode(attribute_value_b64))
            return ""
        if request.args['type'][0] == 'verify':
            mid_b64 = request.args['mid'][0]
            attribute_hash = b64decode(request.args['attribute_hash'][0])
            reference_values = [binary_relativity_sha256_4(b64decode(v))
                                for v in request.args['attribute_values'][0].split(',')]
            peer = self.get_peer_from_mid(mid_b64)
            if peer:
                self.verification_output[request.args['attribute_hash'][0]] = request.args['attribute_values'][0].split(',')
                self.attestation_overlay.verify_attestation_values(peer.address, attribute_hash, reference_values, self.on_verification_results)
            return ""
        return ""
