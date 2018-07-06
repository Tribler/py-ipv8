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
        self.attestation_metadata = {}

    @inlineCallbacks
    def on_request_attestation(self, peer, attribute_name, metadata):
        """
        Return the measurement of an attribute for a certain peer.
        """
        deferred = Deferred()
        self.attestation_requests[(b64encode(peer.mid), attribute_name)] = (deferred, b64encode(json.dumps(metadata)))
        self.attestation_metadata[(peer, attribute_name)] = metadata
        out = yield deferred
        returnValue(out)

    def on_attestation_complete(self, for_peer, attribute_name, attribute_hash, from_peer=None):
        """
        Callback for when an attestation has been completed for another peer.
        We can now sign for it.
        """
        metadata = self.attestation_metadata.get((for_peer, attribute_name), None)
        if for_peer.mid == self.identity_overlay.my_peer.mid:
            self.identity_overlay.request_attestation_advertisement(from_peer, attribute_hash, attribute_name,
                                                                    metadata)
        else:
            self.identity_overlay.add_known_hash(attribute_hash, attribute_name, for_peer.public_key.key_to_bin(),
                                                 metadata)

    def on_verification_results(self, attribute_hash, values):
        """
        Callback for when verification has concluded.
        """
        references = self.verification_output[attribute_hash]
        out = []
        for i in range(len(references)):
            out.append((references[i][0] if isinstance(references[i], tuple) else references[i], values[i]))
        self.verification_output[attribute_hash] = out

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
        type=drop_identity
        type=outstanding -> [(mid_b64, attribute_name)]
        type=verification_output -> {hash_b64: [(value_b64, match)]}
        type=peers -> [mid_b64]
        type=attributes&mid=mid_b64 -> [(attribute_name, attribute_hash)]
        """

        if not request.args or 'type' not in request.args:
            return ""
        if request.args['type'][0] == 'outstanding':
            formatted = []
            for k, v in self.attestation_requests.iteritems():
                formatted.append(k + (v[1], ))
            return json.dumps(formatted)
        if request.args['type'][0] == 'verification_output':
            formatted = {}
            for k, v in self.verification_output.iteritems():
                formatted[b64encode(k)] = [(b64encode(a), m) for a, m in v]
            return json.dumps(formatted)
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
                return json.dumps([(b.transaction["name"], b64encode(b.transaction["hash"]), b.transaction["metadata"])
                                   for b in blocks])
        if request.args['type'][0] == 'drop_identity':
            self.identity_overlay.persistence.execute('DELETE FROM blocks')
            self.identity_overlay.persistence.commit()
            self.attestation_overlay.database.execute('DELETE FROM %s' % self.attestation_overlay.database.db_name)
            self.attestation_overlay.database.commit()
            self.attestation_requests.clear()
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
                metadata = {}
                if 'metadata' in request.args:
                    metadata = json.loads(b64decode(request.args['metadata'][0]))
                    self.attestation_metadata[(self.identity_overlay.my_peer, attribute_name)] = metadata
                self.attestation_overlay.request_attestation(peer, attribute_name, key, metadata)
            return ""
        if request.args['type'][0] == 'attest':
            mid_b64 = request.args['mid'][0]
            attribute_name = request.args['attribute_name'][0]
            attribute_value_b64 = request.args['attribute_value'][0]
            self.attestation_requests[(mid_b64, attribute_name)][0].callback(b64decode(attribute_value_b64))
            return ""
        if request.args['type'][0] == 'verify':
            mid_b64 = request.args['mid'][0]
            attribute_hash = b64decode(request.args['attribute_hash'][0])
            reference_values = [binary_relativity_sha256_4(b64decode(v))
                                for v in request.args['attribute_values'][0].split(',')]
            peer = self.get_peer_from_mid(mid_b64)
            if peer:
                self.verification_output[b64decode(request.args['attribute_hash'][0])] =\
                    [b64decode(v) for v in request.args['attribute_values'][0].split(',')]
                self.attestation_overlay.verify_attestation_values(peer.address, attribute_hash, reference_values, self.on_verification_results)
            return ""
        return ""
