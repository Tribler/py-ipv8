from __future__ import absolute_import

from hashlib import sha1
from base64 import b64decode, b64encode
import json

from twisted.internet.defer import Deferred, succeed

from ..attestation.identity.community import IdentityCommunity
from ..attestation.wallet.community import AttestationCommunity
from ..attestation.wallet.primitives.attestation import binary_relativity_sha256_4
from ..attestation.wallet.primitives.cryptosystem.boneh import generate_keypair
from .formal_endpoint import FormalEndpoint
from ..keyvault.crypto import default_eccrypto
from ..peer import Peer
from ..util import cast_to_bin, cast_to_unicode
from .validation.annotations import RESTInput, RESTOutput
from .validation.types import NUMBER_TYPE, STR_TYPE, TUPLE_TYPE, UNKNOWN_OBJECT


class AttestationEndpoint(FormalEndpoint):
    """
    This endpoint is responsible for handing all requests regarding attestation.
    """

    def __init__(self, session):
        super(AttestationEndpoint, self).__init__()
        self.session = session
        attestation_overlays = [overlay for overlay in session.overlays if isinstance(overlay, AttestationCommunity)]
        identity_overlays = [overlay for overlay in session.overlays if isinstance(overlay, IdentityCommunity)]
        if attestation_overlays and identity_overlays:
            self.attestation_overlay = attestation_overlays[0]
            self.attestation_overlay.set_attestation_request_callback(self.on_request_attestation)
            self.attestation_overlay.set_attestation_request_complete_callback(self.on_attestation_complete)
            self.attestation_overlay.set_verify_request_callback(self.on_verify_request)
            self.identity_overlay = identity_overlays[0]
        self.attestation_requests = {}
        self.verify_requests = {}
        self.verification_output = {}
        self.attestation_metadata = {}

    def on_request_attestation(self, peer, attribute_name, metadata):
        """
        Return the measurement of an attribute for a certain peer.
        """
        deferred = Deferred()
        self.attestation_requests[(b64encode(peer.mid), cast_to_bin(attribute_name))] = \
            (deferred, b64encode(json.dumps(metadata).encode('utf-8')))
        self.attestation_metadata[(peer, attribute_name)] = metadata
        return deferred

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

    def on_verify_request(self, peer, attribute_hash):
        """
        Return the measurement of an attribute for a certain peer.
        """
        block = self.identity_overlay.get_attestation_by_hash(attribute_hash)
        if not block:
            return succeed(None)
        attribute_name = block.transaction[b"name"]
        deferred = Deferred()
        self.verify_requests[(b64encode(peer.mid), attribute_name)] = deferred
        return deferred

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

    @RESTInput("type", STR_TYPE["ASCII"])
    @RESTInput("mid", (STR_TYPE["BASE64"], "The member id to use for 'attributes' type requests."))
    @RESTOutput(lambda request: request.get(b'type', None) == b"outstanding",
                ([TUPLE_TYPE((STR_TYPE["BASE64"], "The member id who requested attestation."),
                             (STR_TYPE["ASCII"], "The requested attribute name."),
                             (STR_TYPE["BASE64"], "The JSON metadata as a string."))],
                 "Poll outstanding attestation requests."))
    @RESTOutput(lambda request: request.get(b'type', None) == b"outstanding_verify",
                ([TUPLE_TYPE((STR_TYPE["BASE64"], "The member id who requested attestation."),
                             (STR_TYPE["ASCII"], "The requested attribute name."))],
                 "Poll outstanding verification requests."))
    @RESTOutput(lambda request: request.get(b'type', None) == b"verification_output",
                ({
                    STR_TYPE["BASE64"]: [TUPLE_TYPE(
                        (STR_TYPE["BASE64"], "Attribute hash."),
                        (NUMBER_TYPE, "Confidence in tested value.")
                    )]
                 },
                 "Poll available verification output."))
    @RESTOutput(lambda request: request.get(b'type', None) == b"peers",
                ([STR_TYPE["BASE64"]],
                 "Fetch all known overlay member identifiers."))
    @RESTOutput(lambda request: request.get(b'type', None) == b"attributes",
                ([TUPLE_TYPE(
                    (STR_TYPE["ASCII"], "The attribute name."),
                    (STR_TYPE["BASE64"], "The attribute hash."),
                    (UNKNOWN_OBJECT, "The user metadata."),
                    (STR_TYPE["BASE64"], "The attester's member id.")
                )],
                 "Get the known attributes for a given member id (our own if no member id is supplied)."))
    @RESTOutput(lambda request: request.get(b'type', None) == b"drop_identity",
                ("",
                 "Drop all identity data (used for debugging)."))
    def render_GET(self, request):
        """
        type=drop_identity
        type=outstanding -> [(mid_b64, attribute_name)]
        type=outstanding_verify -> [(mid_b64, attribute_name)]
        type=verification_output -> {hash_b64: [(value_b64, match)]}
        type=peers -> [mid_b64]
        type=attributes&mid=mid_b64 -> [(attribute_name, attribute_hash)]
        """
        if not request.args or b'type' not in request.args:
            return ""
        if request.args[b'type'][0] == b'outstanding':
            formatted = []
            for k, v in self.attestation_requests.items():
                formatted.append(k + (v[1], ))
            return json.dumps([(x.decode('utf-8'), y.decode('utf-8'), z.decode('utf-8'))
                               for x, y, z in formatted]).encode('utf-8')
        if request.args[b'type'][0] == b'outstanding_verify':
            formatted = []
            for k, v in self.verify_requests.items():
                formatted.append(k)
            return json.dumps([(x.decode('utf-8'), y.decode('utf-8')) for x, y in formatted]).encode('utf-8')
        if request.args[b'type'][0] == b'verification_output':
            formatted = {}
            for k, v in self.verification_output.items():
                formatted[b64encode(k).decode('utf-8')] = [(b64encode(a).decode('utf-8'), m) for a, m in v]
            return json.dumps(formatted).encode('utf-8')
        if request.args[b'type'][0] == b'peers':
            peers = self.session.network.get_peers_for_service(self.identity_overlay.master_peer.mid)
            return json.dumps([b64encode(p.mid).decode('utf-8') for p in peers]).encode('utf-8')
        if request.args[b'type'][0] == b'attributes':
            if b'mid' in request.args:
                mid_b64 = request.args[b'mid'][0]
                peer = self.get_peer_from_mid(mid_b64)
            else:
                peer = self.identity_overlay.my_peer
            if peer:
                blocks = self.identity_overlay.persistence.get_latest_blocks(peer.public_key.key_to_bin(), 200)
                trimmed = {}
                for b in blocks:
                    attester = b64encode(sha1(b.link_public_key).digest())
                    previous = trimmed.get((attester, b.transaction[b"name"]), None)
                    if not previous or previous.sequence_number < b.sequence_number:
                        trimmed[(attester, b.transaction[b"name"])] = b
                return json.dumps([(b.transaction[b"name"].decode('utf-8'),
                                    b64encode(b.transaction[b"hash"]).decode('utf-8'),
                                    {cast_to_unicode(k):
                                         cast_to_unicode(v) for k, v in b.transaction[b"metadata"].items()},
                                    b64encode(sha1(b.link_public_key).digest()).decode('utf-8'))
                                   for b in trimmed.values()]).encode('utf-8')
        if request.args[b'type'][0] == b'drop_identity':
            self.identity_overlay.persistence.execute('DELETE FROM blocks')
            self.identity_overlay.persistence.commit()
            self.attestation_overlay.database.execute('DELETE FROM %s' % self.attestation_overlay.database.db_name)
            self.attestation_overlay.database.commit()
            self.attestation_requests.clear()
            my_new_peer = Peer(default_eccrypto.generate_key(u"curve25519"))
            self.identity_overlay.my_peer = my_new_peer
            self.attestation_overlay.my_peer = my_new_peer
        return b""

    @RESTInput("type", STR_TYPE["ASCII"])
    @RESTInput("mid", (STR_TYPE["BASE64"], "The member id to use for 'attributes' type requests."))
    @RESTInput("attibute_name", STR_TYPE["ASCII"])
    @RESTInput("attribute_value", STR_TYPE["BASE64"])
    @RESTInput("attribute_values", ([STR_TYPE["BASE64"]], "The values to match to/test for, when verifying."))
    @RESTInput("attribute_hash", (STR_TYPE["BASE64"], "The hash of the attribute to prove."))
    @RESTOutput(lambda request: request.get(b'type', None) == b"request",
                ("",
                 "Request attestation for an attribute from an identifier. Takes mid and attribute_name." +
                 "Optionally supply a custom metadata (string to string map) object."))
    @RESTOutput(lambda request: request.get(b'type', None) == b"allow_verify",
                ("",
                 "Allow verification of an attribute by someone. Takes mid and attribute_name."))
    @RESTOutput(lambda request: request.get(b'type', None) == b"attest",
                ("",
                 "Attest an attribute for someone. Takes mid, attribute_name and attribute_value."))
    @RESTOutput(lambda request: request.get(b'type', None) == b"verify",
                ("",
                 "Request verification of someone's attribute. Takes mid, attribute_values, attribute_hash "+
                 "and attribute_values."))
    def render_POST(self, request):
        """
        type=request&mid=mid_b64&attibute_name=attribute_name
        type=allow_verify&mid=mid_b64&attibute_name=attribute_name
        type=attest&mid=mid_b64&attribute_name=attribute_name&attribute_value=attribute_value_b64
        type=verify&mid=mid_b64&attribute_hash=attribute_hash_b64&attribute_values=attribute_value_b64,...
        """
        if not request.args or b'type' not in request.args:
            return b""
        if request.args[b'type'][0] == b'request':
            mid_b64 = request.args[b'mid'][0]
            attribute_name = request.args[b'attribute_name'][0]
            peer = self.get_peer_from_mid(mid_b64)
            if peer:
                _, key = generate_keypair()
                metadata = {}
                if b'metadata' in request.args:
                    metadata_unicode = json.loads(b64decode(request.args[b'metadata'][0]))
                    for k, v in metadata_unicode.items():
                        metadata[cast_to_bin(k)] = cast_to_bin(v)
                    self.attestation_metadata[(self.identity_overlay.my_peer, attribute_name)] = metadata
                self.attestation_overlay.request_attestation(peer, attribute_name, key, metadata)
            return b""
        if request.args[b'type'][0] == b'attest':
            mid_b64 = request.args[b'mid'][0]
            attribute_name = request.args[b'attribute_name'][0]
            attribute_value_b64 = request.args[b'attribute_value'][0]
            outstanding = self.attestation_requests.pop((mid_b64, attribute_name))
            outstanding[0].callback(b64decode(attribute_value_b64))
            return b""
        if request.args[b'type'][0] == b'allow_verify':
            mid_b64 = request.args[b'mid'][0]
            attribute_name = request.args[b'attribute_name'][0]
            self.verify_requests[(mid_b64, attribute_name)].callback(True)
            return b""
        if request.args[b'type'][0] == b'verify':
            mid_b64 = request.args[b'mid'][0]
            attribute_hash = b64decode(request.args[b'attribute_hash'][0])
            reference_values = [binary_relativity_sha256_4(b64decode(v))
                                for v in request.args[b'attribute_values'][0].split(b',')]
            peer = self.get_peer_from_mid(mid_b64)
            if peer:
                self.verification_output[b64decode(request.args[b'attribute_hash'][0])] =\
                    [(b64decode(v), 0.0) for v in request.args[b'attribute_values'][0].split(b',')]
                self.attestation_overlay.verify_attestation_values(peer.address, attribute_hash, reference_values,
                                                                   self.on_verification_results)
            return b""
        return b""
