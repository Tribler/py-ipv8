from asyncio import Future
from base64 import b64decode, b64encode
from hashlib import sha1

from aiohttp import web

from aiohttp_apispec import docs

from . import json_util as json
from .base_endpoint import BaseEndpoint, HTTP_BAD_REQUEST, HTTP_NOT_FOUND, Response
from ..attestation.identity.community import IdentityCommunity, create_community
from ..attestation.wallet.community import AttestationCommunity
from ..keyvault.crypto import default_eccrypto
from ..peer import Peer
from ..util import cast_to_bin, strip_sha1_padding, succeed


class AttestationEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handing all requests regarding attestation.
    """

    def __init__(self):
        super(AttestationEndpoint, self).__init__()
        self.attestation_overlay = self.identity_overlay = self.persistent_key = None
        self.attestation_requests = {}
        self.verify_requests = {}
        self.verification_output = {}
        self.attestation_metadata = {}

    def setup_routes(self):
        self.app.add_routes([web.get('', self.handle_get),
                             web.post('', self.handle_post)])

    def initialize(self, session):
        super(AttestationEndpoint, self).initialize(session)
        self.attestation_overlay = next((overlay for overlay in session.overlays
                                         if isinstance(overlay, AttestationCommunity)), None)
        self.identity_overlay = next((overlay for overlay in session.overlays
                                      if isinstance(overlay, IdentityCommunity)), None)
        if self.attestation_overlay and self.identity_overlay:
            self.attestation_overlay.set_attestation_request_callback(self.on_request_attestation)
            self.attestation_overlay.set_attestation_request_complete_callback(self.on_attestation_complete)
            self.attestation_overlay.set_verify_request_callback(self.on_verify_request)
            self.persistent_key = self.identity_overlay.my_peer

    def on_request_attestation(self, peer, attribute_name, metadata):
        """
        Return the measurement of an attribute for a certain peer.
        """
        future = Future()
        self.attestation_requests[(b64encode(peer.mid).decode(), attribute_name)] = \
            (future, b64encode(json.dumps(metadata).encode('utf-8')).decode())
        self.attestation_metadata[(peer, attribute_name)] = metadata
        return future

    def on_attestation_complete(self, for_peer, attribute_name, attribute_hash, id_format, from_peer=None):
        """
        Callback for when an attestation has been completed for another peer.
        We can now sign for it.
        """
        metadata = self.attestation_metadata.get((for_peer, attribute_name), None)
        if for_peer.mid == self.identity_overlay.my_peer.mid:
            if from_peer.mid == self.identity_overlay.my_peer.mid:
                self.identity_overlay.self_advertise(attribute_hash, attribute_name, id_format, metadata)
            else:
                self.identity_overlay.request_attestation_advertisement(from_peer, attribute_hash, attribute_name,
                                                                        id_format, metadata)
        else:
            self.identity_overlay.add_known_hash(attribute_hash, attribute_name, for_peer.public_key.key_to_bin(),
                                                 metadata)

    def on_verify_request(self, peer, attribute_hash):
        """
        Return the measurement of an attribute for a certain peer.
        """
        metadata = self.identity_overlay.get_attestation_by_hash(attribute_hash)
        if not metadata:
            return succeed(None)
        attribute_name = json.loads(metadata.serialized_json_dict)["name"]
        future = Future()
        self.verify_requests[(b64encode(peer.mid).decode(), attribute_name)] = future
        return future

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
        peers = self.session.network.verified_peers
        matches = [p for p in peers if p.mid == mid]
        return matches[0] if matches else None

    def _drop_identity_table_data(self, keys_to_keep):
        """
        Remove all metadata (TrustChain blocks) from the identity community.

        :param keys_to_keep: list of keys to not remove for
        :type keys_to_keep: [str]
        :return: the list of attestation hashes which have been removed
        :rtype: [database_blob]
        """
        database = self.identity_overlay.identity_manager.database
        all_identities = database.get_known_identities()
        to_remove = []
        attestation_hashes = []
        for key in all_identities:
            if key not in keys_to_keep:
                to_remove.append(key)
                attestation_hashes.extend([t.content_hash for t in database.get_tokens_for(Peer(key).public_key)])

        with database:
            for public_key in to_remove:
                database.executescript("BEGIN TRANSACTION; "
                                       "DELETE FROM Tokens WHERE public_key = ?; "
                                       "DELETE FROM Metadata WHERE public_key = ?; "
                                       "DELETE FROM Attestations WHERE public_key = ?; "
                                       "COMMIT;",
                                       (public_key, public_key, public_key))
        database.commit()

        return attestation_hashes

    def _drop_attestation_table_data(self, attestation_hashes):
        """
        Remove all attestation data (claim based keys and ZKP blobs) by list of attestation hashes.

        :param attestation_hashes: hashes to remove
        :type attestation_hashes: [database_blob]
        :returns: None
        """
        if not attestation_hashes:
            return

        self.attestation_overlay.database.execute((u"DELETE FROM %s" % self.attestation_overlay.database.db_name)
                                                  + u" WHERE hash IN ("
                                                  + u", ".join(c for c in u"?" * len(attestation_hashes))
                                                  + u")",
                                                  attestation_hashes)
        self.attestation_overlay.database.commit()

    @docs(
        tags=["Attestation"],
        summary="Get information from the AttestationCommunity.",
        parameters=[{
            'in': 'query',
            'name': 'type',
            'description': 'Type of query',
            'type': 'string',
            'enum': ['drop_identity', 'outstanding', 'outstanding_verify', 'verification_output', 'peers', 'attributes'],
            'required': True
        }, {
            'in': 'query',
            'name': 'mid',
            'description': 'Filter by mid (only works for type=attributes)',
            'type': 'string'
        }],
        description="""
        type=drop_identity
        type=outstanding -> [(mid_b64, attribute_name)]
        type=outstanding_verify -> [(mid_b64, attribute_name)]
        type=verification_output -> {hash_b64: [(value_b64, match)]}
        type=peers -> [mid_b64]
        type=attributes&mid=mid_b64 -> [(attribute_name, attribute_hash)]
        """
    )
    async def handle_get(self, request):
        if not self.attestation_overlay or not self.identity_overlay:
            return Response({"error": "attestation or identity community not found"}, status=HTTP_NOT_FOUND)

        if not request.query or 'type' not in request.query:
            return Response({"error": "parameters or type missing"}, status=HTTP_BAD_REQUEST)

        if request.query['type'] == 'outstanding':
            formatted = []
            for k, v in self.attestation_requests.items():
                formatted.append(k + (v[1], ))
            return Response([(x, y, z) for x, y, z in formatted])

        elif request.query['type'] == 'outstanding_verify':
            formatted = self.verify_requests.keys()
            return Response([(x, y) for x, y in formatted])

        elif request.query['type'] == 'verification_output':
            formatted = {}
            for k, v in self.verification_output.items():
                formatted[b64encode(k).decode('utf-8')] = [(b64encode(a).decode('utf-8'), m) for a, m in v]
            return Response(formatted)

        elif request.query['type'] == 'peers':
            peers = self.session.network.get_peers_for_service(self.identity_overlay.master_peer.mid)
            return Response([b64encode(p.mid).decode('utf-8') for p in peers])

        elif request.query['type'] == 'attributes':
            if 'mid' in request.query:
                mid_b64 = request.query['mid']
                peer = self.get_peer_from_mid(mid_b64)
            else:
                peer = self.identity_overlay.my_peer
            if peer:
                pseudonym = self.identity_overlay.identity_manager.get_pseudonym(peer.public_key)
                trimmed = {}
                for credential in pseudonym.get_credentials():
                    # TODO: add support for more attesters
                    attestations = list(credential.attestations)
                    if attestations:
                        authority = self.identity_overlay.identity_manager.database.get_authority(attestations[0])
                        attester = b64encode(sha1(authority).digest()).decode()
                    else:
                        attester = ""
                    attribute_hash = pseudonym.tree.elements[credential.metadata.token_pointer].content_hash
                    json_metadata = json.loads(credential.metadata.serialized_json_dict)
                    trimmed[attribute_hash] = (json_metadata["name"], json_metadata, attester)
                # List of (name, attribute_hash, metadata, attester)
                return Response([(
                    data[0],
                    b64encode(strip_sha1_padding(attribute_hash)).decode(),
                    data[1],
                    data[2]) for attribute_hash, data in trimmed.items()])
            else:
                return Response([])

        elif request.query['type'] == 'drop_identity':
            to_keep = [self.persistent_key.public_key.key_to_bin()]
            if 'keep' in request.query:
                to_keep += [self.identity_overlay.my_peer.public_key.key_to_bin()]

            # Remove identity metadata and attestation proofing data, except for the keys to keep
            attestation_hashes = self._drop_identity_table_data(to_keep)
            self._drop_attestation_table_data(attestation_hashes)

            # Remove pending attestations
            self.attestation_requests.clear()

            # Generate new key
            my_new_peer = Peer(default_eccrypto.generate_key(u"curve25519"))
            identity_manager = self.identity_overlay.identity_manager
            await self.session.unload_overlay(self.identity_overlay)
            self.identity_overlay = await create_community(my_new_peer.key, self.session, identity_manager,
                                                           endpoint=self.session.endpoint)
            for overlay in self.session.overlays:
                overlay.my_peer = my_new_peer
            return Response({"success": True})

        else:
            return Response({"error": "type argument incorrect"}, status=HTTP_BAD_REQUEST)

    @docs(
        tags=["Attestation"],
        summary="Send a command to the AttestationCommunity.",
        parameters=[{
            'in': 'query',
            'name': 'type',
            'description': 'Type of query',
            'type': 'string',
            'enum': ['request', 'allow_verify', 'attest', 'verify'],
            'required': True
        }],
        description="""
        type=request&mid=mid_b64&attibute_name=attribute_name&id_format=id_format
        type=allow_verify&mid=mid_b64&attibute_name=attribute_name
        type=attest&mid=mid_b64&attribute_name=attribute_name&attribute_value=attribute_value_b64
        type=verify&mid=mid_b64&attribute_hash=attribute_hash_b64&id_format=id_format
                   &attribute_values=attribute_value_b64,...
        """
    )
    async def handle_post(self, request):
        if not self.attestation_overlay or not self.identity_overlay:
            return Response({"error": "attestation or identity community not found"}, status=HTTP_NOT_FOUND)

        args = request.query
        if not args or 'type' not in args:
            return Response({"error": "parameters or type missing"}, status=HTTP_BAD_REQUEST)

        if args['type'] == 'request':
            mid_b64 = args['mid']
            attribute_name = args['attribute_name']
            id_format = args.get('id_format', 'id_metadata')
            peer = self.get_peer_from_mid(mid_b64)
            if peer:
                key = self.attestation_overlay.get_id_algorithm(id_format).generate_secret_key()
                metadata = {"id_format": id_format}
                if 'metadata' in args:
                    metadata_unicode = json.loads(b64decode(args['metadata']))
                    metadata.update(metadata_unicode)
                self.attestation_metadata[(self.identity_overlay.my_peer, attribute_name)] = metadata
                self.attestation_overlay.request_attestation(peer, attribute_name, key, metadata)
                return Response({"success": True})
            else:
                return Response({"error": "peer unknown"}, status=HTTP_BAD_REQUEST)

        elif args['type'] == 'attest':
            mid_b64 = args['mid']
            attribute_name = args['attribute_name']
            attribute_value_b64 = args['attribute_value']
            outstanding = self.attestation_requests.pop((mid_b64, attribute_name))
            outstanding[0].set_result(b64decode(attribute_value_b64))
            return Response({"success": True})

        elif args['type'] == 'import_blob':
            # Import self-attested binary data
            attribute_name = args['attribute_name']
            id_format = args['id_format']
            metadata = {"id_format": id_format}
            if 'metadata' in args:
                metadata_unicode = json.loads(b64decode(args['metadata']))
                for k, v in metadata_unicode.items():
                    metadata[cast_to_bin(k)] = cast_to_bin(v)
            blob = await request.read()

            self.attestation_overlay.dump_blob(attribute_name, id_format, blob, metadata)

            return Response({"success": True})

        elif args['type'] == 'allow_verify':
            mid_b64 = args['mid']
            attribute_name = args['attribute_name']
            outstanding = self.verify_requests.pop((mid_b64, attribute_name))
            outstanding.set_result(True)
            return Response({"success": True})

        elif args['type'] == 'verify':
            mid_b64 = args['mid']
            attribute_hash = b64decode(args['attribute_hash'])
            reference_values = [b64decode(v) for v in args['attribute_values'].split(',')]
            id_format = args.get('id_format', 'id_metadata')
            peer = self.get_peer_from_mid(mid_b64)
            if peer:
                self.verification_output[attribute_hash] = \
                    [(b64decode(v), 0.0) for v in args['attribute_values'].split(',')]
                self.attestation_overlay.verify_attestation_values(peer.address, attribute_hash, reference_values,
                                                                   self.on_verification_results, id_format)
                return Response({"success": True})
            else:
                return Response({"error": "peer unknown"}, status=HTTP_BAD_REQUEST)

        else:
            return Response({"error": "type argument incorrect"}, status=HTTP_BAD_REQUEST)
