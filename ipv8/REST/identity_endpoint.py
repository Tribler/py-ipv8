from __future__ import annotations

import base64
from typing import TYPE_CHECKING, cast

from aiohttp import web
from aiohttp_apispec import docs, json_schema
from marshmallow.fields import Dict, Float, String

from ..attestation.communication_manager import CommunicationManager
from ..types import IPv8
from ..util import strip_sha1_padding
from .base_endpoint import HTTP_BAD_REQUEST, BaseEndpoint, MiddleWaresType, Response
from .schema import DefaultResponseSchema, schema

if TYPE_CHECKING:
    from aiohttp.abc import Application, Request

PseudonymListResponseSchema = schema(PseudonymListResponse={"names": [String]})
CredentialSchema = schema(Credential={"name": String, "hash": String, "metadata": Dict, "attesters": [String]})
CredentialListResponseSchema = schema(CredentialListResponse={"names": [CredentialSchema]})


def ez_b64_encode(s: bytes) -> str:
    """
    Encode bytes as base 64.
    """
    return base64.b64encode(s).decode()


def ez_b64_decode(s: str) -> bytes:
    """
    Decode bytes from base 64.
    """
    return base64.b64decode(s.encode())


class IdentityEndpoint(BaseEndpoint[IPv8]):
    """
    Endpoint to spawn and manipulate Self-Sovereign Identities.
    """

    def __init__(self, middlewares: MiddleWaresType = ()) -> None:
        """
        Create new unregistered and uninitialized REST endpoint.
        """
        super().__init__(middlewares)
        self.communication_manager: CommunicationManager | None = None
        self.app.on_shutdown.append(self.on_shutdown)

    def initialize(self, session: IPv8) -> None:
        """
        Initialize this endpoint for the given session instance.
        """
        super().initialize(session)
        self.communication_manager = CommunicationManager(session)

    def setup_routes(self) -> None:
        """
        Register the names to make this endpoint callable.
        """
        self.app.add_routes([web.get('', self.list_pseudonyms),

                             web.get('/{pseudonym_name}/schemas', self.list_schemas),

                             web.get('/{pseudonym_name}/public_key', self.get_pseudonym_public_key),
                             web.get('/{pseudonym_name}/unload', self.unload_pseudonym),
                             web.get('/{pseudonym_name}/remove', self.remove_pseudonym),

                             web.get('/{pseudonym_name}/credentials', self.list_pseudonym_credentials),
                             web.get('/{pseudonym_name}/credentials/{subject_key}', self.list_subject_credentials),
                             web.get('/{pseudonym_name}/peers', self.list_pseudonym_peers),

                             web.put('/{pseudonym_name}/allow/{verifier_key}', self.allow_pseudonym_verification),
                             web.put('/{pseudonym_name}/disallow/{verifier_key}', self.disallow_pseudonym_verification),
                             web.put('/{pseudonym_name}/request/{authority_key}', self.create_pseudonym_credential),

                             web.put('/{pseudonym_name}/attest/{subject_key}', self.attest_pseudonym_credential),
                             web.put('/{pseudonym_name}/verify/{subject_key}', self.verify_pseudonym_credential),

                             web.get('/{pseudonym_name}/outstanding/attestations', self.list_pseudonym_outstanding_attestations),
                             web.get('/{pseudonym_name}/outstanding/verifications', self.list_pseudonym_outstanding_verifications),

                             web.get('/{pseudonym_name}/verifications', self.list_pseudonym_verification_output)
                             ])

    @docs(
        tags=["Identity"],
        summary="List our pseudonyms.",
        responses={
            200: {
                "schema": PseudonymListResponseSchema
            }
        }
    )
    async def list_pseudonyms(self, request: Request) -> Response:
        """
        List our pseudonyms.
        """
        if self.communication_manager is None:
            return Response({"names": []})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        return Response({"names": self.communication_manager.list_names()})

    @docs(
        tags=["Identity"],
        summary="List our available identity schemas.",
        parameters=[{
            'in': 'path',
            'name': 'pseudonym_name',
            'description': 'The name of the pseudonym to use.',
            'type': 'string',
        }],
        responses={
            200: {
                "schema": schema(SchemaListResponse={"schemas": [String]})
            }
        }
    )
    async def list_schemas(self, request: Request) -> Response:
        """
        List our available identity schemas.
        """
        if self.communication_manager is None:
            return Response({"schemas": []})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        channel = await self.communication_manager.load(request.match_info['pseudonym_name'],
                                                        request.headers.get('X-Rendezvous'))
        return Response({"schemas": channel.schemas})

    @docs(
        tags=["Identity"],
        summary="Get the public key for a pseudonym.",
        parameters=[{
            'in': 'path',
            'name': 'pseudonym_name',
            'description': 'The name of the pseudonym to use.',
            'type': 'string',
        }],
        responses={
            200: {
                "schema": PseudonymListResponseSchema
            }
        }
    )
    async def get_pseudonym_public_key(self, request: Request) -> Response:
        """
        Get the public key for a pseudonym.
        """
        if self.communication_manager is None:
            return Response({"success": False, "error": "communication manager is not loaded"})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        channel = await self.communication_manager.load(request.match_info['pseudonym_name'],
                                                        request.headers.get('X-Rendezvous'))
        return Response({"public_key": ez_b64_encode(channel.public_key_bin)})

    @docs(
        tags=["Identity"],
        summary="Unload a pseudonym.",
        parameters=[{
            'in': 'path',
            'name': 'pseudonym_name',
            'description': 'The name of the pseudonym to use.',
            'type': 'string',
        }],
        responses={
            200: {
                "schema": DefaultResponseSchema,
                "example": {"success": True}
            }
        }
    )
    async def unload_pseudonym(self, request: Request) -> Response:
        """
        Unload a pseudonym.
        """
        if self.communication_manager is None:
            return Response({"success": False, "error": "communication manager is not loaded"})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        await self.communication_manager.unload(request.match_info['pseudonym_name'])
        return Response({"success": True})

    @docs(
        tags=["Identity"],
        summary="Remove a pseudonym.",
        parameters=[{
            'in': 'path',
            'name': 'pseudonym_name',
            'description': 'The name of the pseudonym to use.',
            'type': 'string',
        }],
        responses={
            200: {
                "schema": DefaultResponseSchema,
                "example": {"success": True}
            }
        }
    )
    async def remove_pseudonym(self, request: Request) -> Response:
        """
        Remove a pseudonym.
        """
        if self.communication_manager is None:
            return Response({"success": False, "error": "communication manager is not loaded"})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        await self.communication_manager.remove(request.match_info['pseudonym_name'])
        return Response({"success": True})

    @docs(
        tags=["Identity"],
        summary="List a pseudonym's credentials.",
        parameters=[{
            'in': 'path',
            'name': 'pseudonym_name',
            'description': 'The name of the pseudonym to use.',
            'type': 'string',
        }],
        responses={
            200: {
                "schema": CredentialListResponseSchema
            }
        }
    )
    async def list_pseudonym_credentials(self, request: Request) -> Response:
        """
        List a pseudonym's credentials.
        """
        if self.communication_manager is None:
            return Response({"names": []})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        channel = await self.communication_manager.load(request.match_info['pseudonym_name'],
                                                        request.headers.get('X-Rendezvous'))
        return Response({"names": [{
            "name": data[0],
            "hash": ez_b64_encode(strip_sha1_padding(attribute_hash)),
            "metadata": data[1],
            "attesters": [ez_b64_encode(attester) for attester in data[2]]
        }
            for attribute_hash, data in channel.get_my_attributes().items()]
        })

    @docs(
        tags=["Identity"],
        summary="List a subject's credentials.",
        parameters=[
            {
                'in': 'path',
                'name': 'pseudonym_name',
                'description': 'The name of the pseudonym to use.',
                'type': 'string',
            },
            {
                'in': 'path',
                'name': 'subject_key',
                'description': 'The public key of the subject to attest for.',
                'type': 'string',
            }
        ],
        responses={
            200: {
                "schema": CredentialListResponseSchema
            },
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'Subject not found': {"success": False, "error": "failed to find subject"}}
            }
        }
    )
    async def list_subject_credentials(self, request: Request) -> Response:
        """
        List a subject's credentials.
        """
        if self.communication_manager is None:
            return Response({"names": []})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        channel = await self.communication_manager.load(request.match_info['pseudonym_name'],
                                                        request.headers.get('X-Rendezvous'))

        subject = None
        for peer in channel.peers:
            if peer.public_key.key_to_bin() == ez_b64_decode(request.match_info['subject_key']):
                subject = peer
                break
        if subject is None:
            return Response({"success": False, "error": "failed to find subject"})

        return Response({"names": [{
            "name": data[0],
            "hash": ez_b64_encode(strip_sha1_padding(attribute_hash)),
            "metadata": data[1],
            "attesters": [ez_b64_encode(attester) for attester in data[2]]
        }
            for attribute_hash, data in channel.get_attributes(subject).items()]
        })

    @docs(
        tags=["Identity"],
        summary="List a pseudonym's peers.",
        parameters=[{
            'in': 'path',
            'name': 'pseudonym_name',
            'description': 'The name of the pseudonym to use.',
            'type': 'string',
        }],
        responses={
            200: {
                "schema": schema(PeerListResponse={"peers": [String]})
            }
        }
    )
    async def list_pseudonym_peers(self, request: Request) -> Response:
        """
        List a pseudonym's peers.
        """
        if self.communication_manager is None:
            return Response({"peers": []})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        channel = await self.communication_manager.load(request.match_info['pseudonym_name'],
                                                        request.headers.get('X-Rendezvous'))
        return Response({"peers": [ez_b64_encode(peer.public_key.key_to_bin()) for peer in channel.peers]})

    @docs(
        tags=["Identity"],
        summary="Verify a credential.",
        parameters=[
            {
                'in': 'path',
                'name': 'pseudonym_name',
                'description': 'The name of the pseudonym to use.',
                'type': 'string',
            },
            {
                'in': 'path',
                'name': 'verifier_key',
                'description': 'The public key of the verifier.',
                'type': 'string',
            }
        ],
        responses={
            200: {
                "schema": DefaultResponseSchema,
                "example": {"success": True}
            },
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'Authority not found': {"success": False, "error": "failed to find authority"}}
            }
        }
    )
    @json_schema(schema(AllowVerification={
        'name*': (String, 'The name of the attribute to allow verification of.')
    }))
    async def allow_pseudonym_verification(self, request: Request) -> Response:
        """
        Verify a credential.
        """
        if self.communication_manager is None:
            return Response({"success": False, "error": "communication manager is not loaded"})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        parameters = await request.json()
        if 'name' not in parameters:
            return Response({"error": "incorrect parameters"}, status=HTTP_BAD_REQUEST)

        channel = await self.communication_manager.load(request.match_info['pseudonym_name'],
                                                        request.headers.get('X-Rendezvous'))
        verifier = None
        for peer in channel.peers:
            if peer.public_key.key_to_bin() == ez_b64_decode(request.match_info['verifier_key']):
                verifier = peer
                break
        if verifier is None:
            return Response({"success": False, "error": "failed to find verifier"})

        channel.allow_verification(verifier, parameters['name'])

        return Response({"success": True})

    @docs(
        tags=["Identity"],
        summary="Disallow verification of a credential.",
        parameters=[
            {
                'in': 'path',
                'name': 'pseudonym_name',
                'description': 'The name of the pseudonym to use.',
                'type': 'string',
            },
            {
                'in': 'path',
                'name': 'verifier_key',
                'description': 'The public key of the verifier.',
                'type': 'string',
            }
        ],
        responses={
            200: {
                "schema": DefaultResponseSchema,
                "example": {"success": True}
            },
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'Authority not found': {"success": False, "error": "failed to find authority"}}
            }
        }
    )
    @json_schema(schema(DisallowVerification={
        'name*': (String, 'The name of the attribute to disallow verification of.')
    }))
    async def disallow_pseudonym_verification(self, request: Request) -> Response:
        """
        Disallow verification of a credential.
        """
        if self.communication_manager is None:
            return Response({"success": False, "error": "communication manager is not loaded"})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        parameters = await request.json()
        if 'name' not in parameters:
            return Response({"error": "incorrect parameters"}, status=HTTP_BAD_REQUEST)

        channel = await self.communication_manager.load(request.match_info['pseudonym_name'],
                                                        request.headers.get('X-Rendezvous'))
        verifier = None
        for peer in channel.peers:
            if peer.public_key.key_to_bin() == ez_b64_decode(request.match_info['verifier_key']):
                verifier = peer
                break
        if verifier is None:
            return Response({"success": False, "error": "failed to find verifier"})

        channel.disallow_verification(verifier, parameters['name'])

        return Response({"success": True})

    @docs(
        tags=["Identity"],
        summary="Create a credential.",
        parameters=[
            {
                'in': 'path',
                'name': 'pseudonym_name',
                'description': 'The name of the pseudonym to use.',
                'type': 'string',
            },
            {
                'in': 'path',
                'name': 'authority_key',
                'description': 'The public key of the authority to request attestation from.',
                'type': 'string',
            }
        ],
        responses={
            200: {
                "schema": DefaultResponseSchema,
                "example": {"success": True}
            },
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'Authority not found': {"success": False, "error": "failed to find authority"}}
            }
        }
    )
    @json_schema(schema(AttestationRequest={
        'name*': (String, 'The name of the attribute to request attestation for.'),
        'schema*': (String, 'The attribute schema to use.'),
        'metadata': (Dict, 'The metadata to attach.')
    }))
    async def create_pseudonym_credential(self, request: Request) -> Response:
        """
        Create a credential.
        """
        if self.communication_manager is None:
            return Response({"success": False, "error": "communication manager is not loaded"})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        parameters = await request.json()
        if 'name' not in parameters or 'schema' not in parameters:
            return Response({"error": "incorrect parameters"}, status=HTTP_BAD_REQUEST)

        channel = await self.communication_manager.load(request.match_info['pseudonym_name'],
                                                        request.headers.get('X-Rendezvous'))
        authority = None
        for peer in channel.peers:
            if peer.public_key.key_to_bin() == ez_b64_decode(request.match_info['authority_key']):
                authority = peer
                break
        if authority is None:
            return Response({"success": False, "error": "failed to find authority"})

        metadata = parameters['metadata'] if 'metadata' in parameters else {}
        channel.request_attestation(authority, parameters['name'], parameters['schema'], metadata)

        return Response({"success": True})

    @docs(
        tags=["Identity"],
        summary="Attest to a credential.",
        parameters=[
            {
                'in': 'path',
                'name': 'pseudonym_name',
                'description': 'The name of the pseudonym to use.',
                'type': 'string',
            },
            {
                'in': 'path',
                'name': 'subject_key',
                'description': 'The public key of the subject to attest for.',
                'type': 'string',
            }
        ],
        responses={
            200: {
                "schema": DefaultResponseSchema,
                "example": {"success": True}
            },
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'Subject not found': {"success": False, "error": "failed to find subject"}}
            }
        }
    )
    @json_schema(schema(Attestation={
        'name*': (String, 'The name of the subject\'s attribute.'),
        'value*': (String, 'The value we believe the subject\'s attribute has.')
    }))
    async def attest_pseudonym_credential(self, request: Request) -> Response:
        """
        Attest to a credential.
        """
        if self.communication_manager is None:
            return Response({"success": False, "error": "communication manager is not loaded"})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        parameters = await request.json()
        if 'name' not in parameters or 'value' not in parameters:
            return Response({"error": "incorrect parameters"}, status=HTTP_BAD_REQUEST)

        channel = await self.communication_manager.load(request.match_info['pseudonym_name'],
                                                        request.headers.get('X-Rendezvous'))

        subject = None
        for peer in channel.peers:
            if peer.public_key.key_to_bin() == ez_b64_decode(request.match_info['subject_key']):
                subject = peer
                break
        if subject is None:
            return Response({"success": False, "error": "failed to find subject"})

        channel.attest(subject, parameters["name"], ez_b64_decode(parameters["value"]))

        return Response({"success": True})

    @docs(
        tags=["Identity"],
        summary="Request verification of a credential.",
        parameters=[
            {
                'in': 'path',
                'name': 'pseudonym_name',
                'description': 'The name of the pseudonym to use.',
                'type': 'string',
            },
            {
                'in': 'path',
                'name': 'subject_key',
                'description': 'The public key of the subject to verify.',
                'type': 'string',
            }
        ],
        responses={
            200: {
                "schema": DefaultResponseSchema,
                "example": {"success": True}
            },
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'Subject not found': {"success": False, "error": "failed to find subject"}}
            }
        }
    )
    @json_schema(schema(VerificationRequest={
        'hash*': (String, 'The hash of the subject\'s attribute.'),
        'value*': (String, 'The value we require the subject\'s attribute to have.'),
        'schema*': (String, 'The schema we require the subject\'s attribute to have.')
    }))
    async def verify_pseudonym_credential(self, request: Request) -> Response:
        """
        Request verification of a credential.
        """
        if self.communication_manager is None:
            return Response({"success": False, "error": "communication manager is not loaded"})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        parameters = await request.json()
        if 'hash' not in parameters or 'value' not in parameters or 'schema' not in parameters:
            return Response({"error": "incorrect parameters"}, status=HTTP_BAD_REQUEST)

        channel = await self.communication_manager.load(request.match_info['pseudonym_name'],
                                                        request.headers.get('X-Rendezvous'))

        subject = None
        for peer in channel.peers:
            if peer.public_key.key_to_bin() == ez_b64_decode(request.match_info['subject_key']):
                subject = peer
                break
        if subject is None:
            return Response({"success": False, "error": "failed to find subject"})

        channel.verify(subject, ez_b64_decode(parameters["hash"]), [ez_b64_decode(parameters["value"])],
                       parameters["schema"])

        return Response({"success": True})

    @docs(
        tags=["Identity"],
        summary="List the oustanding requests for attestations by others.",
        parameters=[{
            'in': 'path',
            'name': 'pseudonym_name',
            'description': 'The name of the pseudonym to use.',
            'type': 'string',
        }],
        responses={
            200: {
                "schema": schema(AttestationRequestsResponse={"requests": [schema(OutstandingAttestationRequest={
                    "peer": String,
                    "attribute_name": String,
                    "metadata": Dict
                })]})
            }
        }
    )
    async def list_pseudonym_outstanding_attestations(self, request: Request) -> Response:
        """
        List the oustanding requests for attestations by others.
        """
        if self.communication_manager is None:
            return Response({"requests": []})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        channel = await self.communication_manager.load(request.match_info['pseudonym_name'],
                                                        request.headers.get('X-Rendezvous'))
        formatted = []
        for k, v in channel.attestation_requests.items():
            formatted.append({
                "peer": ez_b64_encode(k[0].public_key.key_to_bin()),
                "attribute_name": k[1],
                "metadata": v[1]
            })
        return Response({"requests": formatted})

    @docs(
        tags=["Identity"],
        summary="List the oustanding requests for verification by others.",
        parameters=[{
            'in': 'path',
            'name': 'pseudonym_name',
            'description': 'The name of the pseudonym to use.',
            'type': 'string',
        }],
        responses={
            200: {
                "schema": schema(VerificationRequestsResponse={"requests": [schema(OutstandingVerificationRequest={
                    "peer": String,
                    "attribute_name": String
                })]})
            }
        }
    )
    async def list_pseudonym_outstanding_verifications(self, request: Request) -> Response:
        """
        List the oustanding requests for verification by others.
        """
        if self.communication_manager is None:
            return Response({"requests": []})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        channel = await self.communication_manager.load(request.match_info['pseudonym_name'],
                                                        request.headers.get('X-Rendezvous'))
        formatted = [{"peer": ez_b64_encode(k[0].public_key.key_to_bin()), "attribute_name": k[1]}
                     for k in channel.verify_requests]
        return Response({"requests": formatted})

    @docs(
        tags=["Identity"],
        summary="Return the output of our verification requests.",
        parameters=[
            {
                'in': 'path',
                'name': 'pseudonym_name',
                'description': 'The name of the pseudonym to use.',
                'type': 'string',
            }
        ],
        responses={
            200: {
                "schema": schema(VerificationOutputResponse={"outputs": [schema(VerificationOutput={
                    "hash": String,
                    "reference": String,
                    "match": Float
                })]})
            }
        }
    )
    async def list_pseudonym_verification_output(self, request: Request) -> Response:
        """
        Return the output of our verification requests.
        """
        if self.communication_manager is None:
            return Response({"outputs": []})
        self.communication_manager = cast(CommunicationManager, self.communication_manager)

        channel = await self.communication_manager.load(request.match_info['pseudonym_name'],
                                                        request.headers.get('X-Rendezvous'))

        formatted = []
        for k, v in channel.verification_output.items():
            if not v or v[0][1] is None:
                # Not done yet
                continue
            formatted.append({"hash": ez_b64_encode(k), "reference": ez_b64_encode(v[0][0]), "match": v[0][1]})

        return Response({"outputs": formatted})

    async def on_shutdown(self, _: Application) -> None:
        """
        Callback when the shutdown signal fires.
        """
        if self.communication_manager:
            await self.communication_manager.shutdown()
