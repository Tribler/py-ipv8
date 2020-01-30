from binascii import unhexlify

from aiohttp import web

from aiohttp_apispec import docs

from marshmallow.fields import Integer, String

from .base_endpoint import BaseEndpoint, HTTP_NOT_FOUND, Response
from .schema import BlockSchema, schema
from ..attestation.trustchain.community import TrustChainCommunity


class TrustchainEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handing all requests regarding TrustChain.
    """

    def __init__(self):
        super(TrustchainEndpoint, self).__init__()
        self.trustchain = None

    def setup_routes(self):
        self.app.add_routes([web.get('/recent', self.get_recent_blocks),
                             web.get('/blocks/{block_hash}', self.get_block),
                             web.get('/users', self.get_users),
                             web.get('/users/{pub_key}/blocks', self.get_blocks_for_user)])

    def initialize(self, session):
        super(TrustchainEndpoint, self).initialize(session)
        self.trustchain = session.get_overlay(TrustChainCommunity)

    @docs(
        tags=["TrustChain"],
        summary="Return a list of recently created blocks.",
        parameters=[{
            'in': 'query',
            'name': 'limit',
            'description': 'Maximum number of blocks to return',
            'type': 'integer',
        }, {
            'in': 'query',
            'name': 'offset',
            'description': 'Number of most recent blocks to skip',
            'type': 'integer'
        }],
        responses={
            200: {
                "schema": schema(RecentBlocksResponse={
                    "blocks": [BlockSchema]
                })
            }
        }
    )
    async def get_recent_blocks(self, request):
        if not self.trustchain:
            return Response({"error": "Trustchain community not found"}, status=HTTP_NOT_FOUND)

        limit = 10
        offset = 0
        if request.query and 'limit' in request.query:
            limit = int(request.query['limit'])

        if request.query and 'offset' in request.query:
            offset = int(request.query['offset'])

        return Response({
            "blocks": [dict(block) for block in
                       self.trustchain.persistence.get_recent_blocks(limit=limit, offset=offset)]
        })

    @docs(
        tags=["TrustChain"],
        summary="Return a specific block.",
        parameters=[{
            'in': 'path',
            'name': 'block_hash',
            'description': 'Hash of the block to return',
            'type': 'string',
        }],
        responses={
            200: {
                "schema": schema(BlockResponse={
                    "block": BlockSchema
                })
            }
        }
    )
    async def get_block(self, request):
        if not self.trustchain:
            return Response({"error": "Trustchain community not found"}, status=HTTP_NOT_FOUND)

        block_hash = unhexlify(request.match_info['block_hash'])
        if not block_hash:
            return Response({"error": "the block with the provided hash could not be found"},
                            status=HTTP_NOT_FOUND)

        block = self.trustchain.persistence.get_block_with_hash(block_hash)
        if not block:
            return Response({"error": "the block with the provided hash could not be found"},
                            status=HTTP_NOT_FOUND)

        block_dict = dict(block)

        # Fetch the linked block if available
        linked_block = self.trustchain.persistence.get_linked(block)
        if linked_block:
            block_dict["linked"] = dict(linked_block)

        return Response({"block": block_dict})

    @docs(
        tags=["TrustChain"],
        summary="Return a list of known users from the blockchain.",
        parameters=[{
            'in': 'query',
            'name': 'limit',
            'description': 'Maximum nubmer of users to return',
            'type': 'integer',
        }],
        responses={
            200: {
                "schema": schema(UsersResponse={
                    "users": [schema(User={
                        "public_key": String,
                        "blocks": Integer
                    })]
                })
            }
        }
    )
    async def get_users(self, request):
        if not self.trustchain:
            return Response({"error": "Trustchain community not found"}, status=HTTP_NOT_FOUND)

        limit = 100
        if 'limit' in request.query:
            limit = int(request.query['limit'])

        users_info = self.trustchain.persistence.get_users(limit=limit)
        for user in users_info:
            user['public_key'] = user['public_key'].decode('utf-8')
        return Response({"users": users_info})

    @docs(
        tags=["TrustChain"],
        summary="Return a list of blocks for a specific user.",
        parameters=[{
            'in': 'path',
            'name': 'pub_key',
            'description': 'Public key of the user for which to return blocks from',
            'type': 'string',
        }],
        responses={
            200: {
                "schema": schema(BlocksForUserResponse={
                    "blocks": [BlockSchema]
                })
            }
        }
    )
    async def get_blocks_for_user(self, request):
        if not self.trustchain:
            return Response({"error": "Trustchain community not found"}, status=HTTP_NOT_FOUND)

        pub_key = unhexlify(request.match_info['pub_key'])
        if not pub_key:
            return Response({"error": "the user with the provided public key could not be found"},
                            status=HTTP_NOT_FOUND)

        limit = 100
        if 'limit' in request.query:
            limit = int(request.query['limit'])

        latest_blocks = self.trustchain.persistence.get_latest_blocks(pub_key, limit=limit)
        blocks_list = []
        for block in latest_blocks:
            block_dict = dict(block)
            linked_block = self.trustchain.persistence.get_linked(block)
            if linked_block:
                block_dict['linked'] = dict(linked_block)
            blocks_list.append(block_dict)

        return Response({"blocks": blocks_list})
