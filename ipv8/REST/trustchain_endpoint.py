from binascii import hexlify, unhexlify

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
        self.trustchains = None

    def setup_routes(self):
        self.app.add_routes([web.get('/recent', self.get_recent_blocks),
                             web.get('/blocks/{block_hash}', self.get_block),
                             web.get('/users', self.get_users),
                             web.get('/users/{pub_key}/blocks', self.get_blocks_for_user),
                             web.get('/{community_id}/recent', self.get_recent_blocks_cid),
                             web.get('/{community_id}/blocks/{block_hash}', self.get_block_cid),
                             web.get('/{community_id}/users', self.get_users_cid),
                             web.get('/{community_id}/users/{pub_key}/blocks', self.get_blocks_for_user_cid)
                             ])

    def initialize(self, session):
        super(TrustchainEndpoint, self).initialize(session)
        self.trustchains = list(session.get_overlays(TrustChainCommunity))

    def get_most_appropriate_trustchain_id(self):
        """
        Get a suggestion for a Trustchain community, if the user did not specify one.
        """
        if self.trustchains:
            # Pick the most high-level Trustchain (the least subclassed).
            return hexlify(sorted(self.trustchains,
                                  key=lambda x: len(x.__class__.mro()))[0].master_peer.mid).decode("utf-8")
        else:
            return None

    def inject_tcid(self, tcid, rel_url):
        """
        Inject the given Trustchain in the given relative URL.
        """
        url_split = str(rel_url).split('/')
        url_split.insert(2, tcid)
        return "/".join(url_split)

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
        tcid = self.get_most_appropriate_trustchain_id()
        if tcid is None:
            return Response({"error": "Trustchain not loaded"}, status=HTTP_NOT_FOUND)
        raise web.HTTPFound(self.inject_tcid(tcid, request.rel_url))

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
        tcid = self.get_most_appropriate_trustchain_id()
        if tcid is None:
            return Response({"error": "Trustchain not loaded"}, status=HTTP_NOT_FOUND)
        raise web.HTTPFound(self.inject_tcid(tcid, request.rel_url))

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
        tcid = self.get_most_appropriate_trustchain_id()
        if tcid is None:
            return Response({"error": "Trustchain not loaded"}, status=HTTP_NOT_FOUND)
        raise web.HTTPFound(self.inject_tcid(tcid, request.rel_url))

    @docs(
        tags=["TrustChain"],
        summary="Return a list of blocks for a specific user.",
        parameters=[{
            'in': 'path',
            'name': 'pub_key',
            'description': 'Public key of the user for which to return blocks from',
            'type': 'string',
        }, {
            'in': 'path',
            'name': 'community_id',
            'description': 'Community identifier of the Trustchain subclass to query',
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
        tcid = self.get_most_appropriate_trustchain_id()
        if tcid is None:
            return Response({"error": "Trustchain not loaded"}, status=HTTP_NOT_FOUND)
        raise web.HTTPFound(self.inject_tcid(tcid, request.rel_url))

    @docs(
        tags=["TrustChain"],
        summary="Return a list of recently created blocks.",
        parameters=[{
            'in': 'path',
            'name': 'community_id',
            'description': 'Community identifier of the Trustchain subclass to query',
            'type': 'string',
        }, {
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
    async def get_recent_blocks_cid(self, request):
        if not self.trustchains:
            return Response({"error": "Trustchain not loaded"}, status=HTTP_NOT_FOUND)
        community_id = unhexlify(request.match_info['community_id'])
        trustchain = [community for community in self.trustchains if community.master_peer.mid == community_id]
        print("Looking for", hexlify(community_id), "got:", [hexlify(community.master_peer.mid) for community in self.trustchains])
        if not trustchain:
            return Response({"error": "Trustchain community not found"}, status=HTTP_NOT_FOUND)
        trustchain = trustchain[0]

        limit = 10
        offset = 0
        if request.query and 'limit' in request.query:
            limit = int(request.query['limit'])

        if request.query and 'offset' in request.query:
            offset = int(request.query['offset'])

        return Response({"blocks": [dict(block) for block in
                                    trustchain.persistence.get_recent_blocks(limit=limit, offset=offset)]})

    @docs(
        tags=["TrustChain"],
        summary="Return a specific block.",
        parameters=[{
            'in': 'path',
            'name': 'community_id',
            'description': 'Community identifier of the Trustchain subclass to query',
            'type': 'string',
        }, {
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
    async def get_block_cid(self, request):
        if not self.trustchains:
            return Response({"error": "Trustchain not loaded"}, status=HTTP_NOT_FOUND)
        community_id = unhexlify(request.match_info['community_id'])
        trustchain = [community for community in self.trustchains if community.master_peer.mid == community_id]
        if not trustchain:
            return Response({"error": "Trustchain community not found"}, status=HTTP_NOT_FOUND)
        trustchain = trustchain[0]

        block_hash = unhexlify(request.match_info['block_hash'])
        if not block_hash:
            return Response({"error": "the block with the provided hash could not be found"},
                            status=HTTP_NOT_FOUND)

        block = trustchain.persistence.get_block_with_hash(block_hash)
        if not block:
            return Response({"error": "the block with the provided hash could not be found"},
                            status=HTTP_NOT_FOUND)

        block_dict = dict(block)

        # Fetch the linked block if available
        linked_block = trustchain.persistence.get_linked(block)
        if linked_block:
            block_dict["linked"] = dict(linked_block)

        return Response({"block": block_dict})

    @docs(
        tags=["TrustChain"],
        summary="Return a list of known users from the blockchain.",
        parameters=[{
            'in': 'path',
            'name': 'community_id',
            'description': 'Community identifier of the Trustchain subclass to query',
            'type': 'string',
        }, {
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
    async def get_users_cid(self, request):
        if not self.trustchains:
            return Response({"error": "Trustchain not loaded"}, status=HTTP_NOT_FOUND)
        community_id = unhexlify(request.match_info['community_id'])
        trustchain = [community for community in self.trustchains if community.master_peer.mid == community_id]
        if not trustchain:
            return Response({"error": "Trustchain community not found"}, status=HTTP_NOT_FOUND)
        trustchain = trustchain[0]

        limit = 100
        if 'limit' in request.query:
            limit = int(request.query['limit'])

        users_info = trustchain.persistence.get_users(limit=limit)
        for user in users_info:
            user['public_key'] = user['public_key'].decode('utf-8')
        return Response({"users": users_info})

    @docs(
        tags=["TrustChain"],
        summary="Return a list of blocks for a specific user.",
        parameters=[{
            'in': 'path',
            'name': 'community_id',
            'description': 'Community identifier of the Trustchain subclass to query',
            'type': 'string',
        }, {
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
    async def get_blocks_for_user_cid(self, request):
        if not self.trustchains:
            return Response({"error": "Trustchain not loaded"}, status=HTTP_NOT_FOUND)
        community_id = unhexlify(request.match_info['community_id'])
        trustchain = [community for community in self.trustchains if community.master_peer.mid == community_id]
        if not trustchain:
            return Response({"error": "Trustchain community not found"}, status=HTTP_NOT_FOUND)
        trustchain = trustchain[0]

        pub_key = unhexlify(request.match_info['pub_key'])
        if not pub_key:
            return Response({"error": "the user with the provided public key could not be found"},
                            status=HTTP_NOT_FOUND)

        limit = 100
        if 'limit' in request.query:
            limit = int(request.query['limit'])

        latest_blocks = trustchain.persistence.get_latest_blocks(pub_key, limit=limit)
        blocks_list = []
        for block in latest_blocks:
            block_dict = dict(block)
            linked_block = self.trustchain.persistence.get_linked(block)
            if linked_block:
                block_dict['linked'] = dict(linked_block)
            blocks_list.append(block_dict)

        return Response({"blocks": blocks_list})
