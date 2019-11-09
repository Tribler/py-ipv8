from binascii import unhexlify

from aiohttp import web

from .base_endpoint import BaseEndpoint, HTTP_NOT_FOUND, Response
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
                             web.get('/users/{pub_key}', self.get_blocks_for_user)])

    def initialize(self, session):
        super(TrustchainEndpoint, self).initialize(session)
        self.trustchain = next((o for o in session.overlays if isinstance(o, TrustChainCommunity)), None)

    def get_recent_blocks(self, request):
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

    def get_block(self, request):
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

    def get_users(self, request):
        if not self.trustchain:
            return Response({"error": "Trustchain community not found"}, status=HTTP_NOT_FOUND)

        limit = 100
        if 'limit' in request.query:
            limit = int(request.query['limit'])

        users_info = self.trustchain.persistence.get_users(limit=limit)
        return Response({"users": users_info})

    def get_blocks_for_user(self, request):
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
