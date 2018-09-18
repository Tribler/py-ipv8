from __future__ import absolute_import

from binascii import unhexlify
import json

from twisted.web import http
from twisted.web import resource

from ..attestation.trustchain.community import TrustChainCommunity


class TrustchainEndpoint(resource.Resource):
    """
    This endpoint is responsible for handing all requests regarding TrustChain.
    """

    def __init__(self, session):
        resource.Resource.__init__(self)

        trustchain_overlays = [overlay for overlay in session.overlays if isinstance(overlay, TrustChainCommunity)]
        if trustchain_overlays:
            self.putChild("recent", TrustchainRecentEndpoint(trustchain_overlays[0]))
            self.putChild("blocks", TrustchainBlocksEndpoint(trustchain_overlays[0]))
            self.putChild("users", TrustchainUsersEndpoint(trustchain_overlays[0]))


class TrustchainRecentEndpoint(resource.Resource):

    def __init__(self, trustchain):
        resource.Resource.__init__(self)
        self.trustchain = trustchain

    def render_GET(self, request):
        limit = 10
        offset = 0
        if request.args and 'limit' in request.args:
            limit = int(request.args['limit'][0])

        if request.args and 'offset' in request.args:
            offset = int(request.args['offset'][0])

        return json.dumps({"blocks": [dict(block) for block in
                                      self.trustchain.persistence.get_recent_blocks(limit=limit, offset=offset)]})


class TrustchainBlocksEndpoint(resource.Resource):

    def __init__(self, trustchain):
        resource.Resource.__init__(self)
        self.trustchain = trustchain

    def getChild(self, path, request):
        return TrustchainSpecificBlockEndpoint(self.trustchain, path)


class TrustchainSpecificBlockEndpoint(resource.Resource):

    def __init__(self, trustchain, block_hash):
        resource.Resource.__init__(self)
        self.trustchain = trustchain
        try:
            self.block_hash = unhexlify(block_hash)
        except TypeError:
            self.block_hash = None

    def render_GET(self, request):
        if not self.block_hash:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "the block with the provided hash could not be found"})

        block = self.trustchain.persistence.get_block_with_hash(self.block_hash)
        if not block:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "the block with the provided hash could not be found"})

        block_dict = dict(block)

        # Fetch the linked block if available
        linked_block = self.trustchain.persistence.get_linked(block)
        if linked_block:
            block_dict["linked"] = dict(linked_block)

        return json.dumps({"block": block_dict})


class TrustchainUsersEndpoint(resource.Resource):

    def __init__(self, trustchain):
        resource.Resource.__init__(self)
        self.trustchain = trustchain

    def getChild(self, path, request):
        return TrustchainSpecificUserEndpoint(self.trustchain, path)

    def render_GET(self, request):
        limit = 100
        if 'limit' in request.args:
            limit = int(request.args['limit'][0])

        users_info = self.trustchain.persistence.get_users(limit=limit)
        return json.dumps({"users": users_info})


class TrustchainSpecificUserEndpoint(resource.Resource):

    def __init__(self, trustchain, pub_key):
        resource.Resource.__init__(self)
        self.trustchain = trustchain
        self.pub_key = pub_key

        self.putChild("blocks", TrustchainSpecificUserBlocksEndpoint(self.trustchain, self.pub_key))


class TrustchainSpecificUserBlocksEndpoint(resource.Resource):

    def __init__(self, trustchain, pub_key):
        resource.Resource.__init__(self)
        self.trustchain = trustchain
        try:
            self.pub_key = unhexlify(pub_key)
        except TypeError:
            self.pub_key = None

    def render_GET(self, request):
        if not self.pub_key:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "the user with the provided public key could not be found"})

        limit = 100
        if 'limit' in request.args:
            limit = int(request.args['limit'][0])

        latest_blocks = self.trustchain.persistence.get_latest_blocks(self.pub_key, limit=limit)
        blocks_list = []
        for block in latest_blocks:
            block_dict = dict(block)
            linked_block = self.trustchain.persistence.get_linked(block)
            if linked_block:
                block_dict['linked'] = dict(linked_block)
            blocks_list.append(block_dict)

        return json.dumps({"blocks": blocks_list})
