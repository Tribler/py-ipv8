from __future__ import absolute_import

from binascii import unhexlify
import json

from twisted.web import http

from ..attestation.trustchain.community import TrustChainCommunity
from .formal_endpoint import FormalEndpoint
from .validation.annotations import RESTInput, RESTOutput
from .validation.types import NUMBER_TYPE, OptionalKey, STR_TYPE, UNKNOWN_OBJECT


class TrustchainEndpoint(FormalEndpoint):
    """
    This endpoint is responsible for handing all requests regarding TrustChain.
    """

    def __init__(self, session):
        super(TrustchainEndpoint, self).__init__()

        trustchain_overlays = [overlay for overlay in session.overlays if isinstance(overlay, TrustChainCommunity)]
        if trustchain_overlays:
            self.putChild("recent", TrustchainRecentEndpoint(trustchain_overlays[0]))
            self.putChild("blocks", TrustchainBlocksEndpoint(trustchain_overlays[0]))
            self.putChild("users", TrustchainUsersEndpoint(trustchain_overlays[0]))


class TrustchainRecentEndpoint(FormalEndpoint):

    def __init__(self, trustchain):
        super(TrustchainRecentEndpoint, self).__init__()
        self.trustchain = trustchain

    @RESTInput("limit", NUMBER_TYPE)
    @RESTInput("offset", NUMBER_TYPE)
    @RESTOutput(lambda request: True,
                ({
                     "blocks": [{
                         "type": STR_TYPE["ASCII"],
                         "transaction": (UNKNOWN_OBJECT, "JSON object belonging to this type."),
                         "public_key": STR_TYPE["HEX"],
                         "sequence_number": NUMBER_TYPE,
                         "link_public_key": NUMBER_TYPE,
                         "link_sequence_number": NUMBER_TYPE,
                         "previous_hash": STR_TYPE["HEX"],
                         "signature": STR_TYPE["HEX"],
                         "timestamp": NUMBER_TYPE,
                         "hash": STR_TYPE["HEX"],
                         "insert_time":STR_TYPE["ASCII"]
                     }]
                 },
                 "Fetch recently added blocks."))
    def render_GET(self, request):
        limit = 10
        offset = 0
        if request.args and 'limit' in request.args:
            limit = int(request.args['limit'][0])

        if request.args and 'offset' in request.args:
            offset = int(request.args['offset'][0])

        return json.dumps({"blocks": [dict(block) for block in
                                      self.trustchain.persistence.get_recent_blocks(limit=limit, offset=offset)]})


class TrustchainBlocksEndpoint(FormalEndpoint):

    def __init__(self, trustchain):
        super(TrustchainBlocksEndpoint, self).__init__()
        self.trustchain = trustchain

    def getChild(self, path, request):
        return TrustchainSpecificBlockEndpoint(self.trustchain, path)

    def generate_documentation(self, absolute_path=[]):
        super(TrustchainBlocksEndpoint, self).generate_documentation(absolute_path)
        TrustchainSpecificBlockEndpoint(None, "").generate_documentation(absolute_path + ["%s"])


class TrustchainSpecificBlockEndpoint(FormalEndpoint):

    def __init__(self, trustchain, block_hash):
        super(TrustchainSpecificBlockEndpoint, self).__init__()
        self.trustchain = trustchain
        try:
            self.block_hash = unhexlify(block_hash)
        except TypeError:
            self.block_hash = None

    @RESTOutput(lambda request: True,
                ({
                     "block": {
                         "type": STR_TYPE["ASCII"],
                         "transaction": (UNKNOWN_OBJECT, "JSON object belonging to this type."),
                         "public_key": STR_TYPE["HEX"],
                         "sequence_number": NUMBER_TYPE,
                         "link_public_key": NUMBER_TYPE,
                         "link_sequence_number": NUMBER_TYPE,
                         "previous_hash": STR_TYPE["HEX"],
                         "signature": STR_TYPE["HEX"],
                         "timestamp": NUMBER_TYPE,
                         "hash": STR_TYPE["HEX"],
                         "insert_time": STR_TYPE["ASCII"],
                         OptionalKey("linked"): ({
                                                     "type": STR_TYPE["ASCII"],
                                                     "transaction": (UNKNOWN_OBJECT,
                                                                     "JSON object belonging to this type."),
                                                     "public_key": STR_TYPE["HEX"],
                                                     "sequence_number": NUMBER_TYPE,
                                                     "link_public_key": NUMBER_TYPE,
                                                     "link_sequence_number": NUMBER_TYPE,
                                                     "previous_hash": STR_TYPE["HEX"],
                                                     "signature": STR_TYPE["HEX"],
                                                     "timestamp": NUMBER_TYPE,
                                                     "hash": STR_TYPE["HEX"],
                                                     "insert_time":STR_TYPE["ASCII"]
                                                 }, "The dictionary describing the linked block")
                     }
                 },
                 "Fetch a specific block."))
    @RESTOutput(lambda request: True,
                {
                    "error": (STR_TYPE["ASCII"], "The available information in case of no success.")
                },
                http.NOT_FOUND)
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


class TrustchainUsersEndpoint(FormalEndpoint):

    def __init__(self, trustchain):
        super(TrustchainUsersEndpoint, self).__init__()
        self.trustchain = trustchain

    def getChild(self, path, request):
        return TrustchainSpecificUserEndpoint(self.trustchain, path)

    @RESTInput("limit", NUMBER_TYPE)
    @RESTOutput(lambda request: True,
                ({
                     "users": {
                         "public_key": STR_TYPE["HEX"],
                         "blocks": NUMBER_TYPE
                     }
                 },
                 "Fetch the known users."))
    def render_GET(self, request):
        limit = 100
        if 'limit' in request.args:
            limit = int(request.args['limit'][0])

        users_info = self.trustchain.persistence.get_users(limit=limit)
        return json.dumps({"users": users_info})

    def generate_documentation(self, absolute_path=[]):
        super(TrustchainUsersEndpoint, self).generate_documentation(absolute_path)
        TrustchainSpecificUserEndpoint(None, "%s").generate_documentation(absolute_path + ["%s"])


class TrustchainSpecificUserEndpoint(FormalEndpoint):

    def __init__(self, trustchain, pub_key):
        super(TrustchainSpecificUserEndpoint, self).__init__()
        self.trustchain = trustchain
        self.pub_key = pub_key

        self.putChild("blocks", TrustchainSpecificUserBlocksEndpoint(self.trustchain, self.pub_key))


class TrustchainSpecificUserBlocksEndpoint(FormalEndpoint):

    def __init__(self, trustchain, pub_key):
        super(TrustchainSpecificUserBlocksEndpoint, self).__init__()
        self.trustchain = trustchain
        try:
            self.pub_key = unhexlify(pub_key)
        except TypeError:
            self.pub_key = None

    @RESTInput("limit", NUMBER_TYPE)
    @RESTOutput(lambda request: True,
                ({
                     "blocks": [
                         {
                             "type": STR_TYPE["ASCII"],
                             "transaction": (UNKNOWN_OBJECT, "JSON object belonging to this type."),
                             "public_key": STR_TYPE["HEX"],
                             "sequence_number": NUMBER_TYPE,
                             "link_public_key": NUMBER_TYPE,
                             "link_sequence_number": NUMBER_TYPE,
                             "previous_hash": STR_TYPE["HEX"],
                             "signature": STR_TYPE["HEX"],
                             "timestamp": NUMBER_TYPE,
                             "hash": STR_TYPE["HEX"],
                             "insert_time": STR_TYPE["ASCII"],
                             OptionalKey("linked"): ({
                                                         "type": STR_TYPE["ASCII"],
                                                         "transaction": (UNKNOWN_OBJECT,
                                                                         "JSON object belonging to this type."),
                                                         "public_key": STR_TYPE["HEX"],
                                                         "sequence_number": NUMBER_TYPE,
                                                         "link_public_key": NUMBER_TYPE,
                                                         "link_sequence_number": NUMBER_TYPE,
                                                         "previous_hash": STR_TYPE["HEX"],
                                                         "signature": STR_TYPE["HEX"],
                                                         "timestamp": NUMBER_TYPE,
                                                         "hash": STR_TYPE["HEX"],
                                                         "insert_time": STR_TYPE["ASCII"]
                                                     }, "The dictionary describing the linked block")
                         }
                     ]
                 },
                 "Fetch the known users."))
    @RESTOutput(lambda request: True,
                {
                    "error": (STR_TYPE["ASCII"], "The available information in case of no success.")
                },
                http.NOT_FOUND)
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
