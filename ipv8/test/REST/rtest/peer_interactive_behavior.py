import threading
from twisted.internet.defer import inlineCallbacks

from ipv8.test.REST.rtest.test_rest_api_peer import InteractiveTestPeer


class AndroidTestPeer(InteractiveTestPeer):
    """
    Simulates the android application
    """

    def __init__(self,
                 param_dict,
                 path,
                 port,
                 interface='127.0.0.1',
                 configuration=None,
                 get_style_requests=None,
                 post_style_requests=None):
        InteractiveTestPeer.__init__(self, path,
                                     port,
                                     interface,
                                     configuration,
                                     get_style_requests,
                                     post_style_requests)
        threading.Thread.__init__(self)

        self._param_dict = param_dict
        self._param_dict['attribute_name'] = 'QR'

    @inlineCallbacks
    def run(self):
        peer_list = yield self.wait_for_peers(self._param_dict)

        import ast
        peer_list = ast.literal_eval(peer_list)

        for peer in peer_list:
            self._param_dict['mid'] = peer.replace('+', '%2B')

            self._logger.info("Sending an attestation request to %s" % peer)
            print "AndroidTestPeer: Sending an attestation request to", peer
            response = yield self._post_style_requests.make_attestation_request(self._param_dict)
