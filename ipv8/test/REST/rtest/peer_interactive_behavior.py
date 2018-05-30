from json import load

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
        super(AndroidTestPeer, self).__init__(path,
                                              port,
                                              interface,
                                              configuration,
                                              get_style_requests,
                                              post_style_requests)

        self._param_dict = param_dict
        self._param_dict['attribute'] = 'QR'

    def run(self):
        peer_list = yield self.wait_for_peers(self._param_dict)

        for peer in load(peer_list):
            print "HERE", peer
            self._param_dict['mid'] = peer.replace('+', '%2B')
            self.wait_for_attestation_request(self._param_dict)
