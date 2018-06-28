import json
import time
from base64 import b64encode
from urllib import quote
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
                 **kwargs):
        """
        AndroidTestPeer initializer

        :param param_dict: a dictionary containing the required parameters to communicate with a peer
        :param path: the for the working directory of this peer
        :param port: this peer's port
        :param kwargs: a dictionary containing additional configuration parameters:
        {
            'interface': IP or alias of the peer. Defaults to '127.0.0.1'
            'configuration': IPv8 configuration object. Defaults to None
            'get_style_requests': GET style request generator. Defaults to None
            'post_style_requests': POST style request generator. Defaults to None
        }
        """
        interface = kwargs.get('interface', '127.0.0.1')
        configuration = kwargs.get('configuration', None)
        get_style_requests = kwargs.get('get_style_requests', None)
        post_style_requests = kwargs.get('post_style_requests', None)

        InteractiveTestPeer.__init__(self,
                                     path=path,
                                     port=port,
                                     interface=interface,
                                     configuration=configuration,
                                     get_style_requests=get_style_requests,
                                     post_style_requests=post_style_requests)

        self._param_dict = param_dict
        self._param_dict['port'] = port
        self._param_dict['attribute_value'] = quote(b64encode('binarydata')).replace("+", "%2B")
        self._param_dict['metadata'] = b64encode(json.dumps({'psn': '1234567890'}))

    @inlineCallbacks
    def run(self):
        time.sleep(1)

        peer_list = yield self.wait_for_peers(self._param_dict)

        import ast
        peer_list = ast.literal_eval(peer_list)

        for peer in peer_list:
            self._param_dict['mid'] = peer.replace('+', '%2B')

            self._logger.info("Sending an attestation request to %s", self._param_dict['mid'])
            yield self._post_style_requests.make_attestation_request(self._param_dict)
