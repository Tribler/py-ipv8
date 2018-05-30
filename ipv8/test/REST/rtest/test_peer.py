import os
import threading
import time
from json import load
from twisted.internet.defer import returnValue, inlineCallbacks

from ipv8.configuration import get_default_configuration
from ipv8.test.REST.rtest.peer_communication import GetStyleRequests, PostStyleRequests
from ipv8.test.REST.rtest.rest_peer_communication import HTTPGetRequester, HTTPPostRequester
from ipv8.test.REST.rtest.test_rest_api_server import RestAPITestWrapper
from ipv8_service import IPv8


class TestPeer(threading.Thread):
    """
    This class models the basic behavior of simple peer instances which only forward requests. Subclasses should
    implement the actual main logic of the peer in the run() method (from Thread).
    """

    def __init__(self, get_style_requests=None, post_style_requests=None, address_book=None, *args, **kwargs):
        """
        TestPeer constructor

        :param get_style_requests: the GET request generator
        :param post_style_requests: the POST request generator
        :param address_book: an object which contains information on the fellow peers in the system,
                             and how to contact them
        :param args: remainder unnamed parameters
        :param kwargs: remainder named parameters
        """
        super(TestPeer, self).__init__(*args, **kwargs)

        self._address_book = address_book

        # Check to see if the user has provided request generators
        if get_style_requests:
            assert isinstance(get_style_requests, GetStyleRequests), "The get_style_requests parameter must be a " \
                                                                     "subclass of GetStyleRequests"
            self._get_style_requests = get_style_requests
        else:
            # If no get style request provided, default to the HTTP implementation
            self._get_style_requests = HTTPGetRequester()

        if post_style_requests:
            assert isinstance(post_style_requests, PostStyleRequests), "The post_style_requests parameter must be a " \
                                                                       "subclass of PostStyleRequests"
            self._post_style_requests = post_style_requests
        else:
            # If no post style request provided, default to the HTTP implementation
            self._post_style_requests = HTTPPostRequester()

    @inlineCallbacks
    def wait_for_peers(self, dict_param):
        """
        Wait until this peer receives a non-empty list of fellow peers in the network

        :param dict_param: the required parameters by the GET request generator for the peers request type
        :return: a list of currently known peers in the network
        """

        peer_list = yield self._get_style_requests.make_peers(dict_param)

        # Keep iterating until peer_list is non-empty
        while peer_list == "[]":
            # Wait for 4 seconds before trying again
            time.sleep(4)

            # Forward and wait for the response
            peer_list = yield self._get_style_requests.make_peers(dict_param)

        # Return the peer list
        returnValue(peer_list)

    @inlineCallbacks
    def wait_for_attestation_request(self, dict_param):
        """
        Wait until this peer receives a non-empty list of outstanding attestation requests

        :param dict_param: the required parameters by the GET request generator for the outstanding request type
        :return: a list of outstanding attestation requests
        """
        outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Keep iterating until peer_list is non-empty
        while outstanding_requests == "[]":
            # Wait for 4 seconds before trying again
            time.sleep(4)

            # Forward and wait for the response
            outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Return the peer list
        returnValue(outstanding_requests)


class TemporaryPeer(TestPeer):

    def _create_working_directory(self, path):
        """
        Creates a dir at the specified path, if not previously there; otherwise deletes the dir, and makes a new one.

        :param path: the location at which the dir is created
        :return: None
        """
        if os.path.isdir(path):
            import shutil
            shutil.rmtree(path)
        os.mkdir(path)

    def run(self):
        port = 9909
        interface = '127.0.0.1'

        # Create a default configuration
        configuration = get_default_configuration()

        configuration['logger'] = {'level': "ERROR"}

        overlays = ['AttestationCommunity', 'IdentityCommunity']
        configuration['overlays'] = [o for o in configuration['overlays'] if o['class'] in overlays]
        for o in configuration['overlays']:
            o['walkers'] = [{
                'strategy': "RandomWalk",
                'peers': 20,
                'init': {
                    'timeout': 60.0
                }
            }]

        self._create_working_directory('attester')
        os.chdir('attester')

        ipv8 = IPv8(configuration)
        os.chdir(os.path.dirname(__file__))
        manager = RestAPITestWrapper(ipv8, port, interface)
        manager.start()

        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'mid': 'apPXeBNok+8mNrd17pRjZgNWO2E='.replace("+", "%2B")
        }

        # peer_list = yield self.wait_for_peers(param_dict)
        #
        # print "From the other peer", peer_list
        #
        # for peer in load(peer_list):
        #     param_dict['mid'] = peer.replace("+", "%2B")
        self._post_style_requests.make_attestation_request(param_dict)

        while True:
            time.sleep(10)
