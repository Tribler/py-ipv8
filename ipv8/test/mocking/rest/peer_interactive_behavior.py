from __future__ import absolute_import

import json
from base64 import b64encode

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.threads import blockingCallFromThread

from .rest_api_peer import InteractiveRestTestPeer
from .rest_peer_communication import string_to_url


class AECommonBehaviorTestPeer(InteractiveRestTestPeer):
    """
    This class implements some auxiliary methods which may be common across a number of test peers with interaction
    facilities
    """

    @inlineCallbacks
    def wait_for_peers(self, dict_param, excluded_peer_mids=None):
        """
        Wait until this peer receives a non-empty list of fellow peers in the network

        :param dict_param: the required parameters by the GET request generator for the peers request type
        :param excluded_peer_mids: A list of peer mids which should not be taken into consideration as valid peers
        :return: a list of currently known peers in the network bar those passed as exceptions
        """
        assert isinstance(excluded_peer_mids, (list, set)) or not excluded_peer_mids, "excluded_peer_mids " \
                                                                                      "must be a list or set or None"

        # Make sure excluded_peer_mids is a set
        if not excluded_peer_mids:
            excluded_peer_mids = set()
        elif isinstance(excluded_peer_mids, list):
            excluded_peer_mids = set(excluded_peer_mids)

        peer_list = yield self._get_style_requests.make_peers(dict_param)
        peer_list = set(peer_list)

        # Keep iterating until peer_list is non-empty
        while not peer_list - excluded_peer_mids:
            yield self.sleep()

            # Forward and wait for the response
            peer_list = yield self._get_style_requests.make_peers(dict_param)
            peer_list = set(peer_list)

        # Return the peer list
        returnValue(list(peer_list - excluded_peer_mids))

    @inlineCallbacks
    def wait_for_attestation_request(self, dict_param):
        """
        Wait until this peer receives a non-empty list of outstanding attestation requests

        :param dict_param: the required parameters by the GET request generator for the outstanding request type
        :return: a list of outstanding attestation requests
        """
        self._logger.info("Attempting to acquire a list of outstanding requests...")
        outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Keep iterating until peer_list is non-empty
        while not outstanding_requests:
            self._logger.info("Could not acquire a list of outstanding requests. Will wait 0.1 seconds and retry.")
            yield self.sleep()

            # Forward and wait for the response
            outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Return the peer list
        self._logger.info("Have found a non-empty list of outstanding requests. Returning it.")
        returnValue(outstanding_requests)


class RequesterRestTestPeer(AECommonBehaviorTestPeer):
    """
    Simulates the android application
    """

    def __init__(self, port, overlay_classes, get_style_requests, post_style_requests, param_dict,
                 interface='127.0.0.1', memory_dbs=True):
        """
        AndroidTestPeer initializer

        :param port: this peer's port
        :param overlay_classes: the set of overlay classes which should be contained in the peer's IPv8 session object
        :param get_style_requests: GET style request generator
        :param post_style_requests: POST style request generator
        :param param_dict: a dictionary containing the required parameters to communicate with a peer
        :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
        :param memory_dbs: if True, then the DBs of the various overlays / communities are stored in memory; on disk
                           if False
        """
        AECommonBehaviorTestPeer.__init__(self, port, overlay_classes, get_style_requests, post_style_requests,
                                          interface=interface, memory_dbs=memory_dbs)

        self._param_dict = param_dict
        self._param_dict['port'] = port
        self._param_dict['attribute_value'] = string_to_url(b64encode(b'binarydata'), True)
        self._param_dict['metadata'] = b64encode(json.dumps({'psn': '1234567890'}).encode('utf-8')).decode('utf-8')

    def run(self):
        @inlineCallbacks
        def inner_run():
            # Wait for a short period of time
            yield self.sleep()

            peer_list = yield self.wait_for_peers(self._param_dict)
            for peer in peer_list:
                self._param_dict['mid'] = string_to_url(peer)

                self._logger.info("Sending an attestation request to %s", self._param_dict['mid'])
                yield self._post_style_requests.make_attestation_request(self._param_dict)
        blockingCallFromThread(reactor, inner_run)


class MinimalActivityRestTestPeer(AECommonBehaviorTestPeer):
    """
    Simulates a minimal activity test peer, which only attempts to discover fellow peers then goes inactive
    """

    def __init__(self, port, overlay_classes, get_style_requests, param_dict, interface='127.0.0.1', memory_dbs=True):
        """
        MinimalActivityTestPeer initializer

        :param port: this peer's port
        :param overlay_classes: the set of overlay classes which should be contained in the peer's IPv8 session object
        :param get_style_requests: GET style request generator
        :param param_dict: a dictionary containing the required parameters to communicate with a peer
        :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
        """
        AECommonBehaviorTestPeer.__init__(self, port, overlay_classes, get_style_requests, None,
                                          interface=interface, memory_dbs=memory_dbs)

        self._param_dict = param_dict
        self._param_dict['port'] = port

    def run(self):
        @inlineCallbacks
        def inner_run():
            # Wait for a short period of time
            yield self.sleep()

            # Await for some fellow peers, then become inactive
            yield self.wait_for_peers(self._param_dict)
        blockingCallFromThread(reactor, inner_run)
