from __future__ import absolute_import

import logging
import os
import random
import socket
from shutil import rmtree
from string import ascii_uppercase, digits
from threading import Thread

from six.moves import xrange

from twisted.internet.defer import inlineCallbacks
from twisted.internet.error import CannotListenError

from .rest_api_peer import RestTestPeer
from ...base import TestBase

TEST_FOLDER_PREFIX = "test_temp"


class RESTTestBase(TestBase):

    def __init__(self, methodName='runTest'):
        super(RESTTestBase, self).__init__(methodName)

        self.nodes = []
        self.working_dirs = set([])

        self._get_style_requests = None
        self._post_style_requests = None

    def initialize_configurations(self, peer_configurations, get_style_requests, post_style_requests):
        """
        Initialize this test by instantiating some peers

        :param peer_configurations: a list o tuples of the form (int, <? extends TestPeer>); each tuple will initialize
                                    as many peers of the type in the second element as in the first element
        :param get_style_requests: GET style request generator. Defaults to None.
        :param post_style_requests: POST style request generator. Defaults to None.
        :return: None
        """
        assert isinstance(peer_configurations, list), "peer_configurations must be a list"
        assert all(isinstance(x[0], int) and issubclass(x[1], RestTestPeer) for x in peer_configurations), \
            "peer_configurations not properly structured"

        for count, peer_type in peer_configurations:
            for _ in xrange(count):
                self.create_new_peer(peer_type, None)

        self._get_style_requests = get_style_requests
        self._post_style_requests = post_style_requests

    def setUp(self):
        from ....community import _DEFAULT_ADDRESSES
        from ....community import _DNS_ADDRESSES
        while _DEFAULT_ADDRESSES:
            _DEFAULT_ADDRESSES.pop()
        while _DNS_ADDRESSES:
            _DNS_ADDRESSES.pop()
        return super(RESTTestBase, self).setUp()

    @inlineCallbacks
    def tearDown(self):
        while self.working_dirs:
            rmtree(self.working_dirs.pop())

        yield super(RESTTestBase, self).tearDown()

        self.gracefully_terminate_peers()

    @staticmethod
    def generate_local_port(attempts=50):
        port = random.randint(1024, 49152)

        while attempts > 0:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))
                s.close()
                return port
            except socket.error:
                attempts -= 1
                port = random.randint(1024, 49152)

        raise socket.error("Could not find a valid port")

    def create_new_peer(self, peer_cls, port, *args, **kwargs):
        """
        This method should be overwritten in the subclasses of RESTTestBase. It should call self._create_new_peer_inner
        and pass a list of overlay classes to the call (in addition to the other parameters), and then return the
        results returned by self._create_new_peer_inner.

        :param peer_cls: specifies the test class of the new peer
        :param port: the port of the peer mai be optionally provided, however, this is not advised as it might overlap
                     with an existing peer. Thus, it should be set to None. In this case, the port will be chosen by
                     this method.
        :param args: peer arguments (not considering the path and port)
        :param kwargs: keyworded peer arguments
        :return: the newly created peer and its index in the peer list
        """
        raise NotImplementedError("The create_new_peer method should be implemented in the subclasses of RESTTestBase")

    def _create_new_peer_inner(self, peer_cls, port, overlay_classes, *args, **kwargs):
        """
        Create and return a new peer for testing. This is an internal method, which should ideally be wrapped by the
        create_new_peer method which calls this method, and automatically passes a list of the overlay classes which
        are required for a particular set of tests.


        :param peer_cls: specifies the test class of the new peer
        :param port: the port of the peer mai be optionally provided, however, this is not advised as it might overlap
                     with an existing peer. Thus, it should be set to None. In this case, the port will be chosen by
                     this method.
        :param overlay_classes: a list of overlay classes which should be instantiated as overlays in a new peer
        :param args: peer arguments (not considering the path and port)
        :param kwargs: keyworded peer arguments
        :return: the newly created peer and its index in the peer list
        """
        assert issubclass(peer_cls, RestTestPeer), "The provided class type is not for testing (i.e. a subclass of " \
                                                   "TestPeer"
        assert port is None or isinstance(port, int), "The port must be an int or None"
        # Check to see if a peer was provided; if not, generate it
        if port is None:
            port = RESTTestBase.generate_local_port()

        # Create the new peer arguments
        temp_args = [port, overlay_classes] + list(args)

        # Create a directory if this peer requires it.
        if not kwargs.get('memory_dbs', True):
            working_dir_path = self.create_dir()
            self.working_dirs.add(working_dir_path)

        # Create the new peer, and add it to the list of peers for this test
        new_peer = None
        while not new_peer:
            try:
                new_peer = peer_cls(*temp_args, **kwargs)
            except CannotListenError:
                logging.error("Failed to claim supposedly free port %d. Retrying.", temp_args[0])
                temp_args[0] = RESTTestBase.generate_local_port()
        self.nodes.append(new_peer)

        # Move back to the test level, if a new directory was created
        if not kwargs.get('memory_dbs', True):
            os.chdir(os.path.dirname(__file__))

        return new_peer, len(self.nodes) - 1

    @inlineCallbacks
    def introduce_nodes(self, overlay_class):
        for node in self.nodes:
            for other in self.nodes:
                other.get_overlay_by_class(overlay_class).walk_to(node.get_address())
        yield self.deliver_messages()

    def create_dir(self):
        """
        Create a random working directory

        :return: the path to the directory
        """
        random_string = '_temp_' + ''.join(random.choice(ascii_uppercase + digits) for _ in range(10))
        d = os.path.abspath(self.__class__.__name__ + random_string)
        os.makedirs(d)
        return d

    def gracefully_terminate_peers(self):
        """
        Gracefully terminate the peers passed as parameter

        :return: None
        """
        for peer in self.nodes:
            if isinstance(peer, Thread):
                peer.join()
