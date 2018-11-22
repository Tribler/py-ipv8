from __future__ import print_function

from os import path
from random import randint
import time

from twisted.internet import reactor
from twisted.internet.task import LoopingCall

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import sys
    sys.path.append(path.abspath(path.join(path.dirname(__file__), "..")))

from ipv8_service import _COMMUNITIES, IPv8
from ipv8.configuration import get_default_configuration
from ipv8.community import Community
from ipv8.keyvault.crypto import ECCrypto
from ipv8.peer import Peer


START_TIME = time.time()
LOW_EDGE = 0
LOW_EDGE_PEER = None
INSTANCES = []


class MyCommunity(Community):
    master_peer = Peer(ECCrypto().generate_key(u"medium"))

    def started(self):
        def check_peers():
            global INSTANCES, LOW_EDGE, LOW_EDGE_PEER, START_TIME
            if self.get_peers():
                if LOW_EDGE and self.my_peer != LOW_EDGE_PEER:
                    for instance in INSTANCES:
                        instance.stop(False)
                    reactor.callFromThread(reactor.stop)
                    print("%.4f,%.4f" % (LOW_EDGE, time.time() - START_TIME))
                else:
                    LOW_EDGE = time.time() - START_TIME
                    LOW_EDGE_PEER = self.my_peer
        self.register_task("check_peers", LoopingCall(check_peers)).start(0.1, True)

    def create_introduction_response(self, lan_socket_address, socket_address, identifier, introduction=None):
        return super(MyCommunity, self).create_introduction_response(lan_socket_address, socket_address,
                                                                     identifier, introduction, b'1')

    def create_introduction_request(self, socket_address):
        return super(MyCommunity, self).create_introduction_request(socket_address, b'2')


_COMMUNITIES['MyCommunity'] = MyCommunity


for i in [1, 2]:
    configuration = get_default_configuration()
    configuration['keys'] = [{
        'alias': "my peer",
        'generation': u"medium",
        'file': u"ec%d.pem" % i
    }]
    configuration['port'] = 12000 + randint(0, 10000)
    configuration['overlays'] = [{
        'class': 'MyCommunity',
        'key': "my peer",
        'walkers': [{
            'strategy': "RandomWalk",
            'peers': 10,
            'init': {
                'timeout': 3.0
            }
        }],
        'initialize': {},
        'on_start': [('started', )]
    }]
    INSTANCES.append(IPv8(configuration))

reactor.run()
