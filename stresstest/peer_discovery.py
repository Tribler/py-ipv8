import time
from asyncio import ensure_future, get_event_loop
from random import randint

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401

from ipv8.community import Community
from ipv8.configuration import get_default_configuration
from ipv8.keyvault.crypto import ECCrypto
from ipv8.peer import Peer

from ipv8_service import IPv8, _COMMUNITIES


START_TIME = time.time()
LOW_EDGE = 0
LOW_EDGE_PEER = None
INSTANCES = []


class MyCommunity(Community):
    master_peer = Peer(ECCrypto().generate_key(u"medium"))

    def started(self):
        async def check_peers():
            global INSTANCES, LOW_EDGE, LOW_EDGE_PEER, START_TIME
            if self.get_peers():
                if LOW_EDGE and self.my_peer != LOW_EDGE_PEER:
                    print("%.4f,%.4f" % (LOW_EDGE, time.time() - START_TIME))

                    async def shutdown():
                        for instance in INSTANCES:
                            await instance.stop(False)
                        get_event_loop().stop()
                    ensure_future(shutdown())
                else:
                    LOW_EDGE = time.time() - START_TIME
                    LOW_EDGE_PEER = self.my_peer
        self.register_task("check_peers", check_peers, interval=0.1, delay=0)

    def create_introduction_response(self, lan_socket_address, socket_address, identifier, introduction=None):
        return super(MyCommunity, self).create_introduction_response(lan_socket_address, socket_address,
                                                                     identifier, introduction, b'1')

    def create_introduction_request(self, socket_address):
        return super(MyCommunity, self).create_introduction_request(socket_address, b'2')


_COMMUNITIES['MyCommunity'] = MyCommunity


async def start_communities():
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
        ipv8 = IPv8(configuration)
        await ipv8.start()
        INSTANCES.append(ipv8)


ensure_future(start_communities())
get_event_loop().run_forever()
