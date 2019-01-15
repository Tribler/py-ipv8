import json
import thread
from base64 import b64encode
import hashlib

from twisted.internet import reactor

from pyipv8.ipv8.REST.rest_manager import RESTManager
from pyipv8.ipv8.keyvault.crypto import ECCrypto
from pyipv8.ipv8_service import IPv8

from pyipv8.ipv8.attestation.bobchain.community import BOBChainCommunity
from pyipv8.ipv8.keyvault.crypto import ECCrypto
from pyipv8.ipv8.peer import Peer
from pyipv8.ipv8.peerdiscovery.discovery import EdgeWalk, RandomWalk

_WALKERS = {
    'EdgeWalk': EdgeWalk,
    'RandomWalk': RandomWalk
}


def create_community(ipv8, country, state, city, street, number):
        property_details = {"country": country,
                            "state": state,
                            "city": city,
                            "street": street,
                            "number": number}
        community_key = ECCrypto().generate_key(u"medium")
        community_key_hash = hashlib.sha224(json.dumps(property_details)).hexdigest()
        community_peer = Peer(community_key)
        community = BOBChainCommunity(community_peer, ipv8.endpoint, ipv8.network, **property_details)
        ipv8.overlays.append(community)
        for walker in [{
            'strategy': "EdgeWalk",
            'peers': 20,
            'init': {
                'edge_length': 4,
                'neighborhood_size': 6,
                'edge_timeout': 3.0
            }
        }]:
            strategy_class = _WALKERS.get(walker['strategy'],
                                          community.get_available_strategies().get(walker['strategy']))
            args = walker['init']
            target_peers = walker['peers']
            ipv8.strategies.append((strategy_class(community, **args), target_peers))
        for config in [('started',)]:
            reactor.callWhenRunning(getattr(community, config[0]), *config[1:])
       

config = {
    'address': '0.0.0.0',
    'port': 8090,
    'keys': [{
        'alias': "discovery",
        'generation': u"medium",
        'file': u"keys\\discovery.pem"
    }],
    'logger': {
        'level': "INFO"
    },
    'walker_interval': 0.5,
    'overlays': [
        {
            'class': 'DiscoveryCommunity',
            'key': "discovery",
            'walkers': [
                {
                    'strategy': "RandomWalk",
                    'peers': 20,
                    'init': {
                        'timeout': 3.0
                    }
                },
                {
                    'strategy': "RandomChurn",
                    'peers': -1,
                    'init': {
                        'sample_size': 8,
                        'ping_interval': 10.0,
                        'inactive_time': 27.5,
                        'drop_time': 57.5
                    }
                }
            ],
            'initialize': {},
            'on_start': [
                ('resolve_dns_bootstrap_addresses',)
            ]
        }
    ]
}

ipv8 = IPv8.__new__(IPv8)
ipv8.__init__(config)
rest_manager = RESTManager(ipv8)
rest_manager.start(14410)

create_community(ipv8, "Romania", "Bucharest", "District5", "Mirinescu", "21")



