import hashlib
import json
from collections import defaultdict

from twisted.internet import reactor

from pyipv8 import NewCommunityCreatedEvent, NewCommunityRegisteredEvent
from pyipv8.ipv8.attestation.bobchain.community import BOBChainCommunity
from pyipv8.ipv8.keyvault.crypto import ECCrypto
from pyipv8.ipv8.peer import Peer
from pyipv8.ipv8.peerdiscovery.discovery import EdgeWalk, RandomWalk


def construct_communities():
    return defaultdict(construct_communities)


communities = construct_communities()

_WALKERS = {
    'EdgeWalk': EdgeWalk,
    'RandomWalk': RandomWalk
}


class Controller:
    controller = None

    def __init__(self, ipv8):
        self.ipv8 = ipv8
        Controller.controller = self
        NewCommunityCreatedEvent.event.append(self.register_existing_community)

    def get_communities(self):
        return communities

    def register_existing_community(self, community):
        communities[community.country][community.state][community.city][community.street][community.number] = community
        NewCommunityRegisteredEvent.event()

    def create_community(self, country, state, city, street, number):
        property = {"country": country,
                    "state": state,
                    "city": city,
                    "street": street,
                    "number": number}
        community_key = ECCrypto().generate_key(u"medium")
        community_key_hash = hashlib.sha224(json.dumps(property)).hexdigest()
        community_peer = Peer(community_key)
        overlay_instance = BOBChainCommunity(community_peer, self.ipv8.endpoint, self.ipv8.network, **property)
        self.ipv8.overlays.append(overlay_instance)
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
                                          overlay_instance.get_available_strategies().get(walker['strategy']))
            args = walker['init']
            target_peers = walker['peers']
            self.ipv8.strategies.append((strategy_class(overlay_instance, **args), target_peers))
        for config in [('started',)]:
            reactor.callWhenRunning(getattr(overlay_instance, config[0]), *config[1:])
        communities[country][state][city][street][number] = (property, community_key)

        with open("keys/" + str(community_key_hash) + ".pem", 'w') as f:
            f.write(community_key.key_to_bin())

        with open('property_to_key_mappings.json', 'w') as file:
            l = []
            for country, states in communities.items():
                community_id = {"country": country}
                for state, cities in states.items():
                    community_id["state"] = state
                    for city, streets in cities.items():
                        community_id["city"] = city
                        for street, numbers in streets.items():
                            community_id["street"] = street
                            for number in numbers:
                                community_id["number"] = number
                                l.append([community_id, community_key_hash])
            json.dump(l, file)
