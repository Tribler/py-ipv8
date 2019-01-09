import json
import thread
from base64 import b64encode

from twisted.internet import reactor

from pyipv8.gui import open_gui
from pyipv8.ipv8.REST.rest_manager import RESTManager
from pyipv8.ipv8.keyvault.crypto import ECCrypto
from pyipv8.ipv8_service import IPv8

config = {
    'address': '0.0.0.0',
    'port': 8090,
    'keys': [{
        'alias': "my peer",
        'generation': u"medium",
        'file': u"ec.pem"
    }],
    'logger': {
        'level': "INFO"
    },
    'walker_interval': 0.5,
    'overlays': [
        {
            'class': 'DiscoveryCommunity',
            'key': "my peer",
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

try:
    with open('property_to_key_mappings.json', 'r') as file:
        json_file = json.load(file)
        for property in json_file:
            with open("keys/" + property[1] + ".pem", 'r') as key:
                key_content = key.read()
                config['overlays'].append(
                    {
                        'class': 'BOBChainCommunity',
                        'key': "my peer",
                        'walkers': [{
                            'strategy': "EdgeWalk",
                            'peers': 20,
                            'init': {
                                'edge_length': 4,
                                'neighborhood_size': 6,
                                'edge_timeout': 3.0
                            }
                        }],
                        'initialize': {'property_details': property[0],
                                       'property_key': ECCrypto().key_from_private_bin(key_content)},
                        'on_start': [('started',)]
                    }
                )
except IOError:
    with open('property_to_key_mappings.json', 'w') as file:
        json.dump([], file)

# Start the IPv8 service
ipv8 = IPv8(config)
rest_manager = RESTManager(ipv8)
rest_manager.start(14410)

# Print the peer for reference
print "Starting peer", b64encode(ipv8.keys["my peer"].mid)
thread.start_new_thread(open_gui, ())
# Start the Twisted reactor: this is the engine scheduling all of the
# asynchronous calls.
reactor.run()
