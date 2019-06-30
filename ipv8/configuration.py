from __future__ import absolute_import

import copy

default = {
    'address': '0.0.0.0',
    'port': 8090,
    'keys': [
        {
            'alias': "anonymous id",
            'generation': u"curve25519",
            'file': u"ec_multichain.pem"
        }
    ],
    'logger': {
        'level': "INFO"
    },
    'walker_interval': 0.5,
    'overlays': [
        {
            'class': 'DiscoveryCommunity',
            'key': "anonymous id",
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
                },
                {
                    'strategy': "PeriodicSimilarity",
                    'peers': -1,
                    'init': {}
                }
            ],
            'initialize': {},
            'on_start': [
                ('resolve_dns_bootstrap_addresses', )
            ]
        },
        {
            'class': 'HiddenTunnelCommunity',
            'key': "anonymous id",
            'walkers': [
                {
                    'strategy': "RandomWalk",
                    'peers': 20,
                    'init': {
                        'timeout': 3.0
                    }
                }
            ],
            'initialize': {
                'settings': {
                    'min_circuits': 1,
                    'max_circuits': 1,
                    'max_relays_or_exits': 100,
                    'max_time': 10 * 60,
                    'max_time_inactive': 20,
                    'max_traffic': 250 * 1024 * 1024,
                    'max_packets_without_reply': 50,
                    'dht_lookup_interval': 30
                }
            },
            'on_start': [
                ('build_tunnels', 1)
            ]
        },
        {
            'class': 'TrustChainCommunity',
            'key': "anonymous id",
            'walkers': [{
                'strategy': "EdgeWalk",
                'peers': 20,
                'init': {
                    'edge_length': 4,
                    'neighborhood_size': 6,
                    'edge_timeout': 3.0
                }
            }],
            'initialize': {},
            'on_start': []
        },
        {
            'class': 'AttestationCommunity',
            'key': "anonymous id",
            'walkers': [{
                'strategy': "RandomWalk",
                'peers': 20,
                'init': {
                    'timeout': 3.0
                }
            }],
            'initialize': {'anonymize': True},
            'on_start': []
        },
        {
            'class': 'IdentityCommunity',
            'key': "anonymous id",
            'walkers': [{
                'strategy': "RandomWalk",
                'peers': 20,
                'init': {
                    'timeout': 3.0
                }
            }],
            'initialize': {'anonymize': True},
            'on_start': []
        },
        {
            'class': 'DHTDiscoveryCommunity',
            'key': "anonymous id",
            'walkers': [{
                'strategy': "RandomWalk",
                'peers': 20,
                'init': {
                    'timeout': 3.0
                }
            }],
            'initialize': {},
            'on_start': []
        }
    ]
}


def get_default_configuration():
    return copy.deepcopy(default)


__all__ = ['get_default_configuration']
