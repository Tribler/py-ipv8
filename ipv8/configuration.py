import copy

default = {
    'address': '0.0.0.0',
    'port': 8090,
    'keys': [
        {
            'alias': "my peer",
            'generation': u"medium",
            'file': u"ec.pem"
        }
    ],
    'logger': {
        'level': "ERROR"
    },
    'walker_interval': 0.5,
    'overlays': [
        {
            'class': 'DiscoveryCommunity',
            'key': "my peer",
            'walkers': [
                {
                    'strategy': "RandomWalk",
                    'peers': -1,
                    'init': {
                        'timeout': 3.0
                    }
                },
                {
                    'strategy': "RandomChurn",
                    'peers': -1,
                    'init': {
                        'sample_size': 64,
                        'ping_interval': 1.0,
                        'inactive_time': 1.0,
                        'drop_time': 3.0
                    }
                }
            ],
            'initialize': {},
            'on_start': [
                ('resolve_dns_bootstrap_addresses', )
            ]
        }
    ]
}


def get_default_configuration():
    return copy.deepcopy(default)

__all__ = ['get_default_configuration']
