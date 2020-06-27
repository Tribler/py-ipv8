import copy
import enum
import socket
import typing

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
    'working_directory': ".",
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


class Strategy(enum.Enum):
    RandomWalk = "RandomWalk"
    RandomChurn = "RandomChurn"
    PeriodicSimilarity = "PeriodicSimilarity"
    EdgeWalk = "EdgeWalk"

    @classmethod
    def values(cls):
        return [name for name, _ in cls.__members__.items()]


class WalkerDefinition(typing.NamedTuple):
    strategy: Strategy
    peers: int
    init: dict


ConfigBuilderType = typing.TypeVar('ConfigBuilderType', bound='ConfigBuilder')


class ConfigBuilder(object):

    def __init__(self, clean: bool = False):
        self.config = {} if clean else get_default_configuration()

    def finalize(self) -> dict:
        """
        Process the builder input and check for errors, this produces a configuration dictionary suitable for IPv8.

        Essentially this only checks the `config` variable for errors, use that instead if you're confident you never
        make any errors.
        """
        assert self.config.get('address') is not None, "Missing address in config!"
        assert self.config.get('port') is not None, "Missing port in config!"
        assert self.config.get('keys') is not None, "Missing keys in config!"
        assert self.config.get('logger') is not None, "Missing logger in config!"
        assert self.config.get('walker_interval') is not None, "Missing walker_interval in config!"
        assert self.config.get('overlays') is not None, "Missing overlays in config!"
        assert self.config.get('working_directory') is not None, "Missing working_directory in config!"

        socket.inet_aton(self.config.get('address'))  # Errors out if the address is illegal
        assert 0 <= self.config['port'] <= 65535
        assert self.config['walker_interval'] >= 0

        for overlay in self.config['overlays']:
            assert overlay.get('class') is not None, "Missing class in overlay config!"
            assert overlay.get('key') is not None, f"Missing key in overlay config of {overlay['class']}!"
            assert overlay.get('walkers') is not None, f"Missing walkers in overlay config of {overlay['class']}!"
            assert overlay.get('initialize') is not None, f"Missing initialize in overlay config of {overlay['class']}!"
            assert overlay.get('on_start') is not None, f"Missing on_start in overlay config of {overlay['class']}!"
            assert any(key['alias'] == overlay['key'] for key in self.config['keys']),\
                f"Unknown key alias {overlay['key']} in overlay config of {overlay['class']}!"
            assert all(isinstance(key, str) for key in overlay['initialize'].keys()),\
                f"Keyword argument mapping keys must be strings in overlay config of {overlay['class']}!"
            assert all(isinstance(entry[0], str) for entry in overlay['on_start']),\
                f"Start methods must be strings in overlay config of {overlay['class']}!"
            for walker in overlay['walkers']:
                assert walker.get('strategy') is not None,\
                    f"Missing strategy class in strategy config of {overlay['class']}!"
                assert walker.get('peers') is not None,\
                    f"Missing peers in {walker['strategy']} config of {overlay['class']}!"
                assert walker.get('init') is not None,\
                    f"Missing init in {walker['strategy']} config of {overlay['class']}!"
                assert walker['strategy'] in Strategy.values()
                if (walker['strategy'] == Strategy.RandomChurn.value
                        or walker['strategy'] == Strategy.PeriodicSimilarity.value):
                    assert overlay['class'] == 'DiscoveryCommunity'

        return self.config

    def clear_keys(self) -> ConfigBuilderType:
        """
        Remove all keys in the current configuration.
        """
        self.config['keys'] = []
        return self

    def clear_overlays(self) -> ConfigBuilderType:
        """
        Remove all overlays in the current configuration.
        """
        self.config['overlays'] = []
        return self

    def set_address(self, address: str) -> ConfigBuilderType:
        """
        Set the address IPv8 is to try and bind to.

        For localhost only use: 127.0.0.1
        For Internet communication use: 0.0.0.0
        """
        assert address.count('.') == 3
        self.config['address'] = address
        return self

    def set_port(self, port: int) -> ConfigBuilderType:
        """
        Set the port that IPv8 should TRY to bind to.
        If your port is not available, IPv8 will try and find another one.
        """
        self.config['port'] = port
        return self

    def set_log_level(self, log_level: str) -> ConfigBuilderType:
        """
        Set the log level for all of IPv8's loggers.
        Choose from 'CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG' or 'NOTSET'.
        """
        assert log_level in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'NOTSET']
        self.config['logger'] = {'level': log_level}
        return self

    def set_working_directory(self, folder_path: str) -> ConfigBuilderType:
        """
        Set the common working directory for overlays.

        Individual settings may override this working directory, but it serves as the base working directory.
        """
        self.config['working_directory'] = folder_path
        return self

    def set_walker_interval(self, interval: float) -> ConfigBuilderType:
        """
        Set the interval, in seconds, at which IPv8 schedules its strategies.

        An interval of 3.14 would mean that each walker attempts to walk every 3.14 seconds.
        Setting this interval too low will choke the event thread and decrease the QoS of IPv8 overlays.
        Setting this interval too high will decrease the QoS of IPv8 overlays due to lack of content.
        """
        self.config['walker_interval'] = interval
        return self

    def add_key(self, alias: str, generation: str, file_path: str) -> ConfigBuilderType:
        """
        Add a key by alias and mode of generation, to be stored at a certain file path.

        If a key already exists at the given file path, that will be loaded instead of generating a new key.
        """
        assert generation in ['curve25519', 'very-low', 'low', 'medium', 'high']
        if 'keys' in self.config:
            self.config['keys'] = [key for key in self.config['keys'] if key["alias"] != alias]
        else:
            self.config['keys'] = []
        self.config['keys'].append({
            'alias': alias,
            'generation': generation,
            'file': file_path
        })
        return self

    def add_overlay(self,
                    overlay_class: str,
                    key_alias: str,
                    walkers: typing.List[WalkerDefinition],
                    initialize: typing.Dict[str, typing.Any],
                    on_start: typing.List[tuple],
                    allow_duplicate: bool = False) -> ConfigBuilderType:
        """
        Add an overlay by its class name. You can choose from the default communities or register your own (see IPv8's
        ``extra_communities`` for the latter). Whatever key alias you choose for this overlay should be registered
        through add_key.

        The default communities include:

         - 'AttestationCommunity'
         - 'DiscoveryCommunity'
         - 'HiddenTunnelCommunity'
         - 'IdentityCommunity'
         - 'TrustChainCommunity'
         - 'TunnelCommunity'
         - 'DHTDiscoveryCommunity'
         - 'TrustChainTestnetCommunity'

        The initialize argument is a key-value mapping passed to the constructor (__init__) of the overlay.

        The on_start contains a list of tuples that specify the method to call on the overlay when IPv8 has initialized,
        coupled to the positional arguments to pass to the method, for example to call ``some_method(1, 2)``:

         [("some_method", 1, 2)]

        Lastly, IPv8 is capable of loading two distinct instances of the same overlay class. Set ``allow_duplicate``
        to explicitly allow this (usually this is programmer error).
        """
        if 'overlays' in self.config:
            if not allow_duplicate:
                self.config['overlays'] = [overlay for overlay in self.config['overlays']
                                           if overlay["class"] != overlay_class]
        else:
            self.config['overlays'] = []
        self.config['overlays'].append({
            'class': overlay_class,
            'key': key_alias,
            'walkers': [{
                'strategy': walker.strategy.value,
                'peers': walker.peers,
                'init': walker.init
            } for walker in walkers],
            'initialize': initialize,
            'on_start': on_start
        })
        return self


__all__ = ['ConfigBuilder', 'Strategy', 'WalkerDefinition', 'get_default_configuration']
