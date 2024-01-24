from __future__ import annotations

import base64
import copy
import enum
import typing
from typing import Any

from .keyvault.crypto import default_eccrypto

DISPERSY_BOOTSTRAPPER: dict[Any, Any] = {
    'class': "DispersyBootstrapper",
    'init': {
        'ip_addresses': [
            ("130.161.119.206", 6421),
            ("130.161.119.206", 6422),
            ("131.180.27.155", 6423),
            ("131.180.27.156", 6424),
            ("131.180.27.161", 6427),
            ("131.180.27.161", 6521),
            ("131.180.27.161", 6522),
            ("131.180.27.162", 6523),
            ("131.180.27.162", 6524),
            ("130.161.119.215", 6525),
            ("130.161.119.215", 6526),
            ("130.161.119.201", 6527),
            ("130.161.119.201", 6528)
        ],
        'dns_addresses': [
            ("dispersy1.tribler.org", 6421), ("dispersy1.st.tudelft.nl", 6421),
            ("dispersy2.tribler.org", 6422), ("dispersy2.st.tudelft.nl", 6422),
            ("dispersy3.tribler.org", 6423), ("dispersy3.st.tudelft.nl", 6423),
            ("dispersy4.tribler.org", 6424),
            ("tracker1.ip-v8.org", 6521),
            ("tracker2.ip-v8.org", 6522),
            ("tracker3.ip-v8.org", 6523),
            ("tracker4.ip-v8.org", 6524),
            ("tracker5.ip-v8.org", 6525),
            ("tracker6.ip-v8.org", 6526),
            ("tracker7.ip-v8.org", 6527),
            ("tracker8.ip-v8.org", 6528)
        ],
        'bootstrap_timeout': 30.0
    }
}

default: dict[Any, Any] = {
    'interfaces': [
        {
            'interface': "UDPIPv4",
            'ip': "0.0.0.0",
            'port': 8090
        }
    ],
    'keys': [
        {
            'alias': "anonymous id",
            'generation': "curve25519",
            'file': "ec_multichain.pem"
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
            'bootstrappers': [DISPERSY_BOOTSTRAPPER.copy()],
            'initialize': {},
            'on_start': []
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
            'bootstrappers': [DISPERSY_BOOTSTRAPPER.copy()],
            'initialize': {
                'min_circuits': 1,
                'max_circuits': 1,
                'max_joined_circuits': 100,
                'max_time': 10 * 60,
                'max_time_inactive': 20,
                'max_traffic': 250 * 1024 * 1024,
                'dht_lookup_interval': 30
            },
            'on_start': [
                ('build_tunnels', 1)
            ]
        },
        {
            'class': 'DHTDiscoveryCommunity',
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
                    'strategy': "PingChurn",
                    'peers': -1,
                    'init': {}
                }
            ],
            'bootstrappers': [DISPERSY_BOOTSTRAPPER.copy()],
            'initialize': {},
            'on_start': []
        }
    ]
}
"""
The GLOBAL default values for IPv8 configuration. If you modify these, your interpreter will apply these defaults to
all following IPv8 instances. You're most likely looking for ``get_default_configuration()`` instead.
"""


def get_default_configuration() -> dict[Any, Any]:
    """
    Get a COPY of the default configuration.

    You should always use this method instead of accesesing the global default directly.
    """
    return copy.deepcopy(default)


class Strategy(enum.Enum):
    """
    ConfigBuilder enum to request default DiscoveryStrategies to be instantiated.
    """

    RandomWalk = "RandomWalk"
    RandomChurn = "RandomChurn"
    PeriodicSimilarity = "PeriodicSimilarity"
    EdgeWalk = "EdgeWalk"
    PingChurn = "PingChurn"

    @classmethod
    def values(cls: type[Strategy]) -> list[str]:
        """
        Get the known default DiscoveryStrategy names.
        """
        return list(typing.cast(typing.Dict[str, Any], cls.__members__))


class WalkerDefinition(typing.NamedTuple):
    """
    ConfigBuilder directive to request a given strategy to run below a given peer count.

    The strategy instance is created with the keyword arguments given in ``init``.
    If the ``peers`` are set to ``-1``, the strategy will always be invoked, regardless of the number of peers.
    """

    strategy: Strategy
    peers: int
    init: dict


class Bootstrapper(enum.Enum):
    """
    ConfigBuilder enum to request a community to use a given bootstrapping method.
    """

    DispersyBootstrapper = "DispersyBootstrapper"
    UDPBroadcastBootstrapper = "UDPBroadcastBootstrapper"

    @classmethod
    def values(cls: type[Bootstrapper]) -> list[str]:
        """
        Get the known default Bootstrapper names.
        """
        return list(typing.cast(typing.Dict[str, Any], cls.__members__))


class BootstrapperDefinition(typing.NamedTuple):
    """
    ConfigBuilder directive to specify how Bootstrapper instances should be instantiated.

    The bootstrapper instance is created with the keyword arguments given in ``init``.
    """

    bootstrapper: Bootstrapper
    init: dict


default_bootstrap_defs = [BootstrapperDefinition(Bootstrapper.DispersyBootstrapper, DISPERSY_BOOTSTRAPPER['init'])]
"""
Shortcut for the most common ConfigBuilder default bootstrapper settings.
"""


class ConfigBuilder:
    """
    Factory class to create IPv8 configurations.
    """

    def __init__(self, clean: bool = False) -> None:
        """
        Create new ConfigBuilder with either the default settings (``clean=False``) or a completely empty configuration
        dict (``clean=True``).
        """
        self.config = {} if clean else get_default_configuration()

    def finalize(self) -> dict:
        """
        Process the builder input and check for errors, this produces a configuration dictionary suitable for IPv8.

        Essentially this only checks the `config` variable for errors, use that instead if you're confident you never
        make any errors.
        """
        assert self.config.get('keys') is not None, "Missing keys in config!"
        assert self.config.get('logger') is not None, "Missing logger in config!"
        assert self.config.get('walker_interval') is not None, "Missing walker_interval in config!"
        assert self.config.get('overlays') is not None, "Missing overlays in config!"
        assert self.config.get('working_directory') is not None, "Missing working_directory in config!"

        assert self.config['walker_interval'] >= 0

        for overlay in self.config['overlays']:
            assert overlay.get('class') is not None, "Missing class in overlay config!"
            assert overlay.get('key') is not None, f"Missing key in overlay config of {overlay['class']}!"
            assert overlay.get('walkers') is not None, f"Missing walkers in overlay config of {overlay['class']}!"
            assert overlay.get('bootstrappers') is not None,\
                f"Missing bootstrappers in overlay config of {overlay['class']}!"
            assert overlay.get('initialize') is not None,\
                f"Missing initialize in overlay config of {overlay['class']}!"
            assert overlay.get('on_start') is not None, f"Missing on_start in overlay config of {overlay['class']}!"
            assert any(key['alias'] == overlay['key'] for key in self.config['keys']),\
                f"Unknown key alias {overlay['key']} in overlay config of {overlay['class']}!"
            assert all(isinstance(key, str) for key in overlay['initialize']),\
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
            for bootstrapper in overlay['bootstrappers']:
                assert bootstrapper.get('class') is not None,\
                    f"Missing bootstrapper class in bootstrapper config of {overlay['class']}!"
                assert bootstrapper.get('init') is not None,\
                    f"Missing init in {bootstrapper['class']} config of {overlay['class']}!"
                assert bootstrapper['class'] in Bootstrapper.values()

        return self.config

    def clear_keys(self) -> ConfigBuilder:
        """
        Remove all keys in the current configuration.
        """
        self.config['keys'] = []
        return self

    def clear_overlays(self) -> ConfigBuilder:
        """
        Remove all overlays in the current configuration.
        """
        self.config['overlays'] = []
        return self

    def set_address(self, address: str, interface: str = "UDPIPv4") -> ConfigBuilder:
        """
        Set the address IPv8 is to try and bind to.

        | For IPv4 localhost only use ``127.0.0.1``
        | For IPv4 Internet communication use ``0.0.0.0``
        | For IPv6 localhost only use ``::1``
        | For IPv6 Internet communication use ``::``

        :param address: the address to attempt to bind to.
        :param interface: the interface to use (currently "UDPIPv4" or "UDPIPv6").
        """
        existing = ([spec for spec in self.config['interfaces'] if spec['interface'] == interface]
                    if 'interfaces' in self.config else [])
        destination = existing[0] if existing else {'interface': interface}
        destination['ip'] = address
        if not existing:
            if 'interfaces' in self.config:
                self.config['interfaces'].append(destination)
            else:
                self.config['interfaces'] = [destination]
        return self

    def set_port(self, port: int, interface: str = "UDPIPv4") -> ConfigBuilder:
        """
        Set the port that IPv8 should TRY to bind to.
        If your port is not available, IPv8 will try and find another one.

        :param port: the port to attempt to bind to.
        :param interface: the interface to use (currently "UDPIPv4" or "UDPIPv6").
        """
        existing = ([spec for spec in self.config['interfaces'] if spec['interface'] == interface]
                    if 'interfaces' in self.config else [])
        destination = existing[0] if existing else {'interface': interface}
        destination['port'] = port
        if not existing:
            if 'interfaces' in self.config:
                self.config['interfaces'].append(destination)
            else:
                self.config['interfaces'] = [destination]
        return self

    def set_log_level(self, log_level: str) -> ConfigBuilder:
        """
        Set the log level for all of IPv8's loggers.
        Choose from 'CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG' or 'NOTSET'.
        """
        assert log_level in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'NOTSET']
        self.config['logger'] = {'level': log_level}
        return self

    def set_working_directory(self, folder_path: str) -> ConfigBuilder:
        """
        Set the common working directory for overlays.

        Individual settings may override this working directory, but it serves as the base working directory.
        """
        self.config['working_directory'] = folder_path
        return self

    def set_walker_interval(self, interval: float) -> ConfigBuilder:
        """
        Set the interval, in seconds, at which IPv8 schedules its strategies.

        An interval of 3.14 would mean that each walker attempts to walk every 3.14 seconds.
        Setting this interval too low will choke the event thread and decrease the QoS of IPv8 overlays.
        Setting this interval too high will decrease the QoS of IPv8 overlays due to lack of content.
        """
        self.config['walker_interval'] = interval
        return self

    def add_key(self, alias: str, generation: str, file_path: str) -> ConfigBuilder:
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

    def add_key_from_bin(self, alias: str, key_bin_b64: str, file_path: str | None = None) -> ConfigBuilder:
        """
        Add a key by alias and  its raw key material, possibly stored at a certain file path.

        If a key already exists at the given file path, that will be loaded instead of the given key material.

        :param alias: the alias used to reference this key
        :param key_bin_b64: the base64 encoded private key material
        :param file_path: the optional file path to save the key to
        """
        if 'keys' in self.config:
            self.config['keys'] = [key for key in self.config['keys'] if key['alias'] != alias]
        else:
            self.config['keys'] = []
        key_config = {
            'alias': alias,
            'bin': key_bin_b64
        }
        if file_path is not None:
            key_config['file'] = file_path
        self.config['keys'].append(key_config)
        return self

    def add_ephemeral_key(self, alias: str) -> ConfigBuilder:
        """
        Add an ephemeral key, which is only stored in memory (i.e., not associated with a file).

        :param alias: the alias used to reference this key
        """
        eph_key = default_eccrypto.generate_key("curve25519").key_to_bin()
        return self.add_key_from_bin(alias, base64.b64encode(eph_key).decode(), "")

    def add_overlay(self,  # noqa: PLR0913
                    overlay_class: str,
                    key_alias: str,
                    walkers: list[WalkerDefinition],
                    bootstrappers: list[BootstrapperDefinition],
                    initialize: dict[str, typing.Any],
                    on_start: list[tuple],
                    allow_duplicate: bool = False) -> ConfigBuilder:
        """
        Add an overlay by its class name. You can choose from the default communities or register your own (see IPv8's
        ``extra_communities`` for the latter). Whatever key alias you choose for this overlay should be registered
        through add_key.

        The default communities include:

         - 'AttestationCommunity'
         - 'DiscoveryCommunity'
         - 'HiddenTunnelCommunity'
         - 'IdentityCommunity'
         - 'TunnelCommunity'
         - 'DHTDiscoveryCommunity'

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
            'bootstrappers': [{
                'class': bootstrapper.bootstrapper.value,
                'init': bootstrapper.init
            } for bootstrapper in bootstrappers],
            'initialize': initialize,
            'on_start': on_start
        })
        return self


__all__ = ['Bootstrapper', 'BootstrapperDefinition', 'ConfigBuilder', 'DISPERSY_BOOTSTRAPPER', 'Strategy',
           'WalkerDefinition', 'default_bootstrap_defs', 'get_default_configuration']
