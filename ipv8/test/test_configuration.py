from .base import TestBase
from ..configuration import (Bootstrapper, BootstrapperDefinition, ConfigBuilder, DISPERSY_BOOTSTRAPPER, Strategy,
                             WalkerDefinition, get_default_configuration)


class TestConfiguration(TestBase):

    def assertDictInDict(self, expected: dict, container: dict):
        self.assertTrue(any(all(entry.get(key) == expected[key] for key in expected.keys())
                            and len(entry) == len(expected)
                            for entry in container))

    def test_clear_keys(self):
        """
        Check if all keys are cleared when requested.
        """
        builder = ConfigBuilder().clear_keys()

        self.assertEqual(0, len(builder.config['keys']))

    def test_clear_overlays(self):
        """
        Check if all overlays are cleared when requested.
        """
        builder = ConfigBuilder().clear_overlays()

        self.assertEqual(0, len(builder.finalize()['overlays']))

    def test_change_port(self):
        """
        Check if changes to the port are finalized.
        """
        builder = ConfigBuilder().set_port(1000)

        self.assertEqual(1000, builder.finalize()['interfaces'][0]['port'])

    def test_change_address(self):
        """
        Check if changes to the address are finalized.
        """
        builder = ConfigBuilder().set_address("1.1.1.1")

        self.assertEqual("1.1.1.1", builder.finalize()['interfaces'][0]['ip'])

    def test_set_illegal_log_level(self):
        """
        Check if wrong log levels raise an error immediately.
        """
        builder = ConfigBuilder()

        self.assertRaises(AssertionError, builder.set_log_level, "I don't exist")

    def test_change_log_level(self):
        """
        Check if changes to the log level are finalized.
        """
        builder = ConfigBuilder().set_log_level("CRITICAL")

        self.assertEqual("CRITICAL", builder.finalize()['logger']['level'])

    def test_set_illegal_walk_interval(self):
        """
        Check if negative walk intervals raise an error on finalization.
        """
        builder = ConfigBuilder().set_walker_interval(-1.0)

        self.assertRaises(AssertionError, builder.finalize)

    def test_change_walk_interval(self):
        """
        Check if changes to the walk interval are finalized.
        """
        builder = ConfigBuilder().set_walker_interval(3.14)

        self.assertEqual(3.14, builder.finalize()['walker_interval'])

    def test_add_key_illegal_curve(self):
        """
        Check if wrong key curves raise an error immediately.
        """
        builder = ConfigBuilder()

        self.assertRaises(AssertionError, builder.add_key, "my key", "I don't exist", "some file")

    def test_add_key(self):
        """
        Check if changes to the keys are finalized.
        """
        builder = ConfigBuilder().add_key("my new key", "very-low", "some file")

        expected = {
            'alias': "my new key",
            'generation': "very-low",
            'file': "some file"
        }
        keys = builder.finalize()['keys']

        self.assertEqual(1 + len(get_default_configuration()['keys']), len(keys))
        self.assertTrue(any(set(entry.items()) == set(expected.items()) for entry in keys))

    def test_add_key_from_bin(self):
        """
        Check if changes to the keys are finalized in bin mode.
        """
        key_material = ("MG0CAQEEHUkphrkiuNhcofjWfaplwoAk0i7tBIDq93ATwaTKoAcGBSuBBAAaoUADPgAEANBoqp"
                        "ZtJ3z0fbt2knDEBC6nLk2P0AHEWKHoCOzRAAloM3NgRObfmRlkuiQANY0VWRMn1TAjIZqogwBD")
        builder = ConfigBuilder().add_key_from_bin("my new key", key_material)

        expected = {
            'alias': "my new key",
            'bin': key_material
        }
        keys = builder.finalize()['keys']

        self.assertEqual(1 + len(get_default_configuration()['keys']), len(keys))
        self.assertTrue(any(set(entry.items()) == set(expected.items()) for entry in keys))

    def test_add_key_from_bin_file(self):
        """
        Check if changes to the keys are finalized in bin mode with a file.
        """
        key_material = ("MG0CAQEEHUkphrkiuNhcofjWfaplwoAk0i7tBIDq93ATwaTKoAcGBSuBBAAaoUADPgAEANBoqp"
                        "ZtJ3z0fbt2knDEBC6nLk2P0AHEWKHoCOzRAAloM3NgRObfmRlkuiQANY0VWRMn1TAjIZqogwBD")
        builder = ConfigBuilder().add_key_from_bin("my new key", key_material, "some file")

        expected = {
            'alias': "my new key",
            'bin': key_material,
            'file': "some file"
        }
        keys = builder.finalize()['keys']

        self.assertEqual(1 + len(get_default_configuration()['keys']), len(keys))
        self.assertTrue(any(set(entry.items()) == set(expected.items()) for entry in keys))

    def test_add_overlay_overwrite(self):
        """
        Check if the allow duplicate flag does not introduce duplicates.
        """
        builder = ConfigBuilder().add_overlay("DiscoveryCommunity", "anonymous id", [], [], {}, [],
                                              allow_duplicate=False)

        expected = {
            'class': "DiscoveryCommunity",
            'key': "anonymous id",
            'walkers': [],
            'bootstrappers': [],
            'initialize': {},
            'on_start': []
        }

        self.assertEqual(len(get_default_configuration()['overlays']), len(builder.finalize()['overlays']))
        self.assertDictInDict(expected, builder.finalize()['overlays'])

    def test_add_overlay_append(self):
        """
        Check if the duplicate overlays are simply appended.
        """
        builder = ConfigBuilder().add_overlay("DiscoveryCommunity", "anonymous id", [], [], {}, [],
                                              allow_duplicate=True)

        expected = {
            'class': "DiscoveryCommunity",
            'key': "anonymous id",
            'walkers': [],
            'bootstrappers': [],
            'initialize': {},
            'on_start': []
        }

        self.assertEqual(1 + len(get_default_configuration()['overlays']), len(builder.finalize()['overlays']))
        self.assertDictInDict(expected, builder.finalize()['overlays'])

    def test_add_overlay_complex(self):
        """
        Check if a complex overlay is correctly added.
        """
        builder = ConfigBuilder().add_overlay("MyCommunity",
                                              "anonymous id",
                                              [WalkerDefinition(Strategy.RandomWalk, 42, {'timeout': 3.0})],
                                              [BootstrapperDefinition(Bootstrapper.DispersyBootstrapper,
                                                                      {'ip_addresses': [('1.2.3.4', 5)],
                                                                       'dns_addresses': [('tribler.org', 5)]})],
                                              {'settings': {"my_key": "my_value"}},
                                              [('do_a_thing', 42), ('do_another_thing', )])

        expected = {
            'class': "MyCommunity",
            'key': "anonymous id",
            'walkers': [{
                'strategy': "RandomWalk",
                'peers': 42,
                'init': {
                    'timeout': 3.0
                }
            }],
            'bootstrappers': [{
                'class': "DispersyBootstrapper",
                'init': {
                    'ip_addresses': [('1.2.3.4', 5)],
                    'dns_addresses': [('tribler.org', 5)]
                }
            }],
            'initialize': {'settings': {"my_key": "my_value"}},
            'on_start': [('do_a_thing', 42), ('do_another_thing', )]
        }

        self.assertDictInDict(expected, builder.finalize()['overlays'])

    def test_correct_random_churn_strategy(self):
        """
        The DiscoveryCommunity may use the RandomChurn strategy.
        """
        builder = ConfigBuilder().add_overlay("DiscoveryCommunity",
                                              "anonymous id",
                                              [WalkerDefinition(Strategy.RandomChurn, 20, {})],
                                              [],
                                              {},
                                              [])

        expected = {
            'class': "DiscoveryCommunity",
            'key': "anonymous id",
            'walkers': [{
                'strategy': "RandomChurn",
                'peers': 20,
                'init': {}
            }],
            'bootstrappers': [],
            'initialize': {},
            'on_start': []
        }

        self.assertEqual(len(get_default_configuration()['overlays']), len(builder.finalize()['overlays']))
        self.assertDictInDict(expected, builder.finalize()['overlays'])

    def test_correct_periodic_similarity_strategy(self):
        """
        The DiscoveryCommunity may use the PeriodicSimilarity strategy.
        """
        builder = ConfigBuilder().add_overlay("DiscoveryCommunity",
                                              "anonymous id",
                                              [WalkerDefinition(Strategy.PeriodicSimilarity, 20, {})],
                                              [],
                                              {},
                                              [])

        expected = {
            'class': "DiscoveryCommunity",
            'key': "anonymous id",
            'walkers': [{
                'strategy': "PeriodicSimilarity",
                'peers': 20,
                'init': {}
            }],
            'bootstrappers': [],
            'initialize': {},
            'on_start': []
        }

        self.assertEqual(len(get_default_configuration()['overlays']), len(builder.finalize()['overlays']))
        self.assertDictInDict(expected, builder.finalize()['overlays'])

    def test_default_configuration(self):
        """
        Check if we can reconstruct the default configuration.
        """
        builder = ConfigBuilder(True).set_address("0.0.0.0") \
                                     .set_port(8090) \
                                     .add_key("anonymous id", "curve25519", "ec_multichain.pem") \
                                     .set_log_level("INFO") \
                                     .set_working_directory(".") \
                                     .set_walker_interval(0.5) \
                                     .add_overlay("DiscoveryCommunity",
                                                  "anonymous id",
                                                  [WalkerDefinition(Strategy.RandomWalk, 20, {'timeout': 3.0}),
                                                   WalkerDefinition(Strategy.RandomChurn, -1, {
                                                       'sample_size': 8,
                                                       'ping_interval': 10.0,
                                                       'inactive_time': 27.5,
                                                       'drop_time': 57.5
                                                   }),
                                                   WalkerDefinition(Strategy.PeriodicSimilarity, -1, {})],
                                                  [BootstrapperDefinition(Bootstrapper.DispersyBootstrapper,
                                                                          DISPERSY_BOOTSTRAPPER['init'])],
                                                  {},
                                                  []) \
                                     .add_overlay("HiddenTunnelCommunity",
                                                  "anonymous id",
                                                  [WalkerDefinition(Strategy.RandomWalk, 20, {'timeout': 3.0})],
                                                  [BootstrapperDefinition(Bootstrapper.DispersyBootstrapper,
                                                                          DISPERSY_BOOTSTRAPPER['init'])],
                                                  {'settings': {
                                                      'min_circuits': 1,
                                                      'max_circuits': 1,
                                                      'max_relays_or_exits': 100,
                                                      'max_time': 10 * 60,
                                                      'max_time_inactive': 20,
                                                      'max_traffic': 250 * 1024 * 1024,
                                                      'dht_lookup_interval': 30
                                                  }},
                                                  [('build_tunnels', 1)]) \
                                     .add_overlay("DHTDiscoveryCommunity",
                                                  "anonymous id",
                                                  [WalkerDefinition(Strategy.RandomWalk, 20, {'timeout': 3.0}),
                                                   WalkerDefinition(Strategy.PingChurn, -1, {})],
                                                  [BootstrapperDefinition(Bootstrapper.DispersyBootstrapper,
                                                                          DISPERSY_BOOTSTRAPPER['init'])],
                                                  {},
                                                  [])

        self.assertDictEqual(get_default_configuration(), builder.finalize())
