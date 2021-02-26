from .base import TestBase
from ..loader import (CommunityLauncher, IPv8CommunityLoader, after, bootstrapper, kwargs, name, overlay, precondition,
                      set_in_session, walk_strategy)


class MockCommunity:

    def __init__(self, peer, endpoint, network, *args, **kw_args):
        self.peer = peer
        self.endpoint = endpoint
        self.network = network
        self.args = args
        self.kwargs = kw_args
        self.bootstrappers = []


class MockWalk:

    def __init__(self, community, some_attribute):
        self.overlay = community
        self.some_attribute = some_attribute


class MockWalk2:
    pass


class MockBootstrapper:

    def __init__(self, some_attribute):
        self.some_attribute = some_attribute


class MockBootstrapper2:
    pass


class MockSession:

    launch_condition1 = True
    launch_condition2 = False
    some_attribute1 = "I am a string :)"
    some_attribute2 = 1337
    community = None


class MockOverlayProvider:
    endpoint = None
    network = None

    def __init__(self):
        self.overlays = []
        self.strategies = []


class StagedCommunityLauncher(CommunityLauncher):

    def not_before(self):
        return ['CommunityLauncher1', 'CommunityLauncher2']

    def should_launch(self, session: MockSession):
        return session.launch_condition1 and not session.launch_condition2

    def get_overlay_class(self):
        return MockCommunity

    def get_kwargs(self, session: MockSession):
        return {
            'kw1': session.some_attribute1,
            'kw2': session.some_attribute2
        }

    def get_walk_strategies(self):
        return [(MockWalk, {'some_attribute': 4}, 20)]

    def get_bootstrappers(self, session):
        return [(MockBootstrapper, {'some_attribute': 4})]

    def finalize(self, ipv8, session: MockSession, community: MockCommunity):
        session.community = community
        return super()


class TestCommunityLauncher(TestBase):

    def setUp(self):
        self.staged_launcher = StagedCommunityLauncher()
        return super()

    def test_not_before_list(self):
        """
        Check that the not_before decorator with multiple arguments equals the not_before() definition.
        """
        @after('CommunityLauncher1', 'CommunityLauncher2')
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertListEqual(self.staged_launcher.not_before(), DecoratedCommunityLauncher().not_before())

    def test_not_before_multiple(self):
        """
        Check that multiple not_before decorators with an argument equals the not_before() definition.
        """
        @after('CommunityLauncher2')
        @after('CommunityLauncher1')
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertListEqual(self.staged_launcher.not_before(), DecoratedCommunityLauncher().not_before())

    def test_should_launch_single(self):
        """
        Check that a validated single launch condition causes should_launch() to return True.
        """
        @precondition('session.launch_condition1')
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertTrue(DecoratedCommunityLauncher().should_launch(MockSession()))

    def test_shouldnt_launch_single(self):
        """
        Check that an invalid single launch condition causes should_launch() to return False.
        """
        @precondition('session.launch_condition2')
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertFalse(DecoratedCommunityLauncher().should_launch(MockSession()))

    def test_should_launch_multiple(self):
        """
        Check that a validated multiple launch conditions causes should_launch() to return True.
        """
        @precondition('session.launch_condition1')
        @precondition('not session.launch_condition2')
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertTrue(DecoratedCommunityLauncher().should_launch(MockSession()))
        self.assertTrue(self.staged_launcher.should_launch(MockSession()))

    def test_shouldnt_launch_multiple(self):
        """
        Check that an invalid condition for multiple launch conditions causes should_launch() to return False.
        """
        @precondition('session.launch_condition1')
        @precondition('session.launch_condition2')
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertFalse(DecoratedCommunityLauncher().should_launch(MockSession()))

    def test_overlay_class_from_str(self):
        """
        Check if a Community string specification can be lazy-loaded through the overlay_class decorator.
        """
        @overlay(self.__class__.__module__, 'MockCommunity')
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertEqual(self.staged_launcher.get_overlay_class(), DecoratedCommunityLauncher().get_overlay_class())
        self.assertSetEqual({self.__class__.__module__}, DecoratedCommunityLauncher.hiddenimports)

    def test_overlay_class_from_class(self):
        """
        Check if a Community class can be lazy-loaded through the overlay_class decorator.
        """
        @overlay(MockCommunity)
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertEqual(self.staged_launcher.get_overlay_class(), DecoratedCommunityLauncher().get_overlay_class())

    def test_overlay_class_from_function(self):
        """
        Check if a Community class (functional representation) can be lazy-loaded
        through the overlay_class decorator.
        """

        def MockCommunityFunction():
            return MockCommunity

        @overlay(MockCommunityFunction)
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertEqual(self.staged_launcher.get_overlay_class(),
                         DecoratedCommunityLauncher().get_overlay_class())

    def test_walk_strategy_from_str(self):
        """
        Check if adding a walk strategy string specification is successful.
        """
        @walk_strategy(self.__class__.__module__, 'MockWalk', kw_args={'some_attribute': 4})
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertListEqual(self.staged_launcher.get_walk_strategies(),
                             DecoratedCommunityLauncher().get_walk_strategies())
        self.assertSetEqual({self.__class__.__module__}, DecoratedCommunityLauncher.hiddenimports)

    def test_walk_strategy_from_class(self):
        """
        Check if adding a walk strategy from a DiscoveryStrategy class is successful.
        """
        @walk_strategy(MockWalk, kw_args={'some_attribute': 4})
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertListEqual(self.staged_launcher.get_walk_strategies(),
                             DecoratedCommunityLauncher().get_walk_strategies())

    def test_walk_strategy_from_function(self):
        """
        Check if adding a walk strategy from a function is successful.
        """

        def MockWalkFunction():
            return MockWalk

        @walk_strategy(MockWalkFunction, kw_args={'some_attribute': 4})
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertListEqual(self.staged_launcher.get_walk_strategies(),
                             DecoratedCommunityLauncher().get_walk_strategies())

    def test_walk_strategy_multiple(self):
        """
        Check if adding multiple walk strategies is successful.
        """
        @walk_strategy(MockWalk2, target_peers=-1)
        @walk_strategy(self.__class__.__module__, 'MockWalk', kw_args={'some_attribute': 4})
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertListEqual([(MockWalk, {'some_attribute': 4}, 20), (MockWalk2, {}, -1)],
                             DecoratedCommunityLauncher().get_walk_strategies())
        self.assertSetEqual({self.__class__.__module__}, DecoratedCommunityLauncher.hiddenimports)

    def test_bootstrapper_from_str(self):
        """
        Check if adding a bootstrapper string specification is successful.
        """
        @bootstrapper(self.__class__.__module__, 'MockBootstrapper', kw_args={'some_attribute': 4})
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertListEqual(self.staged_launcher.get_bootstrappers(MockSession()),
                             DecoratedCommunityLauncher().get_bootstrappers(MockSession()))
        self.assertSetEqual({self.__class__.__module__}, DecoratedCommunityLauncher.hiddenimports)

    def test_bootstrapper_from_class(self):
        """
        Check if adding a bootstrapper from a Bootstrapper class is successful.
        """
        @bootstrapper(MockBootstrapper, kw_args={'some_attribute': 4})
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertListEqual(self.staged_launcher.get_bootstrappers(MockSession()),
                             DecoratedCommunityLauncher().get_bootstrappers(MockSession()))

    def test_bootstrapper_from_function(self):
        """
        Check if adding a bootstrapper from a function is successful.
        """

        def mock_bootstrapper():
            return MockBootstrapper

        @bootstrapper(mock_bootstrapper, kw_args={'some_attribute': 4})
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertListEqual(self.staged_launcher.get_bootstrappers(MockSession()),
                             DecoratedCommunityLauncher().get_bootstrappers(MockSession()))

    def test_bootstrapper_multiple(self):
        """
        Check if adding multiple bootstrappers is successful.
        """
        @bootstrapper(MockBootstrapper2)
        @bootstrapper(self.__class__.__module__, 'MockBootstrapper', kw_args={'some_attribute': 4})
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertListEqual([(MockBootstrapper, {'some_attribute': 4}), (MockBootstrapper2, {})],
                             DecoratedCommunityLauncher().get_bootstrappers(MockSession()))
        self.assertSetEqual({self.__class__.__module__}, DecoratedCommunityLauncher.hiddenimports)

    def test_set_in_session(self):
        """
        Check if set_in_session correctly sets the attribute of the session.
        """
        @set_in_session('community')
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        session = MockSession()
        community = MockCommunity(None, None, None)
        DecoratedCommunityLauncher().finalize(None, session, community)

        self.assertEqual(community, session.community)

    def test_kwargs(self):
        """
        Check if the kwargs decorator correctly passes keyword arguments.
        """
        @kwargs(kw1='session.some_attribute1', kw2='session.some_attribute2')
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        session = MockSession()
        self.assertDictEqual(self.staged_launcher.get_kwargs(session), DecoratedCommunityLauncher().get_kwargs(session))

    def test_name(self):
        """
        Check if the name of a launcher can be set, using the name decorator.
        """
        @name('Some Name')
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertEqual('Some Name', DecoratedCommunityLauncher().get_name())

    def test_no_name(self):
        """
        Check if the name of a launcher is equal to the Community class name by default.
        """
        @overlay(MockCommunity)
        class DecoratedCommunityLauncher(CommunityLauncher):
            pass

        self.assertEqual('DecoratedCommunityLauncher', DecoratedCommunityLauncher().get_name())


class TestCommunityLoader(TestBase):

    def setUp(self):
        self.community_loader = IPv8CommunityLoader()
        self.overlay_provider = MockOverlayProvider()
        self.session = MockSession()

    def test_load_community(self):
        """
        Check if a CommunityLauncher is launched correctly.
        """
        self.community_loader.set_launcher(StagedCommunityLauncher())

        self.community_loader.load(self.overlay_provider, self.session)

        self.assertEqual(1, len(self.overlay_provider.overlays))
        self.assertEqual(1, len(self.overlay_provider.strategies))

        loaded_overlay = self.overlay_provider.overlays[0]
        loaded_strategy = self.overlay_provider.strategies[0]

        self.assertIsInstance(loaded_overlay, MockCommunity)
        self.assertIsInstance(loaded_strategy[0], MockWalk)
        self.assertEqual(loaded_overlay, loaded_strategy[0].overlay)
        self.assertEqual(4, loaded_strategy[0].some_attribute)
        self.assertEqual(20, loaded_strategy[1])

    def test_protect_infinite_loop(self):
        """
        Check if the CommunityLoader raises an error when it encounters a circular dependency.
        """
        @name("A")
        @overlay(MockCommunity)
        @after("B")
        class A(CommunityLauncher):
            pass

        @name("B")
        @overlay(MockCommunity)
        @after("A")
        class B(CommunityLauncher):
            pass

        self.community_loader.set_launcher(A())
        self.community_loader.set_launcher(B())

        self.assertRaises(RuntimeError, self.community_loader.load, self.overlay_provider, self.session)
