"""
For most types of Community loading, you can use the ConfigBuilder.
These classes present an alternative way to load Community objects into IPv8, itself loaded into another object.
Use if you have a IPv8 manager (a "session") that needs fine-grained control over the loading of each community.
"""

import logging
import types

from .keyvault.crypto import default_eccrypto
from .peer import Peer


# pylint: disable=W0613


def name(str_name):
    """
    Specify a custom name for this launcher.

    For example:

     .. code-block :: Python

        @name('Community1')
        class A(CommunityLauncher):
           ...

    :param str_name: the new name to give this launcher.
    """
    def decorator(instance):
        def new_get_name(_):
            return str_name

        instance.get_name = new_get_name
        return instance
    return decorator


def after(*launcher_name):
    """
    Specify one or more Community classes which should be loaded before the CommunityLauncher is invoked.
    You may call this multiple times and/or with multiple arguments.

    For example:

     .. code-block :: Python

        @after('CommunityLauncher1', 'CommunityLauncher2')
        class A(CommunityLauncher):
           ...

        @after('CommunityLauncher1')
        @after('CommunityLauncher2')
        class A(CommunityLauncher):
           ...

    :param launcher_name: the launcher name(s) that need to be loaded beforehand.
    """
    def decorator(instance):
        old_not_before = instance.not_before

        def new_not_before(self):
            return old_not_before(self) + list(launcher_name)

        instance.not_before = new_not_before
        return instance
    return decorator


def precondition(str_condition):
    """
    Specify a string to be evaluated and interpreted as a condition for this CommunityLauncher to start.
    A ``session`` object is provided to pull a state from.
    You may call this multiple times.

    For example:

     .. code-block :: Python

        @precondition('session.some_condition')
        class A(CommunityLauncher):
           ...

        @precondition('session.some_condition')
        @precondition('not session.some_condition_method()')
        class A(CommunityLauncher):
           ...

    :param str_condition: the string to be evaluated as a launch condition.
    """
    def decorator(instance):
        old_should_launch = instance.should_launch

        def new_should_launch(self, session):
            return (old_should_launch(self, session)
                    and eval(str_condition, globals(), locals()))  # pylint: disable=W0123

        instance.should_launch = new_should_launch
        return instance
    return decorator


def _get_class(class_or_function):
    """
    Return the class by processing incoming argument either as a function or as
    a class.

    :param class_or_function: the class, or the function that represents this class.
    """
    return class_or_function() if isinstance(class_or_function, types.FunctionType) \
        else class_or_function


def overlay(str_module_or_class, str_definition=None):
    """
    Specify, as strings, a module and Community class object defined therein to lazy-load.
    Otherwise, give an actual Community class to load.

    For example:

     .. code-block :: Python

        @overlay('my_module.some_submodule', 'MyCommunityClass')
        class A(CommunityLauncher):
           ...

        from my_module.some_submodule import MyCommunityClass
        @overlay(MyCommunityClass)
        class A(CommunityLauncher):
           ...

        def my_community_class():
            from my_module.some_submodule import MyCommunityClass
            return MyCommunityClass

        @overlay(my_community_class)
        class A(CommunityLauncher):
           ...

    :param str_module_or_class: either the module to load or a Community class.
    :param str_definition: either the class definition to load or None if str_module_or_class is not a string.
    """
    def decorator(instance):
        if isinstance(str_module_or_class, str):
            if not hasattr(instance, "hiddenimports"):
                setattr(instance, "hiddenimports", set())
            instance.hiddenimports.add(str_module_or_class)

            def get_overlay_class(_):
                return getattr(__import__(str_module_or_class, fromlist=[str_definition]), str_definition)
        else:
            def get_overlay_class(_):
                return _get_class(str_module_or_class)

        instance.get_overlay_class = get_overlay_class
        return instance
    return decorator


def walk_strategy(str_module_or_class, str_definition=None, target_peers=20, kw_args=None):
    """
    Specify, as strings, a module and DiscoveryStrategy class object defined therein to lazy-load.
    Otherwise, give an actual DiscoveryStrategy class to load.

    For example:

     .. code-block :: Python

        @walk_strategy('my_module.some_submodule', 'MyStrategyClass')
        class A(CommunityLauncher):
           ...

        from my_module.some_submodule import MyStrategyClass
        @walk_strategy(MyStrategyClass)
        class A(CommunityLauncher):
           ...

        @walk_strategy('my_module.some_submodule', 'MyStrategyClass', target_peers=-1, kwargs={'a key': 'a value'})
        class A(CommunityLauncher):
           ...

       def my_strategy_class():
            from my_module.some_submodule import MyStrategyClass
            return MyStrategyClass

        @walk_strategy(my_strategy_class)
        class A(CommunityLauncher):
            ...

    :param str_module_or_class: either the module to load or a DiscoveryStrategy class.
    :param str_definition: either the class definition to load or None if str_module_or_class is not a string.
    :param target_peers: the target_peers for the strategy.
    :param kw_args: the keyword arguments to initialize the DiscoveryStrategy instance with.
    """
    def decorator(instance):
        old_get_walk_strategies = instance.get_walk_strategies

        if isinstance(str_module_or_class, str):
            if not hasattr(instance, "hiddenimports"):
                setattr(instance, "hiddenimports", set())
            instance.hiddenimports.add(str_module_or_class)
            strategy_class = getattr(__import__(str_module_or_class, fromlist=[str_definition]), str_definition)
        else:
            strategy_class = _get_class(str_module_or_class)

        def new_get_walk_strategies(self):
            return old_get_walk_strategies(self) + [(strategy_class, kw_args or {}, target_peers)]

        instance.get_walk_strategies = new_get_walk_strategies
        return instance
    return decorator


def bootstrapper(str_module_or_class, str_definition=None, kw_args=None):
    """
    Specify, as strings, a module and Bootstrapper class object defined therein to lazy-load.
    Otherwise, give an actual Bootstrapper class to load.

    For example:

     .. code-block :: Python

        @bootstrapper('my_module.some_submodule', 'MyBootstrapper')
        class A(CommunityLauncher):
           ...

        from my_module.some_submodule import MyBootstrapper
        @bootstrapper(MyBootstrapper)
        class A(CommunityLauncher):
           ...

        @bootstrapper('my_module.some_submodule', 'MyBootstrapper', kw_args={'a key': 'a value'})
        class A(CommunityLauncher):
           ...

       def my_bootstrapper_class():
            from my_module.some_submodule import MyBootstrapper
            return MyBootstrapper

        @bootstrapper(my_bootstrapper_class)
        class A(CommunityLauncher):
            ...

    :param str_module_or_class: either the module to load or a Bootstrapper class.
    :param str_definition: either the class definition to load or None if str_module_or_class is not a string.
    :param kw_args: the keyword arguments to initialize the Bootstrapper instance with.
    """
    def decorator(instance):
        old_get_bootstrappers = instance.get_bootstrappers

        if isinstance(str_module_or_class, str):
            if not hasattr(instance, "hiddenimports"):
                setattr(instance, "hiddenimports", set())
            instance.hiddenimports.add(str_module_or_class)
            bootstrapper_class = getattr(__import__(str_module_or_class, fromlist=[str_definition]), str_definition)
        else:
            bootstrapper_class = _get_class(str_module_or_class)

        def new_get_bootstrappers(self, session):
            return old_get_bootstrappers(self, session) + [(bootstrapper_class, kw_args or {})]

        instance.get_bootstrappers = new_get_bootstrappers
        return instance
    return decorator


def set_in_session(attribute_name):
    """
    Specify an attribute to set on the session, once the CommunityLauncher has finished initializing its Community.

    For example, the following sets the ``session.my_community`` to the loaded Community instance:

     .. code-block :: Python

        @set_in_session('my_community')
        class A(CommunityLauncher):
           ...

    :param attribute_name: the attribute name (string) to set on the session, once the Community is loaded.
    """
    def decorator(instance):
        old_finalize = instance.finalize

        def new_finalize(self, ipv8, session, community):
            out = old_finalize(self, ipv8, session, community)
            setattr(session, attribute_name, community)
            return out

        instance.finalize = new_finalize
        return instance
    return decorator


def kwargs(**kw_args):
    """
    Specify keyword arguments as evaluated strings, to initialize the Community with.
    A ``session`` object is provided to pull a state from.

    For example:

     .. code-block :: Python

        @kwargs('working_directory'='session.working_directory')
        class A(CommunityLauncher):
           ...

        @kwargs(a_key='"I am a string! :)"')
        class A(CommunityLauncher):
           ...

    :param kw_args: the mapping of keyword arguments to statements to be evaluated.
    """
    def decorator(instance):
        old_get_kwargs = instance.get_kwargs

        def new_get_kwargs(self, session):
            out = old_get_kwargs(self, session)
            for kwarg in kw_args:
                out[kwarg] = eval(kw_args[kwarg], globals(), locals())  # pylint: disable=W0123
            return out

        instance.get_kwargs = new_get_kwargs
        return instance

    return decorator


class CommunityLauncher:

    """
    Object in charge of preparing a Community for loading in IPv8.
    """

    def __init__(self):
        super()
        self.community_args = []
        self.community_kwargs = {}

    def get_name(self):
        """
        Get the launcher name, for pre-launch organisation.

        :rtype: str
        """
        return self.__class__.__name__

    def not_before(self):
        """
        Should not launch this before some other launcher has completed.

        :return: The list of launcher names to complete before this is launched
        """
        return []

    def should_launch(self, session):
        """
        Check whether this launcher should launch.

        For example:

            return session.config.get_tunnel_community_enabled()

        :type session: object
        :rtype: bool
        """
        return True

    def prepare(self, overlay_provider, session):
        """
        Perform setup tasks before the community is loaded.

        :type overlay_provider: ipv8.IPv8
        :type session: object
        """

    def finalize(self, ipv8, session, community):
        """
        Perform cleanup tasks after the community has been loaded.

        :type ipv8: ipv8.IPv8
        :type session: object
        :type community: IPv8 community
        """

    def get_args(self, session):
        """
        Get the args to load the community with.

        :rtype: tuple
        """
        return self.community_args

    def get_kwargs(self, session):
        """
        Get the kwargs to load the community with.

        :rtype: dict or None
        """
        ret = {}
        ret.update(self.community_kwargs)
        return ret

    def get_overlay_class(self):
        """
        Get the overlay class this launcher wants to load.

        This raises a RuntimeError if it was not overwritten at runtime, to appease Pylint.

        :rtype: ipv8.overlay.Overlay
        """
        raise RuntimeError("CommunityLaunchers should define an Overlay class to load!")

    def get_walk_strategies(self):
        """
        Get walk strategies for this class.
        It should be provided as a list of tuples with the class, kwargs and maximum number of peers.
        """
        return []

    def get_bootstrappers(self, session):
        """
        Get the bootstrappers for this class.
        It should be provided as a list of tuples with the class and kwargs.
        """
        return []

    def get_my_peer(self, ipv8, session):
        return Peer(default_eccrypto.generate_key("curve25519"))


class CommunityLoader:
    """
    Object in charge of loading communities into IPv8.
    """

    def __init__(self):
        self.community_launchers = {}
        self._logger = logging.getLogger(self.__class__.__name__)

    def get_launcher(self, name):
        return self.community_launchers[name][0]

    def has_launched(self, name):
        return self.community_launchers[name][1]

    def set_launcher(self, launcher):
        """
        Register a launcher to be launched by name.

        If a launcher for the same name already existed, it is overwritten.

        :type launcher: CommunityLauncher
        """
        assert isinstance(launcher, CommunityLauncher)

        if launcher.get_name() in self.community_launchers:
            self._logger.info("Overriding CommunityLauncher %s", launcher.get_name())
            if self.has_launched(launcher.get_name()):
                self._logger.error("Unable to replace launcher for %s, it was already launched", launcher.get_name())
                return

        self.community_launchers[launcher.get_name()] = (launcher, False)

    def del_launcher(self, launcher):
        """
        Unregister a launcher

        :type launcher: CommunityLauncher
        """
        assert isinstance(launcher, CommunityLauncher)

        if launcher.get_name() in self.community_launchers:
            del self.community_launchers[launcher.get_name()]

    def load(self, overlay_provider, session):
        """
        Load all of the communities specified by the registered launchers into IPv8.
        """
        remaining = [launcher for launcher, _ in self.community_launchers.values()]
        cycle = len(remaining) * len(remaining)
        while remaining and cycle >= 0:
            launcher = remaining.pop(0)
            cycle -= 1
            if launcher.should_launch(session):
                validated = True
                for dependency in launcher.not_before():
                    # If the dependency does not exist, don't wait for it
                    # If the dependency is never loaded, don't wait for it
                    if dependency in self.community_launchers and \
                            self.community_launchers[dependency][0].should_launch(session):
                        validated = validated and self.has_launched(dependency)
                if validated:
                    self._launch(launcher, overlay_provider, session)
                else:
                    remaining.append(launcher)
        if cycle < 0:
            launcher_names = [launcher.get_name() for launcher in remaining]
            raise RuntimeError("Cycle detected in CommunityLauncher not_before(): %s" % (str(launcher_names)))
        self._logger.info("Finished loading communities!")

    def _launch(self, launcher, ipv8, session):
        """
        This method should be overridden.
        """


class IPv8CommunityLoader(CommunityLoader):
    """
    Loader for IPv8 communities.
    """

    def _launch(self, launcher, ipv8, session):
        """
        Launch a launcher: register the overlay with IPv8.
        """
        # Prepare launcher
        launcher.prepare(ipv8, session)
        # Register community
        overlay_class = launcher.get_overlay_class()
        self._logger.info("Loading overlay %s", overlay_class)
        walk_strategies = launcher.get_walk_strategies()
        peer = launcher.get_my_peer(ipv8, session)
        args = launcher.get_args(session)
        kwargs = launcher.get_kwargs(session)
        overlay = overlay_class(peer, ipv8.endpoint, ipv8.network, *args, **kwargs)
        bootstrappers = launcher.get_bootstrappers(session)

        ipv8.overlays.append(overlay)
        for strategy_class, strategy_kwargs, target_peers in walk_strategies:
            ipv8.strategies.append((strategy_class(overlay, **strategy_kwargs), target_peers))
        for bootstrapper_class, bootstrapper_kwargs in bootstrappers:
            overlay.bootstrappers.append(bootstrapper_class(**bootstrapper_kwargs))

        # Cleanup
        launcher.finalize(ipv8, session, overlay)
        self.community_launchers[launcher.get_name()] = (launcher, True)
