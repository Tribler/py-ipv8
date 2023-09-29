"""
For most types of Community loading, you can use the ConfigBuilder.
These classes present an alternative way to load Community objects into IPv8, itself loaded into another object.
Use if you have a IPv8 manager (a "session") that needs fine-grained control over the loading of each community.
"""
from __future__ import annotations

import abc
import logging
import types
from typing import TYPE_CHECKING, Any, Callable, Type, cast

from .keyvault.crypto import default_eccrypto
from .peer import Peer
from .types import Community

if TYPE_CHECKING:
    from .bootstrapping.bootstrapper_interface import Bootstrapper
    from .peerdiscovery.discovery import DiscoveryStrategy
    from .types import IPv8


class CommunityLauncher:
    """
    Object in charge of preparing a Community for loading in IPv8.
    """

    def __init__(self) -> None:
        """
        Create a new launcher instance.
        """
        super().__init__()
        self.community_args: list = []
        self.community_kwargs: dict = {}

    def get_name(self) -> str:
        """
        Get the launcher name, for pre-launch organisation.
        """
        return self.__class__.__name__

    def not_before(self) -> list[str]:
        """
        Should not launch this before some other launcher has completed.

        :return: The list of launcher names to complete before this is launched
        """
        return []

    def should_launch(self, session: object) -> bool:
        """
        Check whether this launcher should launch.

        For example:

            return session.config.get_tunnel_community_enabled()
        """
        return True

    def prepare(self, overlay_provider: IPv8, session: object) -> None:
        """
        Perform setup tasks before the community is loaded.
        """

    def finalize(self, ipv8: IPv8, session: object, community: Community) -> None:
        """
        Perform cleanup tasks after the community has been loaded.
        """

    def get_kwargs(self, session: object) -> dict:
        """
        Get the kwargs to load the community with.
        """
        ret = {}
        ret.update(self.community_kwargs)
        return ret

    @abc.abstractmethod
    def get_overlay_class(self) -> type[Community]:
        """
        Get the overlay class this launcher wants to load.

        This raises a RuntimeError if it was not overwritten at runtime, to appease Pylint.
        """

    def get_walk_strategies(self) -> list[tuple[type[DiscoveryStrategy], dict, int]]:
        """
        Get walk strategies for this class.
        It should be provided as a list of tuples with the class, kwargs and maximum number of peers.
        """
        return []

    def get_bootstrappers(self, session: object) -> list[tuple[type[Bootstrapper], dict]]:
        """
        Get the bootstrappers for this class.
        It should be provided as a list of tuples with the class and kwargs.
        """
        return []

    def get_my_peer(self, ipv8: IPv8, session: object) -> Peer:
        """
        Create a new Peer object that represents our own peer for the overlay.
        """
        return Peer(default_eccrypto.generate_key("curve25519"))


class CommunityLoader:
    """
    Object in charge of loading communities into IPv8.
    """

    def __init__(self) -> None:
        """
        Create a new loader instance.
        """
        self.community_launchers: dict[str, tuple[CommunityLauncher, bool]] = {}
        self._logger = logging.getLogger(self.__class__.__name__)

    def get_launcher(self, name: str) -> CommunityLauncher:
        """
        Get the launcher belonging to the given name.
        """
        return self.community_launchers[name][0]

    def has_launched(self, name: str) -> bool:
        """
        Check if the launcher with the given name has already been launched.
        """
        return self.community_launchers[name][1]

    def set_launcher(self, launcher: CommunityLauncher) -> None:
        """
        Register a launcher to be launched by name.

        If a launcher for the same name already existed, it is overwritten.
        """
        assert isinstance(launcher, CommunityLauncher)

        if launcher.get_name() in self.community_launchers:
            self._logger.info("Overriding CommunityLauncher %s", launcher.get_name())
            if self.has_launched(launcher.get_name()):
                self._logger.error("Unable to replace launcher for %s, it was already launched", launcher.get_name())
                return

        self.community_launchers[launcher.get_name()] = (launcher, False)

    def del_launcher(self, launcher: CommunityLauncher) -> None:
        """
        Unregister a launcher.
        """
        assert isinstance(launcher, CommunityLauncher)

        if launcher.get_name() in self.community_launchers:
            del self.community_launchers[launcher.get_name()]

    def load(self, overlay_provider: IPv8, session: object) -> None:
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

    @abc.abstractmethod
    def _launch(self, launcher: CommunityLauncher, ipv8: IPv8, session: object) -> None:
        """
        This method should be overridden.
        """


class IPv8CommunityLoader(CommunityLoader):
    """
    Loader for IPv8 communities.
    """

    def _launch(self, launcher: CommunityLauncher, ipv8: IPv8, session: object) -> None:
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
        kwargs = launcher.get_kwargs(session)

        settings = overlay_class.settings_class(my_peer=peer, endpoint=ipv8.endpoint, network=ipv8.network, **kwargs)
        overlay = overlay_class(settings)
        bootstrappers = launcher.get_bootstrappers(session)

        ipv8.overlays.append(overlay)
        for strategy_class, strategy_kwargs, target_peers in walk_strategies:
            ipv8.strategies.append((strategy_class(overlay, **strategy_kwargs), target_peers))
        for bootstrapper_class, bootstrapper_kwargs in bootstrappers:
            overlay = cast(Community, overlay)
            overlay.bootstrappers.append(bootstrapper_class(**bootstrapper_kwargs))

        # Cleanup
        launcher.finalize(ipv8, session, overlay)
        self.community_launchers[launcher.get_name()] = (launcher, True)


def name(str_name: str) -> Callable[[type[CommunityLauncher]], type[CommunityLauncher]]:
    """
    Specify a custom name for this launcher.

    For example:

     .. code-block :: Python

        @name('Community1')
        class A(CommunityLauncher):
           ...

    :param str_name: the new name to give this launcher.
    """
    def decorator(instance: type[CommunityLauncher]) -> type[CommunityLauncher]:
        def new_get_name(self: CommunityLauncher) -> str:
            return str_name

        instance.get_name = new_get_name  # type: ignore[method-assign]
        return instance
    return decorator


def after(*launcher_name: str) -> Callable[[type[CommunityLauncher]], type[CommunityLauncher]]:
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
    def decorator(instance: type[CommunityLauncher]) -> type[CommunityLauncher]:
        old_not_before = instance.not_before

        def new_not_before(self: CommunityLauncher) -> list[str]:
            return old_not_before(self) + list(launcher_name)

        instance.not_before = new_not_before  # type: ignore[method-assign]
        return instance
    return decorator


def precondition(str_condition: str) -> Callable[[type[CommunityLauncher]], type[CommunityLauncher]]:
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
    def decorator(instance: type[CommunityLauncher]) -> type[CommunityLauncher]:
        old_should_launch = instance.should_launch

        def new_should_launch(self: CommunityLauncher, session: object) -> bool:
            return (old_should_launch(self, session)
                    and eval(str_condition, globals(), locals()))  # noqa: PGH001, S307

        instance.should_launch = new_should_launch  # type: ignore[method-assign]
        return instance
    return decorator


def _get_class(class_or_function: type[Community] | Callable[[Any], type[Community]]) -> type[Community]:
    """
    Return the class by processing incoming argument either as a function or as
    a class.

    :param class_or_function: the class, or the function that represents this class.
    """
    return (cast(Type[Community], class_or_function())  # type: ignore[call-arg, method-assign]
            if isinstance(class_or_function, types.FunctionType)
            else cast(Type[Community], class_or_function))


def overlay(str_module_or_class: str | type[Community] | Callable[[], type[Community]],
            str_definition: str | None = None) -> Callable[[type[CommunityLauncher]], type[CommunityLauncher]]:
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
    def decorator(instance: type[CommunityLauncher]) -> type[CommunityLauncher]:
        if isinstance(str_module_or_class, str):
            if not hasattr(instance, "hiddenimports"):
                setattr(instance, "hiddenimports", set())  # noqa: B010
            instance.hiddenimports.add(str_module_or_class)  # type: ignore[attr-defined]

            def get_overlay_class(self: CommunityLauncher) -> type[Community]:
                return getattr(__import__(cast(str, str_module_or_class), fromlist=[cast(str, str_definition)]),
                               cast(str, str_definition))
        else:
            def get_overlay_class(self: CommunityLauncher) -> type[Community]:
                return _get_class(cast(Type[Community], str_module_or_class))

        instance.get_overlay_class = get_overlay_class  # type: ignore[method-assign]
        return instance
    return decorator


def walk_strategy(str_module_or_class: str | type[DiscoveryStrategy] | Callable[[], type[DiscoveryStrategy]],
                  str_definition: str | None = None,
                  target_peers: int = 20,
                  kw_args: dict | None = None) -> Callable[[type[CommunityLauncher]], type[CommunityLauncher]]:
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
    def decorator(instance: type[CommunityLauncher]) -> type[CommunityLauncher]:
        old_get_walk_strategies = instance.get_walk_strategies

        if isinstance(str_module_or_class, str):
            if not hasattr(instance, "hiddenimports"):
                setattr(instance, "hiddenimports", set())  # noqa: B010
            instance.hiddenimports.add(str_module_or_class)  # type: ignore[attr-defined]
            strategy_class = getattr(__import__(cast(str, str_module_or_class),
                                                fromlist=[cast(str, str_definition)]),
                                     cast(str, str_definition))
        else:
            strategy_class = _get_class(cast(Type[Community], str_module_or_class))

        def new_get_walk_strategies(self: CommunityLauncher) -> list[tuple[type[DiscoveryStrategy], dict, int]]:
            return [*old_get_walk_strategies(self), (strategy_class, kw_args or {}, target_peers)]

        instance.get_walk_strategies = new_get_walk_strategies  # type: ignore[method-assign]
        return instance
    return decorator


def bootstrapper(str_module_or_class: str | type[Bootstrapper] | Callable[[], type[Bootstrapper]],
                 str_definition: str | None = None,
                 kw_args: dict | None  = None) -> Callable[[type[CommunityLauncher]], type[CommunityLauncher]]:
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
    def decorator(instance: type[CommunityLauncher]) -> type[CommunityLauncher]:
        old_get_bootstrappers = instance.get_bootstrappers

        if isinstance(str_module_or_class, str):
            if not hasattr(instance, "hiddenimports"):
                setattr(instance, "hiddenimports", set())  # noqa: B010
            instance.hiddenimports.add(str_module_or_class)  # type: ignore[attr-defined]
            bootstrapper_class = getattr(__import__(cast(str, str_module_or_class),
                                                    fromlist=[cast(str, str_definition)]),
                                         cast(str, str_definition))
        else:
            bootstrapper_class = _get_class(cast(Type[Community], str_module_or_class))

        def new_get_bootstrappers(self: CommunityLauncher, session: object) -> list[tuple[type[Bootstrapper], dict]]:
            return [*old_get_bootstrappers(self, session), (bootstrapper_class, kw_args or {})]

        instance.get_bootstrappers = new_get_bootstrappers  # type: ignore[method-assign]
        return instance
    return decorator


def set_in_session(attribute_name: str) -> Callable[[type[CommunityLauncher]], type[CommunityLauncher]]:
    """
    Specify an attribute to set on the session, once the CommunityLauncher has finished initializing its Community.

    For example, the following sets the ``session.my_community`` to the loaded Community instance:

     .. code-block :: Python

        @set_in_session('my_community')
        class A(CommunityLauncher):
           ...

    :param attribute_name: the attribute name (string) to set on the session, once the Community is loaded.
    """
    def decorator(instance: type[CommunityLauncher]) -> type[CommunityLauncher]:
        old_finalize = instance.finalize

        def new_finalize(self: CommunityLauncher, ipv8: IPv8, session: object, community: Community) -> None:
            out = old_finalize(self, ipv8, session, community)
            setattr(session, attribute_name, community)
            return out

        instance.finalize = new_finalize  # type: ignore[method-assign]
        return instance
    return decorator


def kwargs(**kw_args) -> Callable[[type[CommunityLauncher]], type[CommunityLauncher]]:
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
    def decorator(instance: type[CommunityLauncher]) -> type[CommunityLauncher]:
        old_get_kwargs = instance.get_kwargs

        def new_get_kwargs(self: CommunityLauncher, session: object) -> dict:
            out = old_get_kwargs(self, session)
            for kwarg in kw_args:
                out[kwarg] = eval(kw_args[kwarg], globals(), locals())  # noqa: PGH001, S307
            return out

        instance.get_kwargs = new_get_kwargs  # type: ignore[method-assign]
        return instance

    return decorator
