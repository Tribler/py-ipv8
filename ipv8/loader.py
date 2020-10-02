"""
For most types of Community loading, you can use the ConfigBuilder.
These classes present an alternative way to load Community objects into IPv8, itself loaded into another object.
Use if you have a IPv8 manager (a "session") that needs fine-grained control over the loading of each community.
"""

import logging
from abc import ABCMeta, abstractmethod

from .keyvault.crypto import default_eccrypto
from .peer import Peer


# pylint: disable=W0613


class CommunityLauncher:

    """
    Object in charge of preparing a Community for loading in IPv8.
    """

    __metaclass__ = ABCMeta

    def __init__(self):
        super()
        self.community_args = []
        self.community_kwargs = {}

    def get_name(self):
        """
        Get the launcher name, for pre-launch organisation.

        :rtype: str
        """
        return self.get_overlay_class().__name__

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

    @abstractmethod
    def get_overlay_class(self):
        """
        Get the overlay class this launcher wants to load.

        :rtype: ipv8.overlay.Overlay
        """

    def get_walk_strategies(self):
        """
        Get walk strategies for this class.
        It should be provided as a list of tuples with the class, kwargs and maximum number of peers.
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

        ipv8.overlays.append(overlay)
        for strategy_class, strategy_kwargs, max_peers in walk_strategies:
            ipv8.strategies.append((strategy_class(overlay, **strategy_kwargs), max_peers))

        # Cleanup
        launcher.finalize(ipv8, session, overlay)
        self.community_launchers[launcher.get_name()] = (launcher, True)
