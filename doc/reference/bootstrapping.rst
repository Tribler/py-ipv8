IPv8 bootstrapping
==================

Peers discover each other through other Peers, as specified in the `the Peer discovery basics <../reference/peer_discovery.html>`_.
We call this type of Peer discovery *introduction*.
However, you cannot be introduced to a new Peer if you don't know anyone to introduce you in the first place.
This document discusses how IPv8 provides you your first contact.

Bootstrap servers (rendezvous nodes)
------------------------------------

To provide you an initial point of introduction, IPv8 mainly uses bootstrap servers (also known as rendezvous nodes).
You can connect to these servers to attempt to find other Peers for your overlay.
A bootstrap server will then respond to your request for Peers with Peers that have contacted it for the same overlay.
However, these bootstrap servers only introduce you to other Peers, they do not (and can not) actually join any overlay.
A bootstrap server also has no way of knowing what your overlay does, it only knows its 20-byte identifier.

By default, IPv8 comes supplied with a handful of bootstrap IP addresses and bootstrap DNS addresses.
You can freely extend or replace the default servers with your own.
To tell IPv8 what bootstrap IP addresses and bootstrap DNS addresses it should connect to, you can use the ``DispersyBootstrapper`` class.

Using bootstrap servers
^^^^^^^^^^^^^^^^^^^^^^^

To have IPv8 load a bootstrapper for your overlay, you can simply add it to your ``ConfigBuilder.add_overlay()`` step.
This is the easiest way to load a bootstrapper.
For most intents and purposes you can simply use ``default_bootstrap_defs`` provided by ``ipv8.configuration`` (see `the overlay tutorial <../basics/overlay_tutorial.html>`_).
However, you can also completely change the bootstrap servers you use.
For example, this code sets two bootstrap addresses (the IP address 1.2.3.4 with port 5 and the DNS address tribler.org with port 5):

 .. code-block:: python

    ConfigBuilder().add_overlay("MyCommunity",
                                "my id",
                                [WalkerDefinition(Strategy.RandomWalk, 42, {'timeout': 3.0})],
                                [BootstrapperDefinition(Bootstrapper.DispersyBootstrapper,
                                                        {'ip_addresses': [('1.2.3.4', 5)],
                                                         'dns_addresses': [('tribler.org', 5)]})],
                                {},
                                [])

If you are using the ``loader`` instead of ``configuration`` you can load a bootstrapper into your launcher as follows:

 .. code-block:: python

    @overlay('my_module.some_submodule', 'MyCommunity')
    @walk_strategy(RandomWalk)
    @bootstrapper(DispersyBootstrapper, kw_args={'ip_addresses': [('1.2.3.4', 5)], 'dns_addresses': [('tribler.org', 5)]})
    class MyLauncher(CommunityLauncher):
        pass

If you are using neither the ``loader`` nor the ``configuration``, you can manually add a ``DispersyBootstrapper`` instance to your overlay's ``bootstrappers`` field.
However, you should do so before the overlay starts discovering Peers (i.e., before `IPv8.start()` is invoked).

Running a bootstrap server
^^^^^^^^^^^^^^^^^^^^^^^^^^

To run your own bootstrap server simply call ``scripts/tracker_plugin.py``.
For example, this code will attempt to bind to port 12345:

 .. code-block:: bash

    python tracker_plugin.py --listen_port=12345

You are responsible to configure your port forwarding over your hardware in such a way that the specified listen port is connectable.

UDP broadcasts
--------------

Next to bootstrap servers, IPv8 also allows serverless Peer discovery for LANs.
This is done using UDP broadcast sockets.
These broadcasts consist of sending an IPv8 probe UDP packet to all possible ports of the IPv4 broadcast address.
You should consider this option if you are having trouble connecting to other Peers in your home network.
This method is usually very effective for simple home networks.
However, complex home (or work) network setups may still fail to discover these local Peers.

Using UDP broadcasts
^^^^^^^^^^^^^^^^^^^^
Loading UDP broadcast bootstrapping for your overlay functions much the same as using bootstrap servers.
Again, you can simply add it to your ``ConfigBuilder.add_overlay()`` step:

 .. code-block:: python

    ConfigBuilder().add_overlay("MyCommunity",
                                "my id",
                                [WalkerDefinition(Strategy.RandomWalk, 42, {'timeout': 3.0})],
                                [BootstrapperDefinition(Bootstrapper.UDPBroadcastBootstrapper, {})],
                                {},
                                [])

If you are using the ``loader`` instead of ``configuration`` you can load a bootstrapper into your launcher as follows:

 .. code-block:: python

    @overlay('my_module.some_submodule', 'MyCommunity')
    @walk_strategy(RandomWalk)
    @bootstrapper(UDPBroadcastBootstrapper)
    class MyLauncher(CommunityLauncher):
        pass

If you are using neither the ``loader`` nor the ``configuration``, you can manually add a ``UDPBroadcastBootstrapper`` instance to your overlay's ``bootstrappers`` field.

Making your own Bootstrapper
----------------------------

As you may have noticed, loading a ``DispersyBootstrapper`` and a ``UDPBroadcastBootstrapper`` is highly similar.
This is because they both inherit from the ``Bootstrapper`` interface.
You can fulfill the same interface to provide your own bootstrapping mechanism.
To use custom bootstrappers you will either have to use the ``loader`` or manual loading methods.