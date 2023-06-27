TunnelCommunity
===============

This document contains a description of how to use the ``TunnelCommunity`` class for anonymous communication and the ``HiddenTunnelCommunity`` extension of this functionality, which provides service-based end-to-end anonymous communication.
The ``TunnelCommunity`` class should be used when passively contributing to the network health and the ``HiddenTunnelCommunity`` should be used when you want to actively send over the network.

In particular this document will **not** discuss how creating and managing circuits and setting up hidden services works, for this we refer the reader to the Tor research.

Interface
---------

The ``HiddenTunnelCommunity`` class provides an interface for anonymous messaging.
The most important methods of this class are:


* ``build_tunnels()``\ : which will start making the required amount of circuits for the given hop count
* ``active_data_circuits()``\ : will return the currently available circuits to send data over
* ``tunnels_ready()``\ : the quotient of available circuits to send over, compared to ``settings.min_circuits``
* ``tunnel_data()``\ : which will send data to some destination through an exit node
* ``register_service()``\ : which provide end-to-end connections for a particular service

Note that you will have to call ``build_tunnels()`` before sending any data.
For example ``build_tunnels(1)`` will construct 1 hop circuits to maintain a circuit pool of a size between ``settings.min_circuits`` and ``settings.max_circuits``.
Initializing these settings will be covered in a later section.

You can then call ``tunnel_data()`` to send data through a circuit (and eventually an exit node) to some destination.
The circuit to send over should be one of the circuits returned by active_data_circuits().
The destination can be any ip + port tuple.
The message type should be ``u"data"`` and finally the payload can be an arbitrary message.
For example one could send the packet ``1`` to ``("1.2.3.4", 5)``\ :

.. code-block:: python

   community.tunnel_data(community.active_data_circuits()[0], ("1.2.3.4", 5), u"data", "1")

Hidden services
---------------

The ``HiddenTunnelCommunity`` class can also find other circuit exit points for a particular service identifier.
In other words, it is possible to anonymously find other peers communicating anonymously.
To do this, some sort of DHT mechanism needs to be registered (currently Tribler uses mainline DHT).
Whatever DHT mechanism is chosen should be placed in the ``dht_provider`` attribute of the ``HiddenTunnelCommunity``.

Whenever a peer is found for a service, or rather the anonymizing relay for a peer, the callback defined through ``register_service()`` is called with the available peers.
You can then use this peer to ``tunnel_data()`` to.
The complete example is given below:

.. code-block:: python

   def on_peer(peer):
       community.tunnel_data(community.active_data_circuits()[0], peer, u"data", "my message to this peer")
   community.register_service("my service identifier", hops=1, on_peer)

TunnelSettings
--------------

The community can be initialized using the ``TunnelSettings`` class. This class contains the following fields:


* *min_circuits*\ : the minimum amount of circuits to create before ``tunnels_ready()`` gives a value larger than 1.0
* *max_circuits*\ : the maximum amount of circuits to create
* *max_joined_circuits*\ : the maximum amount of circuits, which are not our own, we will partake in
* *max_time*\ : the time after which a circuit will be removed (for security reasons)
* *max_time_inactive*\ : the time after which an idle circuit is removed
* *max_traffic*\ : the amount of traffic after which a circuit will be removed (for security reasons)
* *become_exitnode*\ : whether or not we will exit data for others (may have legal ramifications)
