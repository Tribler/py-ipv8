Network IO and the DiscoveryStrategy
====================================

This document assumes you have a basic understanding of asyncio tasks, as documented in `the tasks tutorial <../basics/tasks_tutorial.html>`_.
You will learn how to use the IPv8's ``DiscoveryStrategy`` class to avoid network congestion.

The DiscoveryStrategy
---------------------

IPv8 only manages one socket (``Endpoint``), which is most likely using the UDP protocol.
If every ``Community`` starts sending at the exact same time and overpowers the UDP socket, this causes packet drops.
To counter this, IPv8 has the ``DiscoveryStrategy`` class.

An IPv8 instance will call each of its registered ``DiscoveryStrategy`` instances sequentially to avoid network I/O clashes.
If you have an ``interval`` task in your ``TaskManager`` that leads to network I/O, you should consider converting it to a ``DiscoveryStrategy``.
You can make your own subclass as follows:

.. literalinclude:: discoverystrategy_tutorial_1.py
   :lines: 13-20

Note that a ``DiscoveryStrategy`` should be thread-safe.
You can use the ``walk_lock`` for thread safety.

Using a DiscoveryStrategy
-------------------------

You can register your ``DiscoveryStrategy`` with a running ``IPv8`` instance as follows:

.. literalinclude:: discoverystrategy_tutorial_1.py
   :lines: 23-28

Note that we specify a ``target_peers`` argument.
This argument specifies the amount of peers after which the ``DiscoveryStrategy`` should no longer be called.
Calls will be resumed when the amount of peers in your ``Community`` dips below this value again.
For example, the built-in ``RandomWalk`` strategy can be configured to stop finding new peers after if an overlay already has ``20`` or more peers.
In this example we have used the magic value ``-1``, which causes ``IPv8`` to never stop calling this strategy.

You can also load your strategy through the ``configuration`` or ``loader``.
First, an example of how to do this with the ``configuration``:

.. literalinclude:: discoverystrategy_tutorial_2.py
   :lines: 16-37

Note that you can add as many strategies as you want to an overlay.
Also note that for IPv8 to link the name ``"MyDiscoveryStrategy"`` to a class, you need to define it in your ``Community``'s ``get_available_strategies()`` dictionary.

Lastly, alternatively, the way to add your custom ``MyDiscoveryStrategy`` class to a ``CommunityLauncher`` is as follows:

 .. code-block:: python

    @overlay('my_module.some_submodule', 'MyCommunity')
    @walk_strategy(MyDiscoveryStrategy)
    class MyLauncher(CommunityLauncher):
        pass

This is the shortest way.
