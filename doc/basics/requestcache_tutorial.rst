Storing states in IPv8
======================

This document assumes you have a basic understanding of network overlays in IPv8, as documented in `the overlay tutorial <../basics/overlay_tutorial.html>`_.
You will learn how to use the IPv8's ``RequestCache`` class to store the state of message flows.

When you need a state
---------------------

More often than not messages come in *flows*.
For example, one peer sends out a *request* and another peer provides a *response*.
Or, as another example, your message is too big to fit into a single UDP packet and you need to keep track of multiple smaller messages that belong together.
In these cases you need to keep a state.
The ``RequestCache`` class keeps track of states and also natively includes a timeout mechanism to make sure you don't get a memory leak.

Typically, you will use one ``RequestCache`` per network overlay, to which you add the caches that store states.

The hard way
------------

The most straightforward way of interacting with the ``RequestCache`` is by adding ``NumberCache`` instances to it directly.
Normally, you will use ``add()`` and ``pop()`` to respectively add new caches and remove existing caches from the ``RequestCache``.
This is a bare-bones example of how states can be stored and retrieved:

.. literalinclude:: requestcache_tutorial_1.py

In the previous example we have assumed that a cache would eventually arrive.
This will almost never be the case in practice.
You can overwrite the ``on_timeout`` method of your ``NumberCache`` instances to deal with cleaning up when a cache times out.
In this following example we shut down when the cache times out:

.. literalinclude:: requestcache_tutorial_2.py

You may notice some inconvenient properties of these caches.
You need to generate a unique identifier and manually keep track of it.
This is why we have an easier way to interact with the ``RequestCache``.

The easier way
--------------

Let's look at the complete Community code for two peers that use each other to count to 10.
For this toy box example we define two messages and a single cache.
Unlike when doing things the hard way, we now use a ``RandomNumberCache`` to have IPv8 select a message identifier for us.
Both the ``identifier`` fields for the messages and the ``name`` for the cache are required.
Please attentively read through this code:

.. literalinclude:: requestcache_tutorial_3.py
   :lines: 12-91

You are encouraged to play around with this code.
Also, take notice of the fact that this example includes a replay attack (try removing the cache and see what happens).
