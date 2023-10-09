Unit Testing Overlays
=====================

This document assumes you have a basic understanding of network overlays in IPv8, as documented in `the overlay tutorial <../basics/overlay_tutorial.html>`_.
You will learn how to use the IPv8's ``TestBase`` class to unit test your overlays.

Files
-----

This tutorial will place all of its files in the ``~/Documents/ipv8_tutorial`` directory.
You are free to choose whatever directory you want, to place your files in.
This tutorial uses the following files in the working directory:

.. code-block:: console

   community.py
   test_community.py

We will use the following ``community.py`` in this tutorial:

.. literalinclude:: testbase_tutorial_1.py
   :lines: 3-57

You're encouraged to fill ``test_community.py`` yourself as you read through this tutorial.

Why and How?
------------

After playing around with your first overlay, you may have discovered that running multiple processes
and configuring your communities to test functionality is not very easy or reproducible.
We certainly have.
Therefore, we have created the ``TestBase`` class with all the tools you need to mock the Internet and
make beautiful unit tests.

Because ``TestBase`` is a subclass of ``unittest.TestCase`` you can use common unit testing convenience methods, like ``testEqual``, ``testTrue``, ``setUp``, ``setUpClass``, etc.
This also means that ``TestBase`` can be used with just about any test runner out there
(like ``unittest``, ``nosetests`` or ``pytest``).

The way we will run our unit tests in this tutorial is with:

.. code-block:: console

    python3 -m unittest test_community.py

If you have custom logic in your subclass, please make sure to call your ``super()`` methods.
Here's an example of custom ``setUp`` and ``tearDown`` methods:

.. literalinclude:: testbase_tutorial_1.py
   :lines: 60-68

Deadlock Detection
------------------

Before you start testing, you need to be warned about ``TestBase.MAX_TEST_TIME``.
By default, ``TestBase.MAX_TEST_TIME`` is set to 10 seconds.
This means that if your testing class takes more than 10 seconds, ``TestBase`` will terminate it.

We should probably mention that in proper software engineering a unit test case should never take 10 seconds.
However, we're not here to judge.
If you want this timeout increased, simply overwrite the value of ``MAX_TEST_TIME`` in your subclass.
For example:

.. code-block:: python

    class MyTests(TestBase):

        MAX_TEST_TIME = 30.0  # Now this class can take 30 seconds

Creating Instances
------------------

The ``initialize()`` method takes care of initializing your ``Community`` subclass for you.
It's as easy as this:

.. literalinclude:: testbase_tutorial_1.py
   :lines: 79-89

What happened here?
First, we instructed ``TestBase`` to create 1 instance of ``MyCommunity`` using ``initialize()``.
As a side note: the raw information needed to make this happen (the mocking of the Internet and the interconnection
of overlays) is actually stored in the ``nodes`` list of ``TestBase``.
Second, we ask our ``TestBase`` to give us the overlay instance of node 0, which is our only node.
The ``overlay()`` method is one of the many convenience methods in ``TestBase`` to access common data in overlays.
We'll provide a complete list of these convenience methods later in this document.
Last, we use a common ``unittest.TestCase`` assertion to check if our ``some_constant()`` overlay method returned 42.

In some cases, you might need to give additional parameters to your ``Community``'s ``__init__()`` method.
In these cases, you can simply add additional keyword arguments to ``initialize()``.

.. literalinclude:: testbase_tutorial_1.py
   :lines: 91-99

In yet more advanced use cases, you may want to provide your own ``MockIPv8`` instances.
This will usually be the case if your ``Community`` instance only supports specific keys.
Commonly, ``Community`` instances may choose to **only** support ``curve25519`` keys, which you can do as follows:

.. literalinclude:: testbase_tutorial_1.py
   :lines: 70-71

Communication
-------------

You should now be able to create ``Community`` instances and call their methods.
However, these instances are not communicating with each other yet.
Take note of this code in our ``Community`` instance that stores the last peer that sent us an introduction request:

.. literalinclude:: testbase_tutorial_1.py
   :lines: 51-54

This code simply stores whatever ``Peer`` object last sent us a request.
We'll create a unit test to test whether this happened:

.. literalinclude:: testbase_tutorial_1.py
   :lines: 101-114

Let's run through this example.
First we create two instances of ``MyCommunity`` using ``initialize()``.
Second, we instruct the first node in our test to send a message to our second node.
Here ``send_introduction_request()`` creates and sends a message to another peer and ``deliver_messages()``
allows it to be received.
Lastly, we assert that our second node received a message from our first node.

Note that the ``asyncio`` programming model of Python executes its events on the main thread (the event loop),
including this test case and the communication that is caused by it.
In other words, since the test itself is occupying the main thread, the messaging will only happen
after our test is finished!
By the time it is allowed to execute, the communication is already cancelled.
The ``deliver_messages()`` method backs off for a given amount of time and then waits for the main thread to be freed.

**Now comes the caveat.**
The main thread being freed may not mean your ``Community`` is actually done doing stuff.
**It is possible to schedule asyncio events in such a way that deliver_messages() can't detect them.**
This commonly happens when you use threading or hardware (like sockets).
In these exceptional cases, you can use ``asyncio.sleep()`` or, better yet, await a custom ``Future`` in the test.

Piggybacking on Introductions
-----------------------------

Some ``Community`` instances prefer to piggyback information onto introductions.
As ``TestBase`` simply adds peers to each other directly, this piggybacked information is not sent.
The ``introduce_nodes()`` method allows you to send these introductions anyway, used as follows
(note the absence of ``deliver_messages()``):

.. literalinclude:: testbase_tutorial_1.py
   :lines: 116-125

Using the RequestCache
----------------------

In real ``Community`` instances, you will have many timeouts and lots of timeout logic in caches.
To make it easier to trigger these timeouts in the ``RequestCache``, we use the ``passthrough()`` method.
Here's an example:

.. literalinclude:: testbase_tutorial_1.py
   :lines: 127-137

In this example we use the ``passthrough()`` contextmanager while we invoke a function that adds a cache.
This causes the timeout of the ``MyCache`` cache we add inside ``add_cache`` to be nullified and instantly fire.
Do note that this timeout occurs in the ``asyncio`` event loop and we need to allow it to fire.
To yield the main thread we use ``deliver_messages()`` again (though in this case ``await asyncio.sleep(0.0)`` would have also
done the trick).

In some complex cases you may have more than one type of cache being added.
In these cases you can add a filter to ``passthrough()`` to make it only nullify some particular classes
(simply add these classes as arguments to ``passthrough()``):

.. literalinclude:: testbase_tutorial_1.py
   :lines: 139-149

Fragile Packet Handling
-----------------------

By default ``IPv8`` adds a general exception handler in ``Community`` instances,
to disallow external messages crashing you.
However, when testing, this exception handler is removed by ``TestBase``.
If you want to enable the general exception handler again, you can either add your class to the
``production_overlay_classes`` list or overwrite ``TestBase.patch_overlays()``.
For example:

.. literalinclude:: testbase_tutorial_1.py
   :lines: 73-77

Temporary Files
---------------

In some cases, you may require temporary files in your unit tests.
``TestBase`` exposes the ``temporary_directory()`` method to generate directories for these files.
This method is ``random.seed()`` compatible.
Normally, ``TestBase`` will clean up these files automatically for you.
However, if you hard-crash ``TestBase`` before its ``tearDown`` is invoked,
the temporary directories will not be cleaned up.

The temporary directory names are prefixed with ``_temp_`` and use a ``uuid`` as a unique name.
The temporary directories will be created in the current working directory
for the mechanism to work on all supported platforms (Windows, Mac and Linux) even with limited permissions.

Asserting Message Delivery
--------------------------

You may want to assert that an overlay receives certain messages after a function.
The ``TestBase`` exposes the ``assertReceivedBy()`` function to do just that.
We'll run through its functionality by example.

Most of the time, you will want to check if a peer received certain messages.
In the following example peer 0 first sends message 1 and then sends message 2 to peer 1.
The following construction asserts this:

.. literalinclude:: testbase_tutorial_2.py
   :lines: 65-68
   :dedent: 4

Sometimes, you can't be sure in what order messages are sent.
In these cases you can use ``ordered=False``:

.. literalinclude:: testbase_tutorial_2.py
   :lines: 71-77
   :dedent: 4

In other cases, your overlay may be sending messages which you cannot control and/or which you don't care about.
In these cases you can set a filter to only include the messages you want:

.. literalinclude:: testbase_tutorial_2.py
   :lines: 80-85
   :dedent: 4

It may also be helpful to inspect the contents of each payload.
You can simply use the return value of the assert function to perform further inspection:

.. literalinclude:: testbase_tutorial_2.py
   :lines: 88-95
   :dedent: 4

If you want to use ``assertReceivedBy()``, make sure that:

 1. Your overlay message handlers only handle a single payload.
 2. Your messages specify a ``msg_id``.
 3. Your messages are compatible with ``ez_send()`` and ``lazy_wrapper_*()``.

Shortcut Reference
------------------

As usual, there is an easy and a hard way to do everything in IPv8.
You are welcome to call ``self.nodes[i].my_peer.public_key.key_to_bin()`` manually
every time you wish to access the public key of node ``i``.
Or, instead, you may use the available shortcut ``self.key_bin(i)``.
You may find your unit test become a lot more readable if you use the available ``TestBase`` shortcuts though.

.. csv-table:: Available ``TestBase`` shortcuts
   :header: "method", "description"
   :widths: 20, 45

   "address(i)", "The IPv4 address of peer i."
   "endpoint(i)", "The Endpoint instance of peer i."
   "key_bin(i)", "The serialized public key (bytes) of peer i."
   "key_bin_private(i)", "The serialized private key (bytes) of peer i."
   "mid(i)", "The SHA-1 of the public key of peer i."
   "my_peer(i)", "The private my_peer Peer instance of peer i."
   "network(i)", "The Network instance of peer i."
   "node(i)", "The MockIPv8 instance of peer i."
   "overlay(i)", "The Community instance of peer i."
   "peer(i)", "The public Peer instance of peer i."
   "private_key(i)", "The private key instance of peer i."
   "public_key(i)", "The public key instance of peer i."

You are encouraged to add shortcuts that may be relevant to your own ``Community`` instance in your own test class.
