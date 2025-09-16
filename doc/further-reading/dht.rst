DHT(Discovery)Community
=======================

This document contains a description of how to use the ``DHTCommunity`` class for distributed hash table (DHT) data storage and the ``DHTDiscoveryCommunity`` extension of this functionality, which provides functionality to connect given public keys.

In particular this document will **not** discuss how distributed hash table work, for this we refer the reader to other resources on the Internet.


Storing values and finding keys
-------------------------------

The ``DHTCommunity`` is the main overlay that allows for decentralized key-value storage.
There are two main functions in this overlay: the ``store_value()`` function and the ``find_values()`` function.

When you call ``store_value()``, you choose the globally unique ``key`` that your given value ``data`` is stored under.
You can, but are not required to, sign this new stored value with your public key to provide it with authenticity.
Note that this function may lead to a ``ipv8.dht.DHTError``: in this case, you will have to try again later.
An example of a call that stores the signed value ``b"my value"`` under the key ``b"my key"``, is the following.

.. literalinclude:: dht_1.py
   :lines: 43-47

The value can later be retrieved from the network by calling ``find_values()`` with the key that the information was stored under.
The following snippet retrieves the value that was stored in the previous snippet, under the ``b"my key"`` key.

.. literalinclude:: dht_1.py
   :lines: 49-55

Note that multiple peers may respond with answers and if (a) the original value is not signed or (b) multiple values are published under the same key, the reported values may be different.
In this example, only one value is published and it is signed so only a single value is ever returned.

Finding peers
-------------

The ``DHTDiscoveryCommunity`` allows for peers to be found by their public key.
You can search for public keys by their SHA-1 hash (conveniently available as ``Peer.mid``).
To do so, you can call ``connect_peer()`` with the hash/mid as shown in the following example.


.. literalinclude:: dht_1.py
   :lines: 58-65

Note that you may need a few attempts to find the peer you are looking for.
Of course, if the peer you are looking for is not online, you may be waiting forever.
