
Creating your first overlay
===========================

This document assumes you have installed all of the dependencies as instructed in the `README.md <https://github.com/Tribler/py-ipv8/blob/master/README.md>`_.
You will learn how to construct a *network overlay* using IPv8.

Running the IPv8 service
------------------------

Fill your ``main.py`` file with the following code:

.. literalinclude:: overlay_tutorial_1.py

You can now run this file using Python as follows:

.. code-block:: bash

   python3 main.py

You should see some debug information being printed to your terminal.
If this step failed, you are probably missing dependencies.

If everything is running correctly: congratulations!
You have just run the IPv8 service for the first time.

Running two IPv8 services
-------------------------

Now that we have managed to create an IPv8-service instance, we want to create a second instance.
This way we can start testing the network overlay with multiple instances.
To try this, fill your ``main.py`` file with the following code:

.. literalinclude:: overlay_tutorial_2.py

If you were successful, you should now see double the debug information being printed to your terminal.

Loading a custom overlay
------------------------

Now that we can launch two instances, let's create the actual network overlay.
To do this, fill your ``main.py`` file with the following code:

.. literalinclude:: overlay_tutorial_3.py

As we replaced the default overlays, you should no longer see any debug information being printed to your terminal.
Our overlay is now loaded twice, but it is still not doing anything.

Printing the known peers
------------------------

Like every DHT-based network overlay framework, IPv8 needs some time to find peers.
We will now modify ``main.py`` again to print the current number of peers:

.. literalinclude:: overlay_tutorial_4.py

Running this should yield something like the following output:

.. code-block:: bash

   $ python main.py 
   I am: Peer<0.0.0.0:0:8090, dxGFpQ4awTMz826HOVCB5OoiPPI=> I found: Peer<0.0.0.0:0:8091, YfHrKJR4O72/k/FBYYxMIQwOb1U=>
   I am: Peer<0.0.0.0:0:8091, YfHrKJR4O72/k/FBYYxMIQwOb1U=> I found: Peer<0.0.0.0:0:8090, dxGFpQ4awTMz826HOVCB5OoiPPI=>

.. warning::
   You should never use the ``address`` of a ``Peer`` as its identifier.
   A ``Peer``'s ``address`` can change over time!
   Instead, use the ``mid`` of a Peer (which is the ``SHA-1`` hash of its public key) or its ``public_key.key_to_bin()`` (the serialized form of the public key).
   The public key of a ``Peer`` never changes.

Adding messages
---------------

As an example for adding messages, we will now make a Lamport clock for three peers.
Update your ``main.py`` once again to contain the following code:

.. literalinclude:: overlay_tutorial_5.py

If you run this, you should see the three peers actively trying to establish an ever-increasing global clock value.
