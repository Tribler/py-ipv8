
Creating your first overlay
===========================

This document assumes you have installed all of the dependencies as instructed in the `README.md <https://github.com/Tribler/py-ipv8/blob/master/README.md>`_.
You will learn how to construct a *network overlay* using IPv8.

Files
-----

First we will setup a working directory to run our overlay in.
This tutorial will place all of its files in the ``~/Documents/ipv8_tutorial`` directory.
You are free to choose whatever directory you want, to place your files in.


#. 
   In the working directory, we will now clone IPv8 through ``git``\ :

   .. code-block:: bash

      git clone https://github.com/Tribler/py-ipv8.git pyipv8

   You should see a folder called ``pyipv8`` appear in the working directory.

#. 
   Then, we need an empty ``__init__.py`` file and a ``main.py`` file, which we will fill with our tutorial code.

At the end of this setup step you should have the following files in your working directory:

.. code-block::

   (folder) pyipv8
   (file) __init__.py
   (file) main.py

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
We will now modify ``main.py`` again to print the current amount of peers:

.. literalinclude:: overlay_tutorial_4.py

Running this should yield something like the following output:

.. code-block:: bash

   $ python main.py 
   I am: Peer<0.0.0.0:0, /zWXEA/4wFeGEKTZ8fckwUwLk3Y=> 
   I know: []
   I am: Peer<0.0.0.0:0, VVsH+LxamOUVUkV/5rjemqYMO8w=> 
   I know: []
   I am: Peer<0.0.0.0:0, /zWXEA/4wFeGEKTZ8fckwUwLk3Y=> 
   I know: ['Peer<10.0.2.15:8091, VVsH+LxamOUVUkV/5rjemqYMO8w=>']
   I am: Peer<0.0.0.0:0, VVsH+LxamOUVUkV/5rjemqYMO8w=> 
   I know: ['Peer<10.0.2.15:8090, /zWXEA/4wFeGEKTZ8fckwUwLk3Y=>']

Adding messages
---------------

As an example for adding messages, we will now make a Lamport clock for three peers.
Update your ``main.py`` once again to contain the following code:

.. literalinclude:: overlay_tutorial_5.py

If you run this, you should see the three peers actively trying to establish an ever-increasing global clock value.
