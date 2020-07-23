
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

.. code-block:: python

   from asyncio import ensure_future, get_event_loop

   from pyipv8.ipv8_service import IPv8
   from pyipv8.ipv8.configuration import get_default_configuration


   async def start_ipv8():
       # Create an IPv8 object with the default settings.
       ipv8 = IPv8(get_default_configuration())
       await ipv8.start()

   # Create a task that runs an IPv8 instance.
   # The task will run as soon as the event loop has started.
   ensure_future(start_ipv8())

   # Start the asyncio event loop: this is the engine scheduling all of the
   # asynchronous calls.
   get_event_loop().run_forever()

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

.. code-block:: python

   from asyncio import ensure_future, get_event_loop

   from pyipv8.ipv8_service import IPv8
   from pyipv8.ipv8.configuration import get_default_configuration


   async def start_ipv8():
       # The first IPv8 will attempt to claim a port.
       await IPv8(get_default_configuration()).start()
       # The second IPv8 will attempt to claim a port.
       # It cannot claim the same port and will end up claiming a different one.
       await IPv8(get_default_configuration()).start()

   ensure_future(start_ipv8())
   get_event_loop().run_forever()

If you were successful, you should now see double the debug information being printed to your terminal.

Loading a custom overlay
------------------------

Now that we can launch two instances, let's create the actual network overlay.
To do this, fill your ``main.py`` file with the following code:

.. code-block:: python

    from asyncio import ensure_future, get_event_loop

    from pyipv8.ipv8.community import Community
    from pyipv8.ipv8_service import IPv8
    from pyipv8.ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition
    from pyipv8.ipv8.keyvault.crypto import ECCrypto
    from pyipv8.ipv8.peer import Peer


    class MyCommunity(Community):
       # Register this community with a master peer.
       # This peer defines the service identifier of this community.
       # Other peers will connect to this community based on the sha-1
       # hash of this peer's public key.
       master_peer = Peer(ECCrypto().generate_key(u"medium"))


    async def start_communities():
       for i in [1, 2]:
           builder = ConfigBuilder().clear_keys().clear_overlays()
           # If we actually want to communicate between two different peers
           # we need to assign them different keys.
           # We will generate an EC key called 'my peer' which has 'medium'
           # security and will be stored in file 'ecI.pem' where 'I' is replaced
           # by the peer number (1 or 2).
           builder.add_key("my peer", "medium", f"ec{i}.pem")
           # Instruct IPv8 to load our custom overlay, registered in _COMMUNITIES.
           # We use the 'my peer' key, which we registered before.
           # We will attempt to find other peers in this overlay using the
           # RandomWalk strategy, until we find 10 peers.
           # We do not provide additional startup arguments or a function to run
           # once the overlay has been initialized.
           builder.add_overlay("MyCommunity", "my peer", [WalkerDefinition(Strategy.RandomWalk, 10, {'timeout': 3.0})], {}, [])
           ipv8 = IPv8(builder.finalize(), extra_communities={'MyCommunity': MyCommunity})
           await ipv8.start()

    ensure_future(start_communities())
    get_event_loop().run_forever()


As we replaced the default overlays, you should no longer see any debug information being printed to your terminal.
Our overlay is now loaded twice, but it is still not doing anything.

Printing the known peers
------------------------

Like every DHT-based network overlay framework, IPv8 needs some time to find peers.
We will now modify ``main.py`` again to print the current amount of peers:

.. code-block:: python

    from asyncio import ensure_future, get_event_loop

    from pyipv8.ipv8.community import Community
    from pyipv8.ipv8_service import IPv8
    from pyipv8.ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition
    from pyipv8.ipv8.keyvault.crypto import ECCrypto
    from pyipv8.ipv8.peer import Peer


    class MyCommunity(Community):
       master_peer = Peer(ECCrypto().generate_key(u"medium"))

       def started(self):
           async def print_peers():
               print("I am:", self.my_peer, "\nI know:", [str(p) for p in self.get_peers()])
           # We register a asyncio task with this overlay.
           # This makes sure that the task ends when this overlay is unloaded.
           # We call the 'print_peers' function every 5.0 seconds, starting now.
           self.register_task("print_peers", print_peers, interval=5.0, delay=0)


    async def start_communities():
       for i in [1, 2]:
           builder = ConfigBuilder().clear_keys().clear_overlays()
           builder.add_key("my peer", "medium", f"ec{i}.pem")
           # We provide the 'started' function to the 'on_start'.
           # We will call the overlay's 'started' function without any
           # arguments once IPv8 is initialized.
           builder.add_overlay("MyCommunity", "my peer", [WalkerDefinition(Strategy.RandomWalk, 10, {'timeout': 3.0})], {}, [('started', )])
           await IPv8(builder.finalize(), extra_communities={'MyCommunity': MyCommunity}).start()

    ensure_future(start_communities())
    get_event_loop().run_forever()

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

.. code-block:: python

    from asyncio import ensure_future, get_event_loop

    from pyipv8.ipv8.community import Community
    from pyipv8.ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition
    from pyipv8.ipv8.keyvault.crypto import ECCrypto
    from pyipv8.ipv8.lazy_community import lazy_wrapper
    from pyipv8.ipv8.messaging.lazy_payload import VariablePayload, vp_compile
    from pyipv8.ipv8.peer import Peer
    from pyipv8.ipv8_service import IPv8


    @vp_compile
    class MyMessage(VariablePayload):
        msg_id = 1  # The byte identifying this message, must be unique per community.
        format_list = ['I']  # When reading data, we unpack an unsigned integer from it.
        names = ["clock"]  # We will name this unsigned integer "clock"


    class MyCommunity(Community):
        master_peer = Peer(ECCrypto().generate_key(u"medium"))

        def __init__(self, my_peer, endpoint, network):
            super(MyCommunity, self).__init__(my_peer, endpoint, network)
            # Register the message handler for messages with the identifier "1".
            self.add_message_handler(1, self.on_message)
            # The Lamport clock this peer maintains.
            # This is for the example of global clock synchronization.
            self.lamport_clock = 0

        def started(self):
            async def start_communication():
                if not self.lamport_clock:
                    # If we have not started counting, try boostrapping
                    # communication with our other known peers.
                    for p in self.get_peers():
                        self.ez_send(p, MyMessage(self.lamport_clock))
                else:
                    self.cancel_pending_task("start_communication")
            self.register_task("start_communication", start_communication, interval=5.0, delay=0)

        @lazy_wrapper(MyMessage)
        def on_message(self, peer, payload):
            # Update our Lamport clock.
            self.lamport_clock = max(self.lamport_clock, payload.clock) + 1
            print(self.my_peer, "current clock:", self.lamport_clock)
            # Then synchronize with the rest of the network again.
            self.ez_send(peer, MyMessage(self.lamport_clock))


    async def start_communities():
        for i in [1, 2, 3]:
            builder = ConfigBuilder().clear_keys().clear_overlays()
            builder.add_key("my peer", "medium", f"ec{i}.pem")
            builder.add_overlay("MyCommunity", "my peer", [WalkerDefinition(Strategy.RandomWalk, 10, {'timeout': 3.0})], {}, [('started', )])
            await IPv8(builder.finalize(), extra_communities={'MyCommunity': MyCommunity}).start()

    ensure_future(start_communities())
    get_event_loop().run_forever()


If you run this, you should see the three peers actively trying to establish an ever-increasing global clock value.
