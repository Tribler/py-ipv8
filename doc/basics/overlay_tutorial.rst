
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

.. code-block:: none

   (folder) pyipv8
   (file) __init__.py
   (file) main.py

Running the IPv8 service
------------------------

Fill your ``main.py`` file with the following code:

.. code-block:: python

   from twisted.internet import reactor

   from pyipv8.ipv8_service import IPv8
   from pyipv8.ipv8.configuration import get_default_configuration


   # Create an IPv8 object with the default settings.
   # It will come to life once the Twisted reactor starts running.
   IPv8(get_default_configuration())
   # Start the Twisted reactor: this is the engine scheduling all of the
   # asynchronous calls.
   reactor.run()

You can now run this file using Python as follows:

.. code-block:: bash

   python main.py

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

   from twisted.internet import reactor

   from pyipv8.ipv8_service import IPv8
   from pyipv8.ipv8.configuration import get_default_configuration


   # The first IPv8 will attempt to claim a port.
   IPv8(get_default_configuration())
   # The second IPv8 will attempt to claim a port.
   # It cannot claim the same port and will end up claiming a different one.
   IPv8(get_default_configuration())
   reactor.run()

If you were successful, you should now see double the debug information being printed to your terminal.

Loading a custom overlay
------------------------

Now that we can launch two instances, let's create the actual network overlay.
To do this, fill your ``main.py`` file with the following code:

.. code-block:: python

   from twisted.internet import reactor

   from pyipv8.ipv8.community import Community
   from pyipv8.ipv8_service import IPv8
   from pyipv8.ipv8.configuration import get_default_configuration
   from pyipv8.ipv8.keyvault.crypto import ECCrypto
   from pyipv8.ipv8.peer import Peer


   class MyCommunity(Community):
       # Register this community with a master peer.
       # This peer defines the service identifier of this community.
       # Other peers will connect to this community based on the sha-1
       # hash of this peer's public key.
       master_peer = Peer(ECCrypto().generate_key(u"medium"))


   for i in [1, 2]:
       configuration = get_default_configuration()
       # If we actually want to communicate between two different peers
       # we need to assign them different keys.
       # We will generate an EC key called 'my peer' which has 'medium'
       # security and will be stored in file 'ecI.pem' where 'I' is replaced
       # by the peer number (1 or 2).
       configuration['keys'] = [{
                   'alias': "my peer",
                   'generation': u"medium",
                   'file': u"ec%d.pem" % i
               }]
       # Instruct IPv8 to load our custom overlay, registered in _COMMUNITIES.
       # We use the 'my peer' key, which we registered before.
       # We will attempt to find other peers in this overlay using the
       # RandomWalk strategy, until we find 10 peers.
       # We do not provide additional startup arguments or a function to run
       # once the overlay has been initialized.
       configuration['overlays'] = [{
           'class': 'MyCommunity',
           'key': "my peer",
           'walkers': [{
                           'strategy': "RandomWalk",
                           'peers': 10,
                           'init': {
                               'timeout': 3.0
                           }
                       }],
           'initialize': {},
           'on_start': []
       }]
       IPv8(configuration, extra_communities={'MyCommunity': MyCommunity})

   reactor.run()

As we replaced the default overlays, you should no longer see any debug information being printed to your terminal.
Our overlay is now loaded twice, but it is still not doing anything.

Printing the known peers
------------------------

Like every DHT-based network overlay framework, IPv8 needs some time to find peers.
We will now modify ``main.py`` again to print the current amount of peers:

.. code-block:: python

   from twisted.internet import reactor
   from twisted.internet.task import LoopingCall

   from pyipv8.ipv8.community import Community
   from pyipv8.ipv8_service import IPv8
   from pyipv8.ipv8.configuration import get_default_configuration
   from pyipv8.ipv8.keyvault.crypto import ECCrypto
   from pyipv8.ipv8.peer import Peer


   class MyCommunity(Community):
       master_peer = Peer(ECCrypto().generate_key(u"medium"))

       def started(self):
           def print_peers():
               print "I am:", self.my_peer, "\nI know:", [str(p) for p in self.get_peers()]
           # We register a Twisted task with this overlay.
           # This makes sure that the task ends when this overlay is unloaded.
           # We call the 'print_peers' function every 5.0 seconds, starting now.
           self.register_task("print_peers", LoopingCall(print_peers)).start(5.0, True)


   for i in [1, 2]:
       configuration = get_default_configuration()
       configuration['keys'] = [{
                   'alias': "my peer",
                   'generation': u"medium",
                   'file': u"ec%d.pem" % i
               }]
       # We provide the 'started' function to the 'on_start'.
       # We will call the overlay's 'started' function without any
       # arguments once IPv8 is initialized.
       configuration['overlays'] = [{
           'class': 'MyCommunity',
           'key': "my peer",
           'walkers': [{
                           'strategy': "RandomWalk",
                           'peers': 10,
                           'init': {
                               'timeout': 3.0
                           }
                       }],
           'initialize': {},
           'on_start': [('started', )]
       }]
       IPv8(configuration, extra_communities={'MyCommunity': MyCommunity})

   reactor.run()

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

   from twisted.internet import reactor
   from twisted.internet.task import LoopingCall

   from pyipv8.ipv8.community import Community
   from pyipv8.ipv8.configuration import get_default_configuration
   from pyipv8.ipv8.keyvault.crypto import ECCrypto
   from pyipv8.ipv8.lazy_community import lazy_wrapper
   from pyipv8.ipv8.messaging.lazy_payload import VariablePayload
   from pyipv8.ipv8.peer import Peer
   from pyipv8.ipv8_service import IPv8


   class MyMessage(VariablePayload):
       format_list = ['I'] # When reading data, we unpack an unsigned integer from it.
       names = ["clock"] # We will name this unsigned integer "clock"


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
           def start_communication():
               if not self.lamport_clock:
                   # If we have not started counting, try boostrapping
                   # communication with our other known peers.
                   for p in self.get_peers():
                       self.send_message(p.address)
               else:
                   self.cancel_pending_task("start_communication")
           self.register_task("start_communication", LoopingCall(start_communication)).start(5.0, True)

       def send_message(self, address):
           # Send a message with our digital signature on it.
           # We use the latest version of our Lamport clock.
           self.endpoint.send(address, self.ezr_pack(1, MyMessage(self.lamport_clock)))

       @lazy_wrapper(MyMessage)
       def on_message(self, peer, payload):
           # Update our Lamport clock.
           self.lamport_clock = max(self.lamport_clock, payload.clock) + 1
           print self.my_peer, "current clock:", self.lamport_clock
           # Then synchronize with the rest of the network again.
           self.send_message(peer.address)


   for i in [1, 2, 3]:
       configuration = get_default_configuration()
       configuration['keys'] = [{
                   'alias': "my peer",
                   'generation': u"medium",
                   'file': u"ec%d.pem" % i
               }]
       configuration['overlays'] = [{
           'class': 'MyCommunity',
           'key': "my peer",
           'walkers': [{
                           'strategy': "RandomWalk",
                           'peers': 10,
                           'init': {
                               'timeout': 3.0
                           }
                       }],
           'initialize': {},
           'on_start': [('started', )]
       }]
       IPv8(configuration, extra_communities={'MyCommunity': MyCommunity})

   reactor.run()

If you run this, you should see the three peers actively trying to establish an ever-increasing global clock value.
