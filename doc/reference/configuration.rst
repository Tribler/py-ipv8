IPv8 configuration options
==========================

The ``ipv8/configuration.py`` contains the main IPv8 configuration options.
IPv8 will read a dictionary that conforms to the configuration format to determine what services to start and which keys to use.
By invoking ``get_default_configuration()``, you can get a dictionary copy of the default settings for your custom IPv8 configuration.

.. |snip1| raw:: html

  "0.0.0.0"


.. |nl| raw:: html

  <br />


.. |snip2| raw:: html

  <small>[{<br />
  &emsp;<nobr>'alias':<nobr>"anonymous<nobr>id",<br />
  &emsp;<nobr>'generation':<nobr>u"curve25519",<br />
  &emsp;<nobr>'file':<nobr>u"ec_multichain.pem"<br />
  }]</small>


.. |snip3| raw:: html

  <small>{<br />
  &emsp;<nobr>'level':<nobr>"INFO",<br />
  }</small>


.. csv-table:: Configuration keys
   :header: "key", "default", "description"
   :widths: 20, 40, 80

   "address", |snip1|, "The IPv4-address to bind to."
   "port", 8090, "The (UDP) port to try and open. If blocked, IPv8 will attempt the next free port (up to 10,000 ports over the specified port)."
   "keys", |snip2|, "Specify a list of keys, by alias, for IPv8 to use. The curve should be picked from those available in the ECCrypto class. IPv8 will generate a new key if the key file does not exist."
   "logger", |snip3|, "The logger intialization arguments, also see the default Python logger facilities."
   "walker_interval", 0.5, "The time interval between IPv8 updates. Each update will trigger all registered strategies to update, mostly this concerns peer discovery."
   "overlays", [ .\.\. ], "The list of overlay definitions and their respective walking strategies. See the overlay definition section for further details."


Each of the overlay specifications is a dictionary following the following standard:

.. csv-table:: Network overlay definitions
   :header: "key", "description"
   :widths: 20, 80

   "class", "The overlay class to load. Do note that any external overlay definitions will have to be registered in IPv8, see also the overlay creation tutorial."
   "key", "The alias of the key to use for the particular overlay."
   "walkers", "The walker to employ."
   "initialize", "The additional arguments to pass to the constructor of the overlay."
   "on_start", "A list of tuples containing method names and their arguments. These methods are invoked when IPv8 has started."


By default, the ``RandomWalk`` and ``EdgeWalk`` strategies are known to IPv8.
Respectively these will take care of performing random walks and random walks with reset probability for peer discovery.
Each overlay may also specify further custom strategies.
By default, IPv8 loads the following overlays:

- AttestationCommunity
- DiscoveryCommunity
- HiddenTunnelCommunity
- IdentityCommunity
- TrustChainCommunity
- TunnelCommunity
- DHTDiscoveryCommunity
- TrustChainTestnetCommunity
   
