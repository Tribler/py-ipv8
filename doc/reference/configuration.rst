IPv8 configuration options
==========================

The ``ipv8/configuration.py`` contains the main IPv8 configuration options.
IPv8 will read a dictionary that conforms to the configuration format to determine what services to start and which keys to use.
By invoking ``get_default_configuration()``, you can get a dictionary copy of the default settings for your custom IPv8 configuration.

.. |snip1| raw:: html

  <small>[{<br />
  &emsp;<nobr>'interface':<nobr>"UDPIPv4",<br />
  &emsp;<nobr>'ip':<nobr>"0.0.0.0",<br />
  &emsp;<nobr>'port':<nobr>8090<br />
  }]</small>


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

   "interfaces", |snip1|, "The interfaces to bind to (``UDPIPv4`` or ``UDPIPv6``) using an IP address and port. If the specified port is blocked, IPv8 will attempt the next free port (up to 10,000 ports over the specified port)."
   "keys", |snip2|, "Specify a list of keys, by alias, for IPv8 to use. The curve should be picked from those available in the ECCrypto class. IPv8 will generate a new key if the key file does not exist."
   "logger", |snip3|, "The logger intialization arguments, also see the default Python logger facilities."
   "walker_interval", 0.5, "The time interval between IPv8 updates. Each update will trigger all registered strategies to update, mostly this concerns peer discovery."
   "overlays", [ .\.\. ], "The list of overlay definitions and their respective walking strategies. See the overlay definition section for further details."

Overlay Specifications
----------------------

Each of the overlay specifications is a dictionary following the following standard:

.. csv-table:: Network overlay definitions
   :header: "key", "description"
   :widths: 20, 80

   "class", "The overlay class to load. Do note that any external overlay definitions will have to be registered in IPv8, see also the overlay creation tutorial."
   "key", "The alias of the key to use for the particular overlay."
   "walkers", "The walker to employ."
   "bootstrappers", "The bootstrappers to use."
   "initialize", "The additional arguments to pass to the constructor of the overlay."
   "on_start", "A list of tuples containing method names and their arguments. These methods are invoked when IPv8 has started."


By default, the ``RandomWalk`` and ``EdgeWalk`` strategies are known to IPv8.
Respectively these will take care of performing random walks and random walks with reset probability for peer discovery.
Each overlay may also specify further custom strategies.
Check out the `the bootstrapping documentation <../reference/bootstrapping.html>`_ for more information on configuring bootstrappers per overlay.

By default, IPv8 loads the following overlays:

- DiscoveryCommunity
- HiddenTunnelCommunity
- DHTDiscoveryCommunity

Key Specifications
------------------

Each of the key specifications is a dictionary following the following standard:

.. csv-table:: Key definitions
   :header: "key", "description"
   :widths: 20, 80

   "alias", "The name by which this key can be referenced in overlay configuration."
   "file", "The optional file to store the key in."
   "generation", "The curve to use if this key needs to be generated."
   "bin", "The b64 encoded raw key material to use."

It is always required to specify a key ``alias``.
If you specify a ``file`` IPv8 will attempt to load your key from this file.
Only if the file does not exist, will the ``generation`` or ``bin`` be referenced.
If a ``file`` has been specified, once a key has been loaded it will be written to the specified ``file``.
If you specify a ``bin``, IPv8 will prefer to use this raw key material over generating a new key from the key curve specified by ``generation``.
You must provide IPv8 with at least one of the key source material options (a ``file``, a ``bin`` or a ``generation``) to have a valid key configuration.
