IPv8 Documentation
==================

Welcome to the IPv8 documentation! This file will help you navigate the existing documentation.
The documentation will explain the concepts behind IPv8, the architecture, and guide you through making your first overlay.


Why does IPv8 exist?
====================

Problems with the very fabric of The Internet, IPv4, are mounting. The approach of IPv6, Mobile IP, and IPSec is hampered by fundamental architectural problems. One solution is moving the intelligence up to a higher layer in the protocol stack and towards the end points. Our endpoints are not dependent on any central infrastructure. Our architecture is academically pure and fully decentralized; to the point of obsession. IPv8 is based on the principle of self-governance. Like Bitcoin and BitTorrent, our IPv8 overlays are permissionless and require no server upkeep costs. 

IPv8 aims to help restore the original Internet; for free; owned by nobody; for everyone.


IPv8 Features
=============

IPv8 is a networking layer which offers identities, communication with some robustness, and provides hooks for higher layers. For instance, our Internet-deployed reputation functions and ledger-based storage of reputation data. IPv8 is designed as a mechanism to build trust.  Each network overlay offers network connections to known digital identities through public keys. Overlays are robust against several network problems and security issues. Using a custom NAT-traversing DHT to find the current IPv4 network address, IPv8 keeps the network connectivity going, even as the IPv4 addresses change.  Each network overlay keeps track of a number of neighbors and occasionally checks if they are still responsive.

IPv8 offers global connectivity through integrated UDP NAT puncturing, announcement of your identity claim and a web-of-trust. IPv8 has an integrated attestation service. You can use IPv8 for official verification that something is true or authentic, according to a trustworthy attestor. By using zero-knowledge proofs we attempt to minimize privacy leakage.


The science behind IPv8
=======================
IPv8 was built through years of experience and was shaped by science. Some key publications are:

* Halkes G, Pouwelse J. UDP NAT and Firewall Puncturing in the Wild. In International Conference on Research in Networking 2011 May 9 (pp. 1-12). Springer, Berlin, Heidelberg.
* Zeilemaker N, Schoon B, Pouwelse J. Dispersy bundle synchronization. TU Delft, Parallel and Distributed Systems. 2013 Jan.


IPv8 Example
============

IPv8 is a tool to build interesting distributed applications. IPv8 overlays can be used to offer various services for your application. Our flagship application Tribler, for example, uses seven IPv8 overlays for serverless discovery. Tribler's services range from DHT-based lookup, Tor-inspired privacy to a completely decentralised marketplace for bandwidth. If we take a look at Tribler's debug screen, it shows IPv8 in action: you can observe statistics such as active neighbors and utilized network traffic to make sure you have made a healthy overlay.

 .. image:: ./resources/healthy_IPv8_overlay_collection.png
   :target: ./resources/healthy_IPv8_overlay_collection.png
   :alt: A screenshot of Tribler's IPv8 statistics
   

Getting help
============
If you spotted an inconsistency in the documentation or found a bug, please let us know in a `GitHub issue <https://github.com/Tribler/py-ipv8/issues>`_.

   
Table of contents
=================

.. toctree::
   :maxdepth: 2
   :caption: Preliminaries:

   preliminaries/install_libsodium.rst

.. toctree::
   :maxdepth: 2
   :caption: Basics:

   basics/overlay_tutorial.rst
   basics/requestcache_tutorial.rst
   basics/testbase_tutorial.rst
   basics/tasks_tutorial.rst
   basics/discoverystrategy_tutorial.rst
   basics/identity_tutorial.rst

.. toctree::
   :maxdepth: 2
   :caption: References:

   reference/peer_discovery.rst
   reference/community_best_practices.rst
   reference/configuration.rst
   reference/bootstrapping.rst
   reference/keys.rst
   reference/serialization.rst

.. toctree::
   :maxdepth: 2
   :caption: Further reading:

   further-reading/advanced_identity.rst
   further-reading/advanced_peer_discovery.rst
   further-reading/anonymization.rst

.. toctree::
   :maxdepth: 2
   :caption: Deprecated/Archive:

   deprecated/attestation_prototype.rst
   deprecated/attestation_tutorial.rst


Search
======

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

