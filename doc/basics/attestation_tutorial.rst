
Using the IPv8 attestation service
==================================

This document assumes you have a basic understanding of network overlays in IPv8, as documented in `the overlay tutorial <../basics/overlay_tutorial.html>`_.
You will learn how to use the IPv8 attestation *HTTP REST API*.
This tutorial will use ``curl`` to perform HTTP ``GET`` and ``POST`` requests.

Note that this tutorial will make use of the Python IPv8 service.
`An Android binding <https://github.com/Tribler/ipv8-android-app>`_ is also available (\ `including demo app <https://github.com/Tribler/ipv8-android-app/tree/demo_app>`_\ ). 

Files
-----

This tutorial will follow the same file structure as `the overlay tutorial <../basics/overlay_tutorial.html>`_.
In this tutorial all of the files are placed in the ``~/Documents/ipv8_tutorial`` directory.


#. 
   In the working directory, we clone IPv8 through ``git``\ :

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

Fill your ``main.py`` file with the following code (runnable with ``python main.py``\ ):

.. code-block:: python

   from base64 import b64encode

   from asyncio import ensure_future, get_event_loop

   from pyipv8.ipv8.configuration import get_default_configuration
   from pyipv8.ipv8.REST.rest_manager import RESTManager
   from pyipv8.ipv8_service import IPv8


   async def start_communities():
       # Launch two IPv8 services.
       # We run REST endpoints for these services on:
       #  - http://localhost:14411/
       #  - http://localhost:14412/
       # This script also prints the peer ids for reference with:
       #  - http://localhost:1441*/attestation?type=peers
       for i in [1, 2]:
           configuration = get_default_configuration()
           configuration['logger']['level'] = "ERROR"
           configuration['keys'] = [
               {'alias': "anonymous id", 'generation': u"curve25519", 'file': u"ec%d_multichain.pem" % i},
               {'alias': "my peer", 'generation': u"medium", 'file': u"ec%d.pem" % i}
           ]

           # Only load the basic communities
           requested_overlays = ['DiscoveryCommunity', 'AttestationCommunity', 'IdentityCommunity']
           configuration['overlays'] = [o for o in configuration['overlays'] if o['class'] in requested_overlays]

           # Give each peer a separate working directory
           working_directory_overlays = ['AttestationCommunity', 'IdentityCommunity']
           for overlay in configuration['overlays']:
               if overlay['class'] in working_directory_overlays:
                   overlay['initialize'] = {'working_directory': 'state_%d' % i}

           # Start the IPv8 service
           ipv8 = IPv8(configuration)
           await ipv8.start()
           rest_manager = RESTManager(ipv8)
           await rest_manager.start(14410 + i)

           # Print the peer for reference
           print("Starting peer", b64encode(ipv8.keys["anonymous id"].mid))


   ensure_future(start_communities())
   get_event_loop().run_forever()

Running the service should yield something like the following output in your terminal:

.. code-block:: bash

   $ python main.py 
   Starting peer aQVwz9aRMRypGwBkaxGRSdQs80c=
   Starting peer bPyWPyswqXMhbW8+0RS6xUtNJrs=

You should see two messages with 28 character base64 encoded strings.
These are the identifiers of the two peers we launched using the service.
You can use these identifiers for your reference when playing around with sending attestation requests.
In your experiment you will see other identifiers than the ``aQVwz9aRMRypGwBkaxGRSdQs80c=`` and ``bPyWPyswqXMhbW8+0RS6xUtNJrs=`` shown above.

As a sanity check you can send your first HTTP ``GET`` requests and you should see that each peer can at least see the other peer.
Note that you might find more peers in the network.

.. code-block:: bash

   $ curl http://localhost:14411/attestation?type=peers
   ["bPyWPyswqXMhbW8+0RS6xUtNJrs="]
   $ curl http://localhost:14412/attestation?type=peers
   ["aQVwz9aRMRypGwBkaxGRSdQs80c="]

Functionality flows
-------------------

Generally speaking there are two (happy) flows when using the IPv8 attestation framework.
The first flow is the enrollment of an attribute and the second flow is the verification of an existing/enrolled attribute.
Both flows consist of a distinct set of requests (and responses) which we will explain in detail in the remainder of this document.

To test a flow, we start the two peers we created previously.
If you did not remove the key files (\ ``*.pem``\ ) after the first run, you will start the same two peers as in the last run.
In our case the output of starting the service is as follows:

.. code-block:: bash

   $ python main.py 
   Starting peer aQVwz9aRMRypGwBkaxGRSdQs80c=
   Starting peer bPyWPyswqXMhbW8+0RS6xUtNJrs=

In our case this means that peer ``aQVwz9aRMRypGwBkaxGRSdQs80c=`` exposes its REST API at ``http://localhost:14411/`` and peer ``bPyWPyswqXMhbW8+0RS6xUtNJrs=`` exposes its REST API at ``http://localhost:14412/``.
If you did not modify the ports in the initial scripts, you will have two different peer identifiers listening at the same ports.
For convenience we will refer to our first peer as *Peer 1* and our second peer as *Peer 2*.

As a last note, beware of URL encoding: when passing these identifiers they need to be properly formatted (\ ``+`` and ``=`` are illegal characters).
In our case we need to use the following formatting of the peer identifiers in URLs (for Peer 1 and Peer 2 respectively):

.. code-block:: none

   aQVwz9aRMRypGwBkaxGRSdQs80c%3D
   bPyWPyswqXMhbW8%2B0RS6xUtNJrs%3D

Enrollment/Attestation flow
^^^^^^^^^^^^^^^^^^^^^^^^^^^

To enroll, or attest, an attribute we will go through the following steps:


#. Sanity checks: Peer 1 and Peer 2 can see each other and have no existing attributes.
#. Peer 1 requests attestation of an attribute by Peer 2.
#. Peer 2 attests to the requested attribute.
#. Peer 1 checks its attributes to confirm successful attestation.

**0. SANITY CHECK -** First we check if both peers can see each other using their respective interfaces.

.. code-block:: bash

   $ curl http://localhost:14411/attestation?type=peers
   ["bPyWPyswqXMhbW8+0RS6xUtNJrs="]
   $ curl http://localhost:14412/attestation?type=peers
   ["aQVwz9aRMRypGwBkaxGRSdQs80c="]

Then we confirm that neither peer has existing attributes.
Note that ``http://*:*/attestation?type=attributes`` is shorthand for ``http://*:*/attestation?type=attributes&mid=mid_b64`` where the identifier is equal to that of the calling peer.

.. code-block:: bash

   $ curl http://localhost:14411/attestation?type=attributes
   []
   $ curl http://localhost:14412/attestation?type=attributes
   []

**1. ATTESTATION REQUEST -** Peer 1 will now ask Peer 2 to attest to an attribute.

.. code-block:: bash

   $ curl -X POST "http://localhost:14411/attestation?type=request&mid=bPyWPyswqXMhbW8%2B0RS6xUtNJrs%3D&attribute_name=my_attribute"

**2. ATTESTATION -** Peer 2 finds an outstanding request for attestation.
Peer 2 will now attest to some attribute value of Peer 1 (\ ``dmFsdWU%3D`` is the string ``value`` in base64 encoding).

.. code-block:: bash

   $ curl http://localhost:14412/attestation?type=outstanding
   [["aQVwz9aRMRypGwBkaxGRSdQs80c=", "my_attribute", "e30="]]
   $ curl -X POST "http://localhost:14412/attestation?type=attest&mid=aQVwz9aRMRypGwBkaxGRSdQs80c%3D&attribute_name=my_attribute&attribute_value=dmFsdWU%3D"

**3. CHECK -** Peer 1 confirms that he now has an attested attribute.

.. code-block:: bash

   $ curl http://localhost:14411/attestation?type=attributes
   [["my_attribute", "oEkkmxqu0Hd/aMVpSOdyP0SIlUM=", {}, "bPyWPyswqXMhbW8+0RS6xUtNJrs="]]
   $ curl http://localhost:14412/attestation?type=attributes
   []

Attribute verification flow
^^^^^^^^^^^^^^^^^^^^^^^^^^^

To verify an attribute we will go through the following steps:


#. Sanity checks: Peer 1 and Peer 2 can see each other and Peer 1 has an existing attribute.
#. Peer 2 requests verification of an attribute of Peer 1.
#. Peer 1 allows verification of its attribute.
#. Peer 2 checks the verification output for the requested verification.

**NOTE: YOU NEED TO BE FAST**\ : if you take more than 10 seconds between step 1 and 2, the request will time out.

**0. SANITY CHECK -** First we check if both peers can see each other using their respective interfaces.

.. code-block:: bash

   $ curl http://localhost:14411/attestation?type=peers
   ["bPyWPyswqXMhbW8+0RS6xUtNJrs="]
   $ curl http://localhost:14412/attestation?type=peers
   ["aQVwz9aRMRypGwBkaxGRSdQs80c="]

Then we confirm that Peer 1 has the existing attribute (\ ``my_attribute`` from the last step).

.. code-block:: bash

   $ curl http://localhost:14411/attestation?type=attributes
   [["my_attribute", "oEkkmxqu0Hd/aMVpSOdyP0SIlUM=", {}, "bPyWPyswqXMhbW8+0RS6xUtNJrs="]]
   $ curl http://localhost:14412/attestation?type=attributes
   []

**1. VERIFICATION REQUEST -** Peer 2 will now ask Peer 1 to verify an attribute.

.. code-block:: bash

   $ curl -X POST "http://localhost:14412/attestation?type=verify&mid=aQVwz9aRMRypGwBkaxGRSdQs80c%3D&attribute_hash=oEkkmxqu0Hd%2FaMVpSOdyP0SIlUM%3D&attribute_values=dmFsdWU%3D"

**2. VERIFICATION -** Peer 1 finds an outstanding request for verification.

.. code-block:: bash

   $ curl http://localhost:14411/attestation?type=outstanding_verify
   [["bPyWPyswqXMhbW8+0RS6xUtNJrs=", "my_attribute"]]
   $ curl -X POST "http://localhost:14411/attestation?type=allow_verify&mid=bPyWPyswqXMhbW8%2B0RS6xUtNJrs%3D&attribute_name=my_attribute"

**3. CHECK -** Peer 2 checks the output of the verification process.

.. code-block:: bash

   $ curl http://localhost:14412/attestation?type=verification_output
   {"oEkkmxqu0Hd/aMVpSOdyP0SIlUM=": [["dmFsdWU=", 0.9999847412109375]]}
