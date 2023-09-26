
Using the IPv8 attestation service
==================================

This document assumes you have a basic understanding of network overlays in IPv8, as documented in `the overlay tutorial <../basics/overlay_tutorial.html>`_.
You will learn how to use the IPv8 attestation *HTTP REST API*.
This tutorial will use ``curl`` to perform HTTP ``GET`` and ``POST`` requests.

This document will cover the basic flows of identification.
If you plan on using real identity data, you will need to familiarize yourself with the `the advanced identity controls <../further-reading/advanced_identity.html>`_.

Running the IPv8 service
------------------------

Fill your ``main.py`` file with the following code (runnable with ``python3 main.py``\ ):

.. literalinclude:: identity_tutorial_1.py

Running the service should yield something like the following output in your terminal:

.. code-block:: bash

   $ python3 main.py
   Starting peer aQVwz9aRMRypGwBkaxGRSdQs80c=
   Starting peer bPyWPyswqXMhbW8+0RS6xUtNJrs=

You should see two messages with 28 character base64 encoded strings.
These are the identifiers of the two peers we launched using the service.
You can use these identifiers for your reference when playing around with sending attestation requests.
In your experiment you will create unique keys and therefore see other identifiers than the ``aQVwz9aRMRypGwBkaxGRSdQs80c=`` and ``bPyWPyswqXMhbW8+0RS6xUtNJrs=`` shown above.

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

.. code-block:: console

   TGliTmFDTFBLOpyBsled71NjFOZfF3L%2Bw0sdAvcM3xI1nM%2Fik6NbRzxmwgFBJRZdQ%2Bh2CURQlwxtFxe33U7oldJtK%2BE1fTk2rOo%3D
   TGliTmFDTFBLOg%2Frrouc7qXT1ZKxHFvzxb4IVRYDPdbN4n7eFFuaT385YNW4aoh3Mruv%2BhSjbssLYmps%2Bjlh9rb250LYD7gEH20%3D

If you are using Python, you can make these identifiers URL-safe by calling ``urllib.parse.quote(identifier, safe='')``.

Enrollment/Attestation flow
^^^^^^^^^^^^^^^^^^^^^^^^^^^

To enroll, or attest, an attribute we will go through the following steps:


#. Sanity checks: Peer 1 and Peer 2 can see each other and have no existing attributes.
#. Peer 1 requests attestation of an attribute by Peer 2.
#. Peer 2 attests to the requested attribute.
#. Peer 1 checks its attributes to confirm successful attestation.

**0. SANITY CHECK -** First we check if both peers can see each other using their respective interfaces.

.. code-block:: bash

   $ curl http://localhost:14411/identity/pseudonym1/peers
   {"peers": ["TGliTmFDTFBLOg/rrouc7qXT1ZKxHFvzxb4IVRYDPdbN4n7eFFuaT385YNW4aoh3Mruv+hSjbssLYmps+jlh9rb250LYD7gEH20="]}
   $ curl http://localhost:14412/identity/pseudonym2/peers
   {"peers": ["TGliTmFDTFBLOpyBsled71NjFOZfF3L+w0sdAvcM3xI1nM/ik6NbRzxmwgFBJRZdQ+h2CURQlwxtFxe33U7oldJtK+E1fTk2rOo="]}

Pseudonyms are lazy-loaded and/or created on demand, it may take a few seconds for the pseudonyms to discover each other.
Then we confirm that neither peer has existing attributes.

.. code-block:: bash

   $ curl http://localhost:14411/identity/pseudonym1/credentials
   {"names": []}
   $ curl http://localhost:14412/identity/pseudonym2/credentials
   {"names": []}

**1. ATTESTATION REQUEST -** Peer 1 will now ask Peer 2 to attest to an attribute.

.. code-block:: bash

   $ curl -X PUT -H "Content-Type: application/json" -d '{"name":"my_attribute","schema":"id_metadata","metadata":{}}' "http://localhost:14411/identity/pseudonym1/request/TGliTmFDTFBLOg%2Frrouc7qXT1ZKxHFvzxb4IVRYDPdbN4n7eFFuaT385YNW4aoh3Mruv%2BhSjbssLYmps%2Bjlh9rb250LYD7gEH20%3D"
   {"success": true}

**2. ATTESTATION -** Peer 2 finds an outstanding request for attestation.
Peer 2 will now attest to some attribute value of Peer 1 (\ ``dmFsdWU=`` is the string ``value`` in base64 encoding).

.. code-block:: bash

   $ curl http://localhost:14412/identity/pseudonym2/outstanding/attestations
   {"requests": [{"peer": "TGliTmFDTFBLOpyBsled71NjFOZfF3L+w0sdAvcM3xI1nM/ik6NbRzxmwgFBJRZdQ+h2CURQlwxtFxe33U7oldJtK+E1fTk2rOo=", "attribute_name": "my_attribute", "metadata": "{}"}]}
   $ curl -X PUT -H "Content-Type: application/json" -d '{"name":"my_attribute","value":"dmFsdWU="}' "http://localhost:14412/identity/pseudonym2/attest/TGliTmFDTFBLOpyBsled71NjFOZfF3L%2Bw0sdAvcM3xI1nM%2Fik6NbRzxmwgFBJRZdQ%2Bh2CURQlwxtFxe33U7oldJtK%2BE1fTk2rOo%3D"
   {"success": true}

**3. CHECK -** Peer 1 confirms that he now has an attested attribute.

.. code-block:: bash

   $ curl http://localhost:14411/identity/pseudonym1/credentials
   {"names": [{"name": "my_attribute", "hash": "mtMiZioWORNgV+GeGACsY+rD+lI=", "metadata": {"name": "my_attribute", "schema": "id_metadata", "date": 1593171171.876003}, "attesters": ["TGliTmFDTFBLOg/rrouc7qXT1ZKxHFvzxb4IVRYDPdbN4n7eFFuaT385YNW4aoh3Mruv+hSjbssLYmps+jlh9rb250LYD7gEH20="]}]}
   $ curl http://localhost:14412/identity/pseudonym2/credentials
   {"names": []}

Attribute verification flow
^^^^^^^^^^^^^^^^^^^^^^^^^^^

To verify an attribute we will go through the following steps:


#. Sanity checks: Peer 1 and Peer 2 can see each other and Peer 1 has an existing attribute.
#. Peer 2 requests verification of an attribute of Peer 1.
#. Peer 1 allows verification of its attribute.
#. Peer 2 checks the verification output for the requested verification.

**0. SANITY CHECK -** First we check if both peers can see each other using their respective interfaces.

.. code-block:: bash

   $ curl http://localhost:14411/identity/pseudonym1/peers
   {"peers": ["TGliTmFDTFBLOg/rrouc7qXT1ZKxHFvzxb4IVRYDPdbN4n7eFFuaT385YNW4aoh3Mruv+hSjbssLYmps+jlh9rb250LYD7gEH20="]}
   $ curl http://localhost:14412/identity/pseudonym2/peers
   {"peers": ["TGliTmFDTFBLOpyBsled71NjFOZfF3L+w0sdAvcM3xI1nM/ik6NbRzxmwgFBJRZdQ+h2CURQlwxtFxe33U7oldJtK+E1fTk2rOo="]}

Then we confirm that Peer 1 has the existing attribute (\ ``my_attribute`` from the last step).

.. code-block:: bash

   $ curl http://localhost:14411/identity/pseudonym1/credentials
   {"names": [{"name": "my_attribute", "hash": "mtMiZioWORNgV+GeGACsY+rD+lI=", "metadata": {"name": "my_attribute", "schema": "id_metadata", "date": 1593171171.876003}, "attesters": ["TGliTmFDTFBLOg/rrouc7qXT1ZKxHFvzxb4IVRYDPdbN4n7eFFuaT385YNW4aoh3Mruv+hSjbssLYmps+jlh9rb250LYD7gEH20="]}]}
   $ curl http://localhost:14412/identity/pseudonym2/credentials
   {"names": []}

**1. VERIFICATION REQUEST -** Peer 2 will now ask Peer 1 to verify an attribute.

.. code-block:: bash

   $ curl -X PUT -H "Content-Type: application/json" -d '{"hash":"mtMiZioWORNgV+GeGACsY+rD+lI=","value":"dmFsdWU=","schema":"id_metadata"}' "http://localhost:14412/identity/pseudonym2/verify/TGliTmFDTFBLOpyBsled71NjFOZfF3L%2Bw0sdAvcM3xI1nM%2Fik6NbRzxmwgFBJRZdQ%2Bh2CURQlwxtFxe33U7oldJtK%2BE1fTk2rOo%3D"
   {"success": true}

**2. VERIFICATION -** Peer 1 finds an outstanding request for verification.

.. code-block:: bash

   $ curl http://localhost:14411/identity/pseudonym1/outstanding/verifications
   {"requests": [{"peer": "TGliTmFDTFBLOg/rrouc7qXT1ZKxHFvzxb4IVRYDPdbN4n7eFFuaT385YNW4aoh3Mruv+hSjbssLYmps+jlh9rb250LYD7gEH20=", "attribute_name": "my_attribute"}
   $ curl -X PUT -H "Content-Type: application/json" -d '{"name":"my_attribute"}' "http://localhost:14411/identity/pseudonym1/allow/TGliTmFDTFBLOg%2Frrouc7qXT1ZKxHFvzxb4IVRYDPdbN4n7eFFuaT385YNW4aoh3Mruv%2BhSjbssLYmps%2Bjlh9rb250LYD7gEH20%3D"
   {"success": true}

**3. CHECK -** Peer 2 checks the output of the verification process.

.. code-block:: bash

   $ curl http://localhost:14412/identity/pseudonym2/verifications
   {"outputs": [{"hash": "mtMiZioWORNgV+GeGACsY+rD+lI=", "reference": "dmFsdWU=", "match": 0.9999847412109375}]}
