
Advanced attestation service usage
==================================

This document assumes you have a basic understanding of identification flows in IPv8, as documented in `the overlay tutorial <../../basics/identity_tutorial>`_.
This document addresses the following three topics:

- Enabling anonymization.
- Setting a REST API access token.
- Setting a rendezvous token.

Each of these features can be enabled independently, but should all be enabled when dealing with actual identity data.


Enabling anonymization
----------------------

**Purpose:** *disallow device fingerprinting.*

In the basic identity tutorial we created the following configuration:

.. code-block:: python

    for peer_id in [1, 2]:
        configuration = get_default_configuration()
        configuration['keys'] = [{'alias': "anonymous id", 'generation': u"curve25519", 'file': f"keyfile_{peer_id}.pem"}]
        configuration['working_directory'] = f"state_{peer_id}"
        configuration['overlays'] = []

To enable anonymization of all traffic through the identity layer we need to load the anonymization overlay.
This is done by editing the loaded overlays through ``configuration['overlays']``, as follows:

.. code-block:: python

    for peer_id in [1, 2]:
        configuration = get_default_configuration()
        configuration['keys'] = [{'alias': "anonymous id", 'generation': u"curve25519", 'file': f"keyfile_{peer_id}.pem"}]
        configuration['working_directory'] = f"state_{peer_id}"
        configuration['overlays'] = [overlay for overlay in configuration['overlays'] if overlay['class'] == 'HiddenTunnelCommunity']

Inclusion of the ``'HiddenTunnelCommunity'`` overlay automatically enables anonymization of identity traffic.
Note that this anonymization:

1. Requires other peers to be online.
2. Requires additional startup time. It can take several seconds for an anonymized circuit to be established.

Setting a REST API key
----------------------

**Purpose:** *disallow other local services from hijacking IPv8.*

In the basic identity tutorial we started the REST API as follows:

.. code-block:: python

    for peer_id in [1, 2]:
        ipv8 = IPv8(configuration)
        await ipv8.start()
        rest_manager = RESTManager(ipv8)
        await rest_manager.start(14410 + peer_id)

To set a REST API key, we will have to pass it to the ``RESTManager`` constructor, as follows (replacing ``"my secret key"`` with your key):

.. code-block:: python

    for peer_id in [1, 2]:
        ipv8 = IPv8(configuration)
        await ipv8.start()
        rest_manager = RESTManager(ipv8, api_key="my secret key")
        await rest_manager.start(14410 + peer_id)

All requests to the core will then have to use either:

1. The ``X-Api-Key`` HTTP header set to the key value (this is the preferred option).
2. A URL parameter ``apikey`` set to the key value.

Any HTTP request without either of these entries or using the wrong key will be dropped.

Using a REST API X509 certificate
---------------------------------

**Purpose:** *provide transport layer security (TLS) for the REST API.*

In the basic identity tutorial we started the REST API as follows:

.. code-block:: python

    for peer_id in [1, 2]:
        ipv8 = IPv8(configuration)
        await ipv8.start()
        rest_manager = RESTManager(ipv8)
        await rest_manager.start(14410 + peer_id)

To use a certificate file, we will have to pass it to the ``RESTManager`` constructor, as follows (replacing ``cert_fileX`` with the file path of your certificate file for the particular IPv8 instance):

.. code-block:: python

    for peer_id in [1, 2]:
        ipv8 = IPv8(configuration)
        await ipv8.start()
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_fileX)
        rest_manager = RESTManager(ipv8, ssl_context=ssl_context)
        await rest_manager.start(14410 + peer_id)

This can (and should) be combined with an API key.
Also note that if you start two IPv8 instances, you would normally want them to have different certificates.

If you don't have a certificate file, you can generate one with ``openssl`` as follows:

.. code-block:: bash

    openssl req -newkey rsa:2048 -nodes -keyout private.key -x509 -days 365 -out certfile.pem
    cat private.key >> certfile.pem
    rm private.key

Setting a rendezvous token
--------------------------

**Purpose:** *disallow exposure of pseudonym public keys.*

In the basic identity tutorial we used HTTP requests without a rendezvous token as follows:

.. code-block:: bash

   $ curl http://localhost:14411/identity/pseudonym1/peers
   {"peers": ["TGliTmFDTFBLOg/rrouc7qXT1ZKxHFvzxb4IVRYDPdbN4n7eFFuaT385YNW4aoh3Mruv+hSjbssLYmps+jlh9rb250LYD7gEH20="]}

By including the ``X-Rendezvous`` header entry and setting it to a shared secret in base64 encoding, we can guide a rendezvous between peers.
The following is an example of a rendezvous using the shared identifier string ``abc``.

.. code-block:: bash

   $ curl --header "X-Rendezvous: YWJj" http://localhost:14411/identity/pseudonym1/peers

Notes:

- Include this header in all of your requests.
- If you want to switch rendezvous tokens, first call ``identity/{pseudonym_name}/unload``.
- Any identifier over 20 bytes is truncated.
- You may still find peers other than those you are interested in if you happen to share the same rendezvous identifier. Always communicate and verify the public key of your counterparty beforehand (use the ``identity/{pseudonym_name}/public_key`` REST endpoint for this).
