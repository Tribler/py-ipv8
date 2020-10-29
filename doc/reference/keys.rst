Key generation options
======================

The ``ipv8/keyvault/crypto.py`` file contains the main public key cryptography class for IPv8: ``ECCrypto``.
It allows you to generate the following keys:


.. csv-table:: Available curves for key generation
   :header: "name", "curve", "backend"
   :widths: 20, 20, 20

   "very-low", "SECT163K1", "M2Crypto"
   "low", "SECT233K1", "M2Crypto"
   "medium", "SECT409K1", "M2Crypto"
   "high", "SECT571R1", "M2Crypto"
   "curve25519", "EC25519", "Libsodium"


The ``M2Crypto`` backend keys do not actually use the ``M2Crypto`` backend, but use a ``python-cryptography`` backend.
These ``M2Crypto`` curves are supported for backwards compatibility with the Dispersy project.
For new applications, only the ``curve25519`` should be used.

Generally you will create either a new ``ECCrypto`` instance (if you wish to modify or extend the base cryptography) or use the default ``default_eccrypto`` instance.
The following methods are most commonly used:

- ``generate_key()``: generate a new key from a given curve name.
- ``key_to_bin()``: serialize a given key into a string.
- ``key_from_private_bin()``: load a private key from a string.
- ``key_from_public_bin()``: load a public key from a string.

The following methods will usually be handled by IPv8 internally:

- ``key_to_hash()``: convert a key into a ``sha1`` string (usually accessed through ``Peer.mid``).
- ``create_signature()``: create a signature for some data (usually handled by the ``Community`` class).
- ``is_valid_signature()``: checks a signature for validity (usually handled by the ``Community`` class).
