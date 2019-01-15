from __future__ import absolute_import
from __future__ import print_function

from binascii import hexlify

from ipv8.keyvault.crypto import ECCrypto

# This script generates a curve25519 key and prints it in hex format
print(hexlify(ECCrypto().generate_key(u"curve25519").key_to_bin()))
