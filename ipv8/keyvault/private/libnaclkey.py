import libnacl
import libnacl.dual
import libnacl.sign

from ...keyvault.public.libnaclkey import LibNaCLPK
from ...keyvault.keys import PrivateKey


class LibNaCLSK(PrivateKey, LibNaCLPK):
    """
    A LibNaCL implementation of a secret key.
    """

    def __init__(self, binarykey=""):
        """
        Create a new LibNaCL secret key. Optionally load it from a string representation.
        Otherwise generate it from the 25519 curve.

        :param binarykey: load the sk from this string (see key_to_bin())
        """
        # Load the key, if specified
        if binarykey:
            crypt, seed = binarykey[:libnacl.crypto_box_SECRETKEYBYTES], \
                          binarykey[libnacl.crypto_box_SECRETKEYBYTES :
                                    libnacl.crypto_box_SECRETKEYBYTES + libnacl.crypto_sign_SEEDBYTES]
            self.key = libnacl.dual.DualSecret(crypt, seed)
        else:
            self.key = libnacl.dual.DualSecret()
        # Immediately create a verifier
        self.veri = libnacl.sign.Verifier(self.key.hex_vk())

    def pub(self):
        """
        Get the public key for this secret key.
        """
        return LibNaCLPK(pk=self.key.pk, hex_vk=self.veri.hex_vk())

    def signature(self, msg):
        """
        Create a signature for a message.

        :param msg: the message to sign
        :return: the signature for the message
        """
        return self.key.signature(msg)

    def key_to_bin(self):
        """
        Get the string representation of this key.
        """
        return "LibNaCLSK:" + self.key.sk + self.key.seed
