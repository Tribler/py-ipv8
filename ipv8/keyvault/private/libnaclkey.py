import libnacl
import libnacl.dual
import libnacl.sign

from ...keyvault.keys import PrivateKey
from ...keyvault.public.libnaclkey import LibNaCLPK


class LibNaCLSK(PrivateKey, LibNaCLPK):
    """
    A LibNaCL implementation of a secret key.
    """

    def __init__(self, binarykey: bytes = b"") -> None:
        """
        Create a new LibNaCL secret key. Optionally load it from a string representation.
        Otherwise generate it from the 25519 curve.

        :param binarykey: load the sk from this string (see key_to_bin())
        """
        # Load the key, if specified
        if binarykey:
            crypt, seed = (binarykey[:libnacl.crypto_box_SECRETKEYBYTES],
                           binarykey[libnacl.crypto_box_SECRETKEYBYTES: libnacl.crypto_box_SECRETKEYBYTES
                                     + libnacl.crypto_sign_SEEDBYTES])
            key = libnacl.dual.DualSecret(crypt, seed)
        else:
            key = libnacl.dual.DualSecret()

        super().__init__(pk=key.pk, hex_vk=key.hex_vk())
        self.key = key

    def pub(self) -> LibNaCLPK:
        """
        Get the public key for this secret key.
        """
        return LibNaCLPK(pk=self.key.pk, hex_vk=self.veri.hex_vk())

    def signature(self, msg: bytes) -> bytes:
        """
        Create a signature for a message.

        :param msg: the message to sign
        :return: the signature for the message
        """
        return self.key.signature(msg)

    def key_to_bin(self) -> bytes:
        """
        Get the string representation of this key.
        """
        return b"LibNaCLSK:" + self.key.sk + self.key.seed
