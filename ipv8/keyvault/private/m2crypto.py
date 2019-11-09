from base64 import encodebytes
from binascii import unhexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .. import NEW_CRYPTOGRAPHY_SIGN_VERSION
from ...keyvault.keys import PrivateKey
from ...keyvault.public.m2crypto import M2CryptoPK


class M2CryptoSK(PrivateKey, M2CryptoPK):
    """
    A pyca implementation of a secret key, backwards compatible with Dispersy M2Crypto secret keys.
    """

    def __init__(self, curve=None, keystring=None, filename=None):
        """
        Create a new M2Crypto secret key. Optionally load it from a string representation (in a file)
        or generate it using some curve.

        :param curve: the EllipticCurve object specifying the curve
        :param keystring: the string to load the key from
        :param filename: the filename to load the key from
        """
        if curve:
            self.ec = ec.generate_private_key(curve, default_backend())

        elif keystring:
            self.ec = self.key_from_pem(b"-----BEGIN EC PRIVATE KEY-----\n%s-----END EC PRIVATE KEY-----\n" %
                                        encodebytes(keystring))

        elif filename:
            with open(filename, 'rb') as keyfile:
                self.ec = self.key_from_pem(keyfile.read())

    def pub(self):
        """
        Get the public key for this secret key.
        """
        return M2CryptoPK(ec_pub=self.ec.public_key())

    def has_secret_key(self):
        """
        Is this is a secret key (yes it is)?
        """
        return True

    def key_to_pem(self):
        "Convert a key to the PEM format."

        return self.ec.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.TraditionalOpenSSL,
                                     serialization.NoEncryption())

    def key_from_pem(self, pem):
        """
        Load a key from a pem certificate.

        :param pem: the PEM formatted private key
        """
        return serialization.load_pem_private_key(pem, password=None, backend=default_backend())

    def signature(self, msg):
        """
        Create a signature for a message in a backwards compatible fashion

        :param msg: the message to sign
        """
        # Create the pyca signature
        if NEW_CRYPTOGRAPHY_SIGN_VERSION:
            signature = self.ec.sign(msg, ec.ECDSA(hashes.SHA1()))
        else:
            signer = self.ec.signer(ec.ECDSA(hashes.SHA1()))
            signer.update(msg)
            signature = signer.finalize()
        # Decode the DSS r and s variables from the pyca signature
        # We are going to turn these longs into (binary) string format
        r, s = decode_dss_signature(signature)
        # Convert the r and s to a valid hex representation
        r = hex(r).rstrip("L").lstrip("0x") or "0"
        s = hex(s).rstrip("L").lstrip("0x") or "0"
        # We want bytes: one byte is two nibbles:
        # Prefix with a 0 if the result is of odd length
        if len(r) % 2 == 1:
            r = "0" + r
        if len(s) % 2 == 1:
            s = "0" + s
        # Now we can turn this into a binary string
        r = unhexlify(r)
        s = unhexlify(s)
        key_len = self.get_signature_length() // 2
        # For easy decoding, prepend 0 to r and s until they are of >equal length<
        return b"".join((b"\x00" * (key_len - len(r)), r, b"\x00" * (key_len - len(s)), s))
