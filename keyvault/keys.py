import abc
from hashlib import sha1


class Key(object):
    """
    Interface for a public or private key.
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def pub(self):
        pass

    @abc.abstractmethod
    def has_secret_key(self):
        pass

    @abc.abstractmethod
    def key_to_bin(self):
        pass

    def key_to_hash(self):
        if self.has_secret_key():
            return sha1(self.pub().key_to_bin()).digest()
        return sha1(self.key_to_bin()).digest()


class PrivateKey(Key):
    """
    Interface for a private key.
    """

    __metaclass__ = abc.ABCMeta

    def has_secret_key(self):
        return True

    @abc.abstractmethod
    def signature(self, msg):
        pass


class PublicKey(Key):
    """
    Interface for a public key.
    """

    __metaclass__ = abc.ABCMeta

    def pub(self):
        return self

    def has_secret_key(self):
        return False

    @abc.abstractmethod
    def verify(self, signature, msg):
        pass

    @abc.abstractmethod
    def get_signature_length(self):
        pass
