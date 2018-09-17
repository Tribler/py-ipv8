from __future__ import absolute_import

import abc
from hashlib import sha1
import six


class Key(six.with_metaclass(abc.ABCMeta, object)):
    """
    Interface for a public or private key.
    """

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


class PrivateKey(six.with_metaclass(abc.ABCMeta, Key)):
    """
    Interface for a private key.
    """

    def has_secret_key(self):
        return True

    @abc.abstractmethod
    def signature(self, msg):
        pass


class PublicKey(six.with_metaclass(abc.ABCMeta, Key)):
    """
    Interface for a public key.
    """

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
