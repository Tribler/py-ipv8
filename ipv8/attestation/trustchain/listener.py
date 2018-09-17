from __future__ import absolute_import

import abc
import six

from .block import TrustChainBlock


class BlockListener(six.with_metaclass(abc.ABCMeta, object)):
    """
    This class defines a listener for TrustChain blocks with a specific type.
    """

    BLOCK_CLASS = TrustChainBlock

    @abc.abstractmethod
    def should_sign(self, block):
        """
        Method to indicate whether this listener wants a specific block signed or not.
        """
        pass

    @abc.abstractmethod
    def received_block(self, block):
        """
        This method is called when a listener receives a block that matches the BLOCK_CLASS.
        :return:
        """
        pass
