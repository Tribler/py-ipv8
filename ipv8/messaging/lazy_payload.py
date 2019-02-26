from __future__ import absolute_import

import inspect

from six import string_types
from six.moves import xrange

from .payload import Payload


class VariablePayload(Payload):
    """
    A Payload instance which mimics a struct. Useful for when you want a less verbose way to specify Payloads.

    This class requires you to only specify your format in:

        - <MyPayload>.format_list : a list of Serializer format specifications
        - <MyPayload>.names : the field names to use for the given formats

    For instance:

        class MyPayload(VariablePayload):
            format_list = ['?']
            names = ["is_this_a_boolean"]

    If you require field-specific pack/unpack operations you can specify them using the `fix_pack_*` and
    `fix_unpack_*` methods.
    Custom packing and unpacking rules can be useful for compression methods like socket.inet_aton, which you only
    want to apply when actually sending over the wire.
    """

    names = []

    def __init__(self, *args, **kwargs):
        """
        Instantiate this VariablePayload class.

        :param args: the anonymous list of arguments, an index-based mapping to self.names and self.format_list
        :param kwargs: the named arguments, mapping to self.names and self.format_list (in no particular order)
        :raises KeyError: if the given arguments do not match the class specification
        """
        index = 0
        fwd_args = {}
        # If our super class is an old-style Payload function, forward the required arguments.
        if not issubclass(super(VariablePayload, self).__class__, VariablePayload) and \
                inspect.ismethod(super(VariablePayload, self).__init__):
            super_argspec = inspect.getargspec(super(VariablePayload, self).__init__).args[1:]
            for arg in super_argspec:
                if arg in kwargs:
                    fwd_args[arg] = kwargs.pop(arg)
                else:
                    fwd_args[arg] = args[index]
                index += 1
            super(VariablePayload, self).__init__(**fwd_args)
        Payload.__init__(self)
        # Try to fill the required format specification.
        for _ in range(len(self.format_list) - index):
            # Run out all anonymous arguments, then start popping from the keyword arguments.
            # This will raise a KeyError if we provide more arguments than we can handle.
            value = args[index] if index < len(args) else kwargs.pop(self.names[index])
            setattr(self, self.names[index], value)
            index += 1
        if index != len(self.format_list):
            raise KeyError("%s missing %d arguments!" % (self.__class__.__name__, len(args) - index))
        # Try to fill in the optional format specification.
        for _ in self.optional_format_list:
            # If we run out of anonymous and named arguments, we stop.
            if index == len(args) and not kwargs:
                break
            value = args[index] if index < len(args) else kwargs.pop(self.names[index])
            setattr(self, self.names[index], value)
            index += 1
        if kwargs:
            raise KeyError("%s has leftover keyword arguments: %s!" % (self.__class__.__name__, str(kwargs)))

    @classmethod
    def from_unpack_list(cls, *args):
        """
        Given a list of raw arguments, initialize a new cls instance.

        If this class has special rules for certain fields, apply them.
        """
        unpack_args = list(args)
        for i in xrange(len(args)):
            custom_rule = "fix_unpack_" + cls.names[i]
            if hasattr(cls, custom_rule):
                unpack_args[i] = getattr(cls, custom_rule)(args[i])
        return cls(*unpack_args)

    @staticmethod
    def _to_packlist_fmt(fmt):
        return fmt if isinstance(fmt, string_types) else 'payload'

    def _fix_pack(self, name):
        """
        Check if there are custom rules for sending this field.
        """
        raw_value = getattr(self, name)
        custom_rule = "fix_pack_" + name
        if hasattr(self, custom_rule):
            return getattr(self, custom_rule)(raw_value)
        return raw_value

    def to_pack_list(self):
        """
        Convert the VariablePayload to a Serializable pack list.
        This method will automatically pull from the available format names and set instance fields.

        :return: the pack list
        """
        out = []
        index = 0
        for _ in range(len(self.format_list)):
            out.append((self._to_packlist_fmt(self.format_list[index]), self._fix_pack(self.names[index])))
            index += 1
        while index < len(self.names) and hasattr(self, self.names[index]):
            out.append((self._to_packlist_fmt(self.optional_format_list[index - len(self.format_list)]),
                        self._fix_pack(self.names[index])))
        index += 1
        return out
