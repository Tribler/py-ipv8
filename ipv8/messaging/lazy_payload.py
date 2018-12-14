from __future__ import absolute_import

import inspect

from six.moves import xrange

from .payload import Payload


class RuntimePayload(Payload):
    """
    A "Runtime" (actually on module load) generated Payload definition.

    You should never be initializing this directly.
    Instead, creation should be done through the ezpayload wrapper.
    """

    ez_names = []

    def __init__(self, *args, **kwargs):
        """
        Interpret the keyword arguments as class field assignments.

        Ergo:
            ..
            >> mypayload = MyPayload(a=2)

            >> mypayload.a == 2

            True
        """
        # Extract the arguments used by the super
        args_offset = 0
        if inspect.ismethod(super(RuntimePayload, self).__init__):
            superargs = inspect.getargspec(super(RuntimePayload, self).__init__).args[1:] # Ignore 'self'
            runtimesuperargs = getattr(super(RuntimePayload, self), 'ez_names', [])
            superargs += runtimesuperargs
            superkwargs = {}
            for k in list(kwargs.keys()):
                if k in superargs:
                    superkwargs[k] = kwargs.pop(k)
            fwargs = args[:len(superargs)]
            args = args[len(superargs):]
            args_offset = len(runtimesuperargs)
            super(RuntimePayload, self).__init__(*fwargs, **superkwargs)
        # If everything matches, we assign our own fields
        for i in xrange(len(args)):
            setattr(self, self.ez_names[i + args_offset], args[i])
        for k, v in kwargs.items():
            setattr(self, k, v)

    def to_pack_list(self):
        return (super(RuntimePayload, self).to_pack_list() or []) +\
               list(zip([(fmt if isinstance(fmt, str) else "payload")
                         for fmt in self.format_list[-len(self.ez_names):]],
                        [getattr(self, name) for name in self.ez_names]))

    @classmethod
    def from_unpack_list(cls, *args):
        superargs = args[:-len(cls.ez_names)]
        names = []
        if superargs:
            for base in cls.__bases__:
                names += inspect.getargspec(base.__init__).args[1:]
        names += cls.ez_names
        return cls(**{kwtuple[0]: kwtuple[1] for kwtuple in list(zip(names, args))})


def ezdecorator(ezfunc, baseclass=RuntimePayload):
    """
    Decorate a (function) specification as a class type with a certain baseclass.
    The function name becomes the class name and the arguments become the fields.

    :param ezfunc: the function to wrap
    :type ezfunc: function
    :param baseclass: the baseclass to inherit from
    :type baseclass: type(Payload)
    :return: the runtime definition of the required type
    """
    argspec = inspect.getargspec(ezfunc)
    bases = (baseclass,) if issubclass(baseclass, RuntimePayload) else (RuntimePayload, baseclass)
    return type(ezfunc.__name__, bases, {'ez_names': getattr(baseclass, 'ez_names', []) + argspec.args,
                                         'format_list': baseclass.format_list + list(argspec.defaults)})

def ezpayload(ezfunc):
    """
    Wrap a function to turn it into a Payload class definition (yes, you can do this in Python).
    Optionally supply another Payload to inherit from.

    :param ezfunc: the function to wrap or the base class to inherit from for the following function to wrap
    :type ezfunc: function or Payload
    :return: the new runtime Payload type
    """
    if inspect.isclass(ezfunc):
        return lambda wrapped: ezdecorator(wrapped, ezfunc)
    else:
        return ezdecorator(ezfunc)


__all__ = ['ezpayload']
