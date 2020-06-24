import inspect
import types

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
            super_argspec = inspect.getfullargspec(super(VariablePayload, self).__init__).args[1:]
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
        for i in range(len(args)):
            custom_rule = "fix_unpack_" + cls.names[i]
            if hasattr(cls, custom_rule):
                unpack_args[i] = getattr(cls, custom_rule)(args[i])
        return cls(*unpack_args)

    @staticmethod
    def _to_packlist_fmt(fmt):
        return fmt if isinstance(fmt, str) else 'payload'

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


def _raw_compile(f_code):
    """
    Compile some code for injection into the locals().
    We cheat the systems by giving the f_code as the filename.
    This allows programmers to actually see the autogenerated output instead of just "<string>".

    :param f_code: the code to compile for execution
    :type f_code: str
    :return: the compiled code object
    :rtype: code
    """
    return compile(f_code, '<string>' + f_code, 'exec')


def _compile_init(src_cls, fmt_list_len, names):
    """
    Compile the init function.

    Takes the form of:

     .. code-block :: Python

        def __init__(self, a, b, c=None):
            self.a = a
            self.b = b
            if c is not None:
                setattr(self, 'c', c)

    :param src_cls: the source class to use
    :param src_cls: VariablePayload
    :param fmt_list_len: the length of the class format_list
    :type fmt_list_len: int
    :param names: the format list's names
    :type names: [str]
    :return: the compiled code object
    :rtype: code
    """
    f_code = """
def __init__(self, %s):
    Payload.__init__(self)
    opt_args = 0
    self._opt_list = []
    %s
    """ % (', '.join([name for name in names[:fmt_list_len]]
                     + ['%s=None' % name for name in names[fmt_list_len:]]),
           '\n    '.join(['self.%s = %s' % (name, name) for name in names[:fmt_list_len]]
                         + ["""if %s is not None:
        setattr(self, "%s", %s)
        self._opt_list.append((%s, %s))
        opt_args += 1""" % (name, name, name,
                            "self.optional_format_list[opt_args]"
                            if isinstance(src_cls.optional_format_list[i], str) else '"payload"',
                            "self.fix_pack_%s(self.%s)" % (name, name)
                            if hasattr(src_cls, "fix_pack_" + name) else "self.%s" % name)
                            for i, name in enumerate(names[fmt_list_len:])]))
    return compile(f_code, f_code, 'exec')


def _compile_from_unpack_list(src_cls, fmt_list_len, names):
    """
    Compile the unpacking code.

    Takes the form of (``fix_unpack_`` is inserted if defined in the source class):

    .. code-block :: Python

        def from_unpack_list(cls, a, b, c=None):
            return cls(a, fix_unpack_b(b), c)

    :param src_cls: the source class to use
    :param src_cls: VariablePayload
    :param fmt_list_len: the length of the class format_list
    :type fmt_list_len: int
    :param names: the format list's names
    :type names: [str]
    :return: the compiled code object
    :rtype: code
    """
    arg_list = ', '.join([name for name in names[:fmt_list_len]] + ['%s=None' % name for name in names[fmt_list_len:]])
    f_code = """
def from_unpack_list(cls, %s):
    return cls(%s)
    """ % (arg_list, ', '.join(["None if %s is None else cls.fix_unpack_%s(%s)" % (name, name, name)
                                if hasattr(src_cls, "fix_unpack_" + name)
                                else name for name in names]))
    return compile(f_code, f_code, 'exec')


def _compile_to_pack_list(src_cls, format_list, names):
    """
    Compile the packing code.

    Takes the form of (``fix_pack_`` is inserted if defined in the source class):

    .. code-block :: Python

        def to_pack_list(self):
            return [("I", self.a), ("H", fix_pack_b(self.b)))]

    :param src_cls: the source class to use
    :param src_cls: VariablePayload
    :param fmt_list_len: the length of the class format_list
    :type fmt_list_len: int
    :param names: the format list's names
    :type names: [str]
    :return: the compiled code object
    :rtype: code
    """
    f_code = """
def to_pack_list(self):
    return [%s] + self._opt_list
        """ % ', '.join(('("%s", self.fix_pack_%s(self.%s))' % (fmt if isinstance(fmt, str) else "payload",
                                                                names[i], names[i]))
                        if hasattr(src_cls, "fix_pack_" + names[i]) else
                        ('("%s", self.%s)' % (fmt if isinstance(fmt, str) else "payload", names[i]))
                        for i, fmt in enumerate(format_list))
    return compile(f_code, f_code, 'exec')


def vp_compile(vp_definition):
    """
    JIT Compilation of a VariablePayload definition.

    Don't look at the internals :)
    """
    # Load the function definitions into the local scope. Don't try this at home kids.
    exec(_compile_init(vp_definition, len(vp_definition.format_list), vp_definition.names),
         globals(), locals())
    exec(_compile_from_unpack_list(vp_definition, len(vp_definition.format_list), vp_definition.names),
         globals(), locals())
    exec(_compile_to_pack_list(vp_definition, vp_definition.format_list, vp_definition.names),
         globals(), locals())
    # Rewrite the class methods from the locally loaded overwrites.
    # from_unpack_list is a classmethod, so we need to scope it properly.
    setattr(vp_definition, '__init__', locals()['__init__'])
    setattr(vp_definition, 'from_unpack_list', types.MethodType(locals()['from_unpack_list'], vp_definition))
    setattr(vp_definition, 'to_pack_list', locals()['to_pack_list'])
    return vp_definition


__all__ = ['VariablePayload', 'vp_compile']
