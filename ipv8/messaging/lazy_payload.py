from __future__ import annotations

import inspect
import types
from typing import Any, TypeVar

from .serialization import FormatListType, Payload


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

    names: list[str] = []

    def __init__(self, *args: Any, **kwargs) -> None:  # noqa: ANN401
        """
        Instantiate this VariablePayload class.

        :param args: the anonymous list of arguments, an index-based mapping to self.names and self.format_list
        :param kwargs: the named arguments, mapping to self.names and self.format_list (in no particular order)
        :raises KeyError: if the given arguments do not match the class specification
        """
        index = 0
        fwd_args = {}
        # If our super class is an old-style Payload function, forward the required arguments.
        if not issubclass(super().__class__, VariablePayload) and \
                inspect.ismethod(super().__init__):
            super_argspec = inspect.getfullargspec(super().__init__).args[1:]
            for arg in super_argspec:
                if arg in kwargs:
                    fwd_args[arg] = kwargs.pop(arg)
                else:
                    fwd_args[arg] = args[index]
                index += 1
            super().__init__(**fwd_args)
        Payload.__init__(self)
        # Try to fill the required format specification.
        base = index
        for i in range(len(self.format_list) - index):
            # Run out all anonymous arguments, then start popping from the keyword arguments.
            # This will raise a KeyError if we provide more arguments than we can handle.
            for _ in range(8 if self.format_list[i + base] == 'bits' else 1):
                value = args[index] if index < len(args) else kwargs.pop(self.names[index])
                setattr(self, self.names[index], value)
                index += 1
        if len(args) - index > 0:
            msg = f"{self.__class__.__name__} missing {len(args) - index} arguments!"
            raise KeyError(msg)
        if kwargs:
            msg = f"{self.__class__.__name__,} has leftover keyword arguments: {kwargs}!"
            raise KeyError(msg)
        setattr(self.__class__, "__match_args__", tuple(self.names))

    @classmethod
    def from_unpack_list(cls: type[VariablePayload], *args: Any) -> VariablePayload:  # noqa: ANN401
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
    def _to_packlist_fmt(fmt: FormatListType) -> str:
        if isinstance(fmt, str):
            return fmt
        if isinstance(fmt, list):
            return 'payload-list'
        return 'payload'

    def _fix_pack(self, name: str) -> Any:  # noqa: ANN401
        """
        Check if there are custom rules for sending this field.
        """
        raw_value = getattr(self, name)
        custom_rule = "fix_pack_" + name
        if hasattr(self, custom_rule):
            return getattr(self, custom_rule)(raw_value)
        return raw_value

    def to_pack_list(self) -> list[tuple]:
        """
        Convert the VariablePayload to a Serializable pack list.
        This method will automatically pull from the available format names and set instance fields.

        :return: the pack list
        """
        out = []
        index = 0
        for i in range(len(self.format_list)):
            args = []
            for _ in range(8 if self.format_list[i] == 'bits' else 1):
                args.append(self._fix_pack(self.names[index]))
                index += 1
            out.append((self._to_packlist_fmt(self.format_list[i]), *args))
        return out


class VariablePayloadWID(VariablePayload):
    msg_id: int


def _compile_init(names: list[str], defaults: dict[str, Any]) -> types.CodeType:
    """
    Compile the init function.

    For (["a", "b"], {"b": 3}) this takes the form of:

     .. code-block :: Python

        def __init__(self, a, b=3):
            self.a = a
            self.b = b

    :param names: the format list's names
    :type names: [str]
    :return: the compiled code object
    :rtype: code
    """
    arg_list = ', '.join((f"{name}={defaults.get(name)}" if name in defaults else name) for name in names)
    setters = '\n    '.join([f"self.{name} = {name}" for name in names])
    f_code = f"""
def __init__(self, {arg_list}):
    Payload.__init__(self)
    {setters}
    """
    return compile(f_code, f_code, 'exec')


def _compile_from_unpack_list(src_cls: type[VariablePayload], names: list[str]) -> types.CodeType:
    """
    Compile the unpacking code.

    Takes the form of (``fix_unpack_`` is inserted if defined in the source class):

    .. code-block :: Python

        def from_unpack_list(cls, a, b):
            return cls(a, fix_unpack_b(b), c)

    :param src_cls: the source class to use
    :param src_cls: VariablePayload
    :param names: the format list's names
    :type names: [str]
    :return: the compiled code object
    :rtype: code
    """
    arg_list = ', '.join(names)
    args = ', '.join([f"None if {name} is None else cls.fix_unpack_{name}({name})"
                      if hasattr(src_cls, "fix_unpack_" + name)
                      else name for name in names])
    f_code = f"""
def from_unpack_list(cls, {arg_list}):
    return cls({args})
    """
    return compile(f_code, f_code, 'exec')


def _compile_to_pack_list(src_cls: type[VariablePayload],
                          format_list: list[FormatListType],
                          names: list[str]) -> types.CodeType:
    """
    Compile the packing code.

    Takes the form of (``fix_pack_`` is inserted if defined in the source class):

    .. code-block :: Python

        def to_pack_list(self):
            return [("I", self.a), ("H", fix_pack_b(self.b)))]

    :param src_cls: the source class to use
    :param src_cls: VariablePayload
    :param format_list: the format_list
    :type format_list: [FormatListType]
    :param names: the format list's names
    :type names: [str]
    :return: the compiled code object
    :rtype: code
    """
    fmts = []
    index = 0
    for fmt in format_list:
        args = []
        for _ in range(8 if fmt == 'bits' else 1):
            name = names[index]
            if hasattr(src_cls, "fix_pack_" + name):
                args.append(f"self.fix_pack_{name}(self.{name})")
            else:
                args.append(f"self.{name}")
            index += 1
        derived_fmt = fmt if isinstance(fmt, str) else ("payload-list" if isinstance(fmt, list) else "payload")
        fmts.append('("{}", {})'.format(derived_fmt, ", ".join(args)))
    f_code = f"""
def to_pack_list(self):
    return [{', '.join(fmts)}]
"""
    return compile(f_code, f_code, 'exec')


T = TypeVar("T", bound=VariablePayload)


def vp_compile(vp_definition: type[T]) -> type[T]:
    """
    JIT Compilation of a VariablePayload definition.
    """
    # We use ``exec`` purposefully here, disable the pylint warning:
    # ruff: noqa: B010, S102

    # Load the function definitions into the local scope.
    exec(_compile_init(vp_definition.names, {
        k: v.default
        for k, v in inspect.signature(vp_definition.__init__).parameters.items()
        if v.default is not inspect.Parameter.empty
    }), globals(), locals())
    exec(_compile_from_unpack_list(vp_definition, vp_definition.names), globals(), locals())
    exec(_compile_to_pack_list(vp_definition, vp_definition.format_list, vp_definition.names), globals(), locals())

    # Rewrite the class methods from the locally loaded overwrites.
    # from_unpack_list is a classmethod, so we need to scope it properly.
    setattr(vp_definition, '__init__', locals()['__init__'])
    setattr(vp_definition, '__match_args__', tuple(vp_definition.names))
    setattr(vp_definition, 'from_unpack_list', types.MethodType(locals()['from_unpack_list'], vp_definition))
    setattr(vp_definition, 'to_pack_list', locals()['to_pack_list'])
    return vp_definition


__all__ = ['VariablePayload', 'vp_compile']
