from dataclasses import dataclass as ogdataclass
from functools import partial
from typing import List, Type, TypeVar, Union, cast, get_type_hints

from .lazy_payload import VariablePayload, vp_compile
from .serialization import Serializable


def type_from_format(fmt: str) -> TypeVar:
    """
    Convert a Serializer format directive to a type usable with @dataclass.
    """
    out = object.__new__(TypeVar)
    out.__init__(fmt)
    return out


def type_map(t: Type) -> Union[str, Serializable, List[Serializable]]:
    if t is bool:
        return "?"
    elif t is int:
        return "q"
    elif t is bytes:
        return "varlenH"
    elif t is str:
        return "varlenHutf8"
    elif isinstance(t, TypeVar):
        return t.__name__
    elif hasattr(t, '__origin__') and t.__origin__ in (tuple, list, set):
        return [t.__args__[0]]
    elif isinstance(t, (tuple, list, set)) or Serializable in t.mro():
        return cast(Serializable, t)
    else:
        raise NotImplementedError(t, " unknown")


def dataclass(cls=None, *, init=True, repr=True,  # pylint: disable=W0622
              eq=True, order=False, unsafe_hash=False, frozen=False, msg_id=None):
    """
    Equivalent to ``@dataclass``, but also makes the wrapped class a ``VariablePayload``.

    See ``dataclasses.dataclass`` for argument descriptions.
    """
    if cls is None:
        return partial(dataclass, init=init, repr=repr, eq=eq, order=order, unsafe_hash=unsafe_hash,
                       frozen=frozen, msg_id=msg_id)

    origin = ogdataclass(cls, init=init, repr=repr, eq=eq, order=order, unsafe_hash=unsafe_hash,
                         frozen=frozen)

    class DataClassPayload(origin, VariablePayload):
        names = list(get_type_hints(cls).keys())
        format_list = list(map(type_map, get_type_hints(cls).values()))

    if msg_id is not None:
        setattr(DataClassPayload, "msg_id", msg_id)
    DataClassPayload.__name__ = cls.__name__
    DataClassPayload.__qualname__ = cls.__qualname__
    return vp_compile(DataClassPayload)


def overwrite_dataclass(old_dataclass):
    """
    In order to get type hinting you have to do the following:

    .. code-block:: python

        from dataclasses import dataclass
        from ipv8.messaging.payload_dataclass import dataclass

    Linters don't like this. Instead, you can use this function to have a linter friendly alternative:

    .. code-block:: python

        from dataclasses import dataclass
        from ipv8.messaging.payload_dataclass import overwrite_dataclass

        dataclass = overwrite_dataclass(dataclass)

    :param old_dataclass: the dataclass.dataclass definition.
    :returns: the new dataclass definition
    """
    assert old_dataclass  # Though unused, we reference the variable to placate the linters.
    return dataclass


__all__ = ['overwrite_dataclass', 'type_from_format']
