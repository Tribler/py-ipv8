from __future__ import annotations

from dataclasses import dataclass as ogdataclass
from functools import partial
from typing import Callable, Iterable, Type, TypeVar, cast, get_type_hints

from .lazy_payload import VariablePayload, vp_compile
from .serialization import FormatListType, Serializable


def type_from_format(fmt: str) -> TypeVar:
    """
    Convert a Serializer format directive to a type usable with @dataclass.
    """
    out = object.__new__(TypeVar)
    TypeVar.__init__(out, fmt)
    return out


def type_map(t: Type) -> FormatListType:
    if t is bool:
        return "?"
    if t is int:
        return "q"
    if t is bytes:
        return "varlenH"
    if t is str:
        return "varlenHutf8"
    if isinstance(t, TypeVar):
        return t.__name__
    if getattr(t, '__origin__', None) in (tuple, list, set):
        return [t.__args__[0]]
    if isinstance(t, (tuple, list, set)) or Serializable in getattr(t, "mro", list)():
        return cast(Type[Serializable], t)
    raise NotImplementedError(t, " unknown")

def dataclass(cls: type | None = None, *,  # noqa: PLR0913
              init: bool = True,
              repr: bool = True,  # noqa: A002
              eq: bool = True,
              order: bool = False,
              unsafe_hash: bool = False,
              frozen: bool = False,
              msg_id: int | None = None) -> partial[Type[VariablePayload]] | Type[VariablePayload]:
    """
    Equivalent to ``@dataclass``, but also makes the wrapped class a ``VariablePayload``.

    See ``dataclasses.dataclass`` for argument descriptions.
    """
    if cls is None:
        # Forward user parameters. Format: ``@dataclass(foo=bar)``.
        return partial(cast(Callable[..., Type[VariablePayload]], dataclass), init=init, repr=repr, eq=eq, order=order,
                       unsafe_hash=unsafe_hash, frozen=frozen, msg_id=msg_id)

    # Finally, we have the actual class. Format: ``@dataclass`` or forwarded from partial (see above).
    origin: type = ogdataclass(cls, init=init, repr=repr, eq=eq, order=order,  # type: ignore[call-overload]
                               unsafe_hash=unsafe_hash, frozen=frozen)

    class DataClassPayload(origin, VariablePayload):
        names = list(get_type_hints(cls).keys())
        format_list = list(map(type_map, cast(Iterable[type], get_type_hints(cls).values())))

    if msg_id is not None:
        setattr(DataClassPayload, "msg_id", msg_id)  # noqa: B010
    DataClassPayload.__name__ = cls.__name__
    DataClassPayload.__qualname__ = cls.__qualname__
    return vp_compile(DataClassPayload)


def overwrite_dataclass(old_dataclass):  # noqa: ANN001, ANN201
    """
    Overwrite the dataclass function.

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
