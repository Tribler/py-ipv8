from __future__ import annotations

import dataclasses
import sys
from typing import Any, TypeVar, cast, get_args, get_type_hints

from typing_extensions import Self

from .lazy_payload import VariablePayload, VariablePayloadWID, vp_compile
from .serialization import FormatListType, Serializable


def type_from_format(fmt: str) -> TypeVar:
    """
    Convert a Serializer format directive to a type usable with @dataclass.
    """
    out = TypeVar.__new__(TypeVar, fmt)  # type: ignore[call-arg]
    TypeVar.__init__(out, fmt)
    return out


def type_map(t: type) -> FormatListType:  # noqa: PLR0911
    if t is bool:
        return "?"
    if t is int:
        return "q"
    if t is float:
        return "d"
    if t is bytes:
        return "varlenH"
    if t is str:
        return "varlenHutf8"
    if isinstance(t, TypeVar):
        return t.__name__
    if getattr(t, "__origin__", None) in (tuple, list, set):
        fmt = get_args(t)[0]
        if issubclass(fmt, Serializable):
            return [fmt]
        return f"arrayH-{type_map(fmt)}"
    if isinstance(t, (tuple, list, set)) or Serializable in getattr(t, "mro", list)():
        return cast("type[Serializable]", t)
    raise NotImplementedError(t, " unknown")


def convert_to_payload(dataclass_type: type, msg_id: int | None = None) -> None:
    if msg_id is not None:
        dataclass_type.msg_id = msg_id  # type: ignore[attr-defined]
    dt_fields = dataclasses.fields(dataclass_type)
    type_hints = get_type_hints(dataclass_type)
    dataclass_type.names = [field.name for field in dt_fields]  # type: ignore[attr-defined]
    dataclass_type.format_list = [type_map(type_hints[field.name]) for field in  # type: ignore[attr-defined]
                                  dt_fields]
    setattr(sys.modules[dataclass_type.__module__], dataclass_type.__name__, vp_compile(dataclass_type))


class DataClassPayload(VariablePayload):
    """
    A Payload that is defined as a dataclass.
    """

    def __class_getitem__(cls, item: int) -> DataClassPayloadWID:
        """
        Syntactic sugar to add a msg_id attribute into the class inheritance structure.

        |

        .. code-block::

            class MyPayload(DataClassPayload[12]):
                pass

            assert MyPayload().msg_id == 12

        :param item: The item to get, i.e., the message id
        """
        return cast("DataClassPayloadWID", type(cls.__name__, (DataClassPayloadWID, ), {"msg_id": item}))

    def __new__(cls, *args: Any, **kwargs) -> Self:  # noqa: ANN401, ARG004
        """
        Allocate memory for a new DataClassPayload class.
        """
        out = super().__new__(cls)
        convert_to_payload(cls)
        return out


class DataClassPayloadWID(VariablePayloadWID):
    """
    A Payload that is defined as a dataclass and has a message id [0, 255].
    """

    def __new__(cls, *args: Any, **kwargs) -> Self:  # noqa: ANN401, ARG004
        """
        Allocate memory for a new DataClassPayloadWID class.
        """
        out = super().__new__(cls)
        convert_to_payload(cls, msg_id=cls.msg_id)
        return out


__all__ = ["DataClassPayload", "type_from_format"]
