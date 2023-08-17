from __future__ import annotations

from typing import cast

from marshmallow import Schema
from marshmallow.base import SchemaABC
from marshmallow.fields import Boolean, Integer, List, Nested, String
from marshmallow.schema import SchemaMeta


class DefaultResponseSchema(Schema):
    """
    Every response contains its sucess status and optionally the error that occurred.
    """

    success = Boolean(description='Indicator of success/failure', required=True)
    error = String(description='Optional field describing any failures that may have occurred', required=False)


class Address(Schema):
    """
    The schema for address information.
    """

    ip = String()
    port = Integer()


class AddressWithPK(Address):
    """
    The schema for addresses that have a public key.
    """

    public_key = String()


class OverlayStatisticsSchema(Schema):
    """
    The schema for overlay statistics.
    """

    num_up = Integer()
    num_down = Integer()
    bytes_up = Integer()
    bytes_down = Integer()
    diff_time = Integer()


class OverlayStrategySchema(Schema):
    """
    The schema describing discovery strategies for overlays.
    """

    name = String()
    target_peers = Integer()


class OverlaySchema(Schema):
    """
    The schema to describe overlays.
    """

    id = String()  # noqa: A003
    my_peer = String()
    global_time = Integer()
    peers = List(Nested(cast(SchemaABC, AddressWithPK)))
    overlay_name = String()
    max_peers = Integer()
    is_isolated = Boolean()
    my_estimated_wan = Nested(cast(SchemaABC, Address))
    my_estimated_lan = Nested(cast(SchemaABC, Address))
    strategies = List(Nested(cast(SchemaABC, OverlayStrategySchema)))
    statistics = Nested(cast(SchemaABC, OverlayStatisticsSchema))


class DHTValueSchema(Schema):
    """
    The schema to describe values in the DHT.
    """

    public_key = String()
    key = String()
    value = String()


def schema(**kwargs) -> Schema:
    """
    Create a schema. Mostly useful for creating single-use schemas on-the-fly.
    """
    items = list(kwargs.items())
    if len(items) != 1 or not isinstance(items[0][1], dict):
        msg = "schema required 1 keyword argument of type dict"
        raise RuntimeError(msg)
    name, spec = items[0]

    schema_dict: dict[str, Nested | List] = {}
    for key, value in spec.items():
        cls, description = value if isinstance(value, tuple) else (value, None)
        required = key.endswith('*')
        key = key.rstrip('*')  # noqa: PLW2901
        kwargs = {'required': required, 'description': description}

        if isinstance(cls, SchemaMeta):
            schema_dict[key] = Nested(cast(SchemaABC, cls), required=required)
        elif isinstance(cls, list) and len(cls) == 1:
            cls = cls[0]
            schema_dict[key] = List(Nested(cast(SchemaABC, cls)), **kwargs) if isinstance(cls, SchemaMeta) else List(cls, **kwargs)
        else:
            schema_dict[key] = cls.__call__(**kwargs) if callable(cls) else cls
    return cast(Schema, type(name, (Schema,), schema_dict))
