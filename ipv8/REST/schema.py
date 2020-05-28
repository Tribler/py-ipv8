from marshmallow import Schema
from marshmallow.fields import Boolean, Integer, List, Nested, String
from marshmallow.schema import SchemaMeta


class DefaultResponseSchema(Schema):
    success = Boolean(description='Indicator of success/failure', required=True)
    error = String(description='Optional field describing any failures that may have occurred', required=False)


class TransactionSchema(Schema):
    down = Integer()
    total_down = Integer()
    up = Integer()
    total_up = Integer()


class BlockSchema(Schema):
    transaction = Nested(TransactionSchema)
    linked = Nested('BlockSchema')
    type = String()
    tx = String()
    public_key = String()
    sequence_number = Integer()
    link_public_key = String()
    link_sequence_number = Integer()
    previous_hash = String()
    signature = String()
    insert_time = String()
    block_timestamp = Integer()
    block_hash = String()


class OverlayStatisticsSchema(Schema):
    num_up = Integer()
    num_down = Integer()
    bytes_up = Integer()
    bytes_down = Integer()
    diff_time = Integer()


class OverlaySchema(Schema):
    master_peer = String()
    my_peer = String()
    global_time = Integer()
    peers = List(String)
    overlay_name = String()
    statistics = Nested(OverlayStatisticsSchema)


class DHTValueSchema(Schema):
    public_key = String()
    key = String()
    value = String()


def schema(**kwargs):
    """
    Create a schema. Mostly useful for creating single-use schemas on-the-fly.
    """
    items = list(kwargs.items())
    if len(items) != 1 or not isinstance(items[0][1], dict):
        raise RuntimeError('schema required 1 keyword argument of type dict')
    name, spec = items[0]

    schema_dict = {}
    for key, value in spec.items():
        cls, description = value if isinstance(value, tuple) else (value, None)
        required = key.endswith('*')
        key = key.rstrip('*')
        kwargs = {'required': required, 'description': description}

        if isinstance(cls, SchemaMeta):
            schema_dict[key] = Nested(cls, required=required)
        elif isinstance(cls, list) and len(cls) == 1:
            cls = cls[0]
            schema_dict[key] = List(Nested(cls), **kwargs) if isinstance(cls, SchemaMeta) else List(cls, **kwargs)
        else:
            schema_dict[key] = cls.__call__(**kwargs) if callable(cls) else cls
    return type(name, (Schema,), schema_dict)
