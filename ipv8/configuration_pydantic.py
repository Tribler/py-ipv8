"""
Pydantic configuration BaseModels for IPv8.

If you want to see the available configuration options, print the schema as follows:

::

        from json import dumps
        print(dumps(format_schema_recursive(IPv8Configuration), indent=4))

|
You can use the ``IPv8Configuration by simply passing it to an ``IPv8`` constructor:

::

        ipv8_instance = IPv8(IPv8Configuration())

"""

import base64
import inspect
import sys
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Type, Union

from pydantic import BaseModel, Field, validator
from pydantic.validators import dict_validator

from .configuration import DISPERSY_BOOTSTRAPPER, default
from .keyvault.crypto import default_eccrypto


class AbstractModel:
    """
    Mixin to disallow a model to be instantiated directly.

    This construct is useful for DRY configurations that instantiate objects in some inheritance structure.
    For example, a ``DuckType`` is not a bird but a ``Pigeon`` and a ``Crow`` are (though they both quack)
    and this can be reflected when making birds (``make_bird``) by configuration:

    |

    ::

        @dataclass
        class DuckType(ABC):  # Abstract: a DuckType is not a bird, it just quacks
            quacks_per_second: int

        @dataclass
        class Pigeon(DuckType):
            in_flock: bool  # A group of pigeons is called a flock, not a murder

        @dataclass
        class Crow(DuckType):
            in_murder: bool  # A group of crows is called a murder, not a flock

        class DuckTypeConfig(BaseModel, AbstractModel):
            quacks_per_second: int

        class PigeonConfig(DuckTypeConfig):
            in_flock: bool

        class CrowConfig(DuckTypeConfig):
            in_murder: bool

        def make_bird(bird_config: DuckTypeConfig) -> Optional[DuckType]:
            '''
            Our composable architecture needs something that quacks per second.
            The user registers implementations:

            composable_architecture.register(Crow)
            composable_architecture.register(Pigeon)
            etc.

            We don't need defensive programming in the composable_architecture
            if the user can't make a DuckTypeConfig in the first place!
            '''
            return composable_architecture.get_implementer(bird_config)

    :returns: The mixin for pydantic BaseModel subclasses.
    """

    def __new__(cls, *args, **kwargs):
        """
        If mixed-in to ``check`` the MRO is [child 1 .. n, check, .. non-AbstractModel .., AbstractModel, object]
        If there are no children this becomes [check, .. non-AbstractModel .., AbstractModel, object]
        """
        check = cls.mro()[1:2] or [object]  # Still works if the mro is empty
        if not issubclass(check[0], AbstractModel) and check is not AbstractModel:
            # Try to give the caller some hints.
            parent_module = sys.modules[cls.__module__]
            possibilities = [cname for cname, cinstance in inspect.getmembers(parent_module)
                             if inspect.isclass(cinstance) and cname != "AbstractModel"
                             and issubclass(cinstance, cls) and cinstance is not cls]
            raise NotImplementedError(f"{cls} is an abstract model and must be implemented by a subclass! "
                                      + (f"Perhaps you want one of these: {possibilities}?" if possibilities else ""))
        return super().__new__(cls)


class BaseConfigurationClass(BaseModel):
    """
    Augment the ``BaseModel`` class with 1) dict cast unwrapping and 2) inherited validators.
    """

    def __iter__(self, *args, **kwargs):
        """
        Make ``dict(model)`` equal to ``model.dict()``.

        Normally this function only only gives the child model references instead of unwrapping them.
        """
        return iter(self.dict().items())

    @classmethod
    def get_validators(cls):
        yield cls.validate

    @classmethod
    def validate(cls, value):
        if isinstance(value, cls):
            return value
        else:
            return cls(**dict_validator(value))

    def dict(self, *args, **kwargs):
        kwargs['by_alias'] = True
        return super().dict(*args, **kwargs)

    class Config:
        allow_population_by_field_name = True


class BootstrapperInit(BaseConfigurationClass, AbstractModel):
    pass


class UDPBroadcastBootstrapperInit(BootstrapperInit):
    bootstrap_timeout: float = 30.0


class DispersyBootstrapperInit(BootstrapperInit):
    ip_addresses: Optional[List[tuple]] = None
    dns_addresses: Optional[List[tuple]] = None
    bootstrap_timeout: float = 30.0

    @validator('ip_addresses', always=True)
    @classmethod
    def _default_ip_addresses(cls, v):
        return DISPERSY_BOOTSTRAPPER['init']['ip_addresses'] if v is None else v

    @validator('dns_addresses', always=True)
    @classmethod
    def _default_dns_addresses(cls, v):
        return DISPERSY_BOOTSTRAPPER['init']['dns_addresses'] if v is None else v


class Bootstrapper(BaseConfigurationClass, AbstractModel):
    cls: str = Field(alias='class')
    init: BootstrapperInit = Field(..., arbitrary_types_allowed=True)


class DispersyBootstrapper(Bootstrapper):

    def __init__(self, **kwargs):
        kwargs["class"] = "DispersyBootstrapper"
        super().__init__(**kwargs)


class UDPBroadcastBootstrapper(Bootstrapper):

    def __init__(self, **kwargs):
        kwargs["class"] = "UDPBroadcastBootstrapper"
        super().__init__(**kwargs)


class Interface(BaseConfigurationClass):
    interface: str = default["interfaces"][0]["interface"]
    ip: str = default["interfaces"][0]["ip"]
    port: int = default["interfaces"][0]["port"]


class Logger(BaseConfigurationClass):
    level: str = default["logger"]["level"]

    @validator("level", always=True)
    @classmethod
    def validate_level(cls, v):
        allowed = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'NOTSET']
        assert v in allowed, f"Illegal log level {v} specified! Should be one of {allowed}!"
        return v


class Key(BaseConfigurationClass, AbstractModel):
    alias: str = default["keys"][0]["alias"]


class PreloadedKey(Key):
    bin: str


def generate_ephemeral_key():
    return base64.b64encode(default_eccrypto.generate_key("curve25519").key_to_bin()).decode()


class EphemeralKey(Key):
    bin: str = Field(frozen=True, default_factory=generate_ephemeral_key)


class FileKey(Key):
    generation: str = default["keys"][0]["generation"]
    file: str = default["keys"][0]["file"]


class Walker(BaseConfigurationClass, AbstractModel):
    strategy: str = Field(...)
    peers: int = 20
    init: dict = Field(default_factory=dict)

    @validator("peers", always=True)
    @classmethod
    def validate_peer_count(cls, v):
        assert v >= 0 or v == -1, f"A walker's peer count must be >= 0 or set to -1 (infinite), got: {v}!"
        return v


class RandomWalk(Walker):
    def __init__(self, **kwargs):
        kwargs["strategy"] = "RandomWalk"
        if "init" not in kwargs:
            kwargs["init"] = {"timeout": 3.0}
        super().__init__(**kwargs)


class EdgeWalk(Walker):
    def __init__(self, **kwargs):
        kwargs["strategy"] = "EdgeWalk"
        super().__init__(**kwargs)


class RandomChurn(Walker):
    def __init__(self, **kwargs):
        kwargs["strategy"] = "RandomChurn"
        if "peers" not in kwargs:
            kwargs["peers"] = -1
        if "init" not in kwargs:
            kwargs["init"] = {'sample_size': 8, 'ping_interval': 10.0, 'inactive_time': 27.5, 'drop_time': 57.5}
        super().__init__(**kwargs)


class PeriodicSimilarity(Walker):
    def __init__(self, **kwargs):
        kwargs["strategy"] = "PeriodicSimilarity"
        if "peers" not in kwargs:
            kwargs["peers"] = -1
        super().__init__(**kwargs)


class PingChurn(Walker):
    def __init__(self, **kwargs):
        kwargs["strategy"] = "PingChurn"
        if "peers" not in kwargs:
            kwargs["peers"] = -1
        super().__init__(**kwargs)


class Overlay(BaseConfigurationClass):
    cls: str = Field(alias='class')
    key: str = default["keys"][0]["alias"]
    walkers: List[Walker] = [RandomWalk()]
    bootstrappers: List[Bootstrapper] = [DispersyBootstrapper(init=DispersyBootstrapperInit())]
    initialize: dict = Field(default_factory=dict)
    on_start: List[tuple] = []


class IPv8Configuration(BaseConfigurationClass):
    """
    Main pydantic IPv8 configuration model, can be fed directly into the ``IPv8`` class constructor.
    """
    interfaces: List[Interface] = [Interface()]
    key_aliases: List[Key] = Field([FileKey()], alias="keys")
    logger: Logger = Logger()
    working_directory: str = default["working_directory"]
    walker_interval: float = default["walker_interval"]
    overlays: List[Overlay] = [
        Overlay(cls="DiscoveryCommunity", walkers=[RandomWalk(), RandomChurn(), PeriodicSimilarity()]),
        Overlay(cls="HiddenTunnelCommunity", initialize=default["overlays"][1]["initialize"],
                on_start=default["overlays"][1]["on_start"]),
        Overlay(cls="DHTDiscoveryCommunity", walkers=[RandomWalk(), PingChurn()])
    ]

    @validator("interfaces", always=True)
    @classmethod
    def validate_interfaces(cls, v):
        it_names = [spec.interface for spec in v]
        assert len(v) == len(set(it_names)), f"Duplicate interface names specified: {', '.join(it_names)}!"
        return v


def format_schema_recursive(*base_models: Type[BaseModel]) -> dict:
    """
    Create a schema (``dict``) describing a BaseModel class.

    |
    For example, the following pretty-prints the schema of ``IPv8Configuration``:

    ::

        from json import dumps
        print(dumps(format_schema_recursive(IPv8Configuration), indent=4))

    |
    Note that the schema shows the expected interface, which is not necessarily equal to its implementations!
    For example, only ``A`` and ``Main`` are shown when calling ``format_schema_recursive(Main)`` using this code:

    ::

        class A(BaseModel):
            property: number

        class B(A):
            property2: number

        class Main(BaseModel):
            a_implementation: A

    In the above example, you could force generation for ``B`` by calling ``format_schema_recursive(Main, B)``.

    :param base_models: the models to generate the schema for
    :returns: the mapping of types for the given collection of base models
    """
    def format_schema_single(model_schema: dict, refs: set) -> Union[dict, list, str]:
        """
        Try to convert the types given by pydantic into actual Python objects. Turns objects into dicts, arrays into
        lists, custom definitions into their BaseModel class names, and keeps whatever other primitive is used.

        Note: this function is recursive!

        :param model_schema: the result of ``<BaseModel>.schema()``
        :param refs: a reference to a set in which to add encountered references
        :returns: either a dict describing the schema or a str describing a single primitive type
        """
        properties: Union[str, List[Any], Dict[Any, Any]]
        if "type" in model_schema:
            is_object = model_schema["type"] in ["object", "array"]
            name = model_schema["title"] if is_object else model_schema["type"]
            if "properties" in model_schema:
                # It's a dict!
                properties = {k: format_schema_single(v, refs) for k, v in model_schema["properties"].items()}
            elif "items" in model_schema:
                # It's a list!
                if '$ref' in model_schema['items']:
                    properties = [model_schema['items']['$ref']]
                    refs.add(model_schema['items']['$ref'])
                else:
                    # It's an empty list!
                    properties = []
            elif is_object:
                # It's an empty dict!
                properties = {}
            else:
                # It's a "none of the above or below" (number, string, etc.)!
                return f"{name.lower()}"
        else:
            # It's a custom definition!
            if '$ref' in model_schema:
                properties = model_schema["$ref"]
                refs.add(model_schema["$ref"])
            elif len(model_schema["allOf"]) == 1:
                properties = model_schema["allOf"][0]["$ref"]
                refs.add(model_schema["allOf"][0]["$ref"])
            else:
                properties = []
                for m in model_schema["allOf"]:
                    properties.append(m["$ref"])
                    refs.add(m["$ref"])
        return properties

    finished_refs: Set[str] = set()
    known_refs = {f"#/definitions/{base_model.__name__}" for base_model in base_models}
    out = {}
    while len(finished_refs) != len(known_refs):
        # 1. Fetch the Python class "model" belonging to the (str) definition name
        next_ref = list(known_refs - finished_refs)[0]
        assert next_ref.startswith("#/definitions/")
        clsname = next_ref[14:]
        model = None
        if clsname in globals():
            # Easy: the class has already been imported.
            model = globals()[clsname]
        else:
            # Hard: we need to find the class definition in the loaded modules.
            for module in sys.modules:
                if clsname in dir(sys.modules[module]):
                    model = getattr(sys.modules[module], clsname)
                    break
            # Extra hard: it is still possible to make exotic definitions that escape this search.
            #             We'll just let the caller manually work around this (e.g., by adding the class to globals).
        assert model is not None, f"Failed to locate class belonging to {next_ref}!"
        # 2. Format the model class into a dict
        out[model.__name__] = ({i.name: i.value for i in model} if issubclass(model, Enum)
                               else format_schema_single(model.schema(), known_refs))
        finished_refs.add(next_ref)
    return out
