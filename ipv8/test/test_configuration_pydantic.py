import base64
import enum
import importlib
import unittest

from .base import TestBase
from ..configuration import default

try:
    importlib.import_module("pydantic")

    SKIP_TEST_CASE = False
except ImportError:
    SKIP_TEST_CASE = True
else:
    from ..configuration_pydantic import (BaseConfigurationClass, Bootstrapper, BootstrapperInit, DispersyBootstrapper,
                                          DispersyBootstrapperInit, EdgeWalk, EphemeralKey, FileKey, IPv8Configuration,
                                          Interface, Key, Overlay, PeriodicSimilarity, PingChurn, PreloadedKey,
                                          RandomChurn, RandomWalk, UDPBroadcastBootstrapper,
                                          UDPBroadcastBootstrapperInit, Walker, format_schema_recursive)


class CustomColor(enum.Enum):
    """
    Note ``Color`` is an illegal name and will be overwritten by pydantic!
    """
    RED = 1
    GREEN = 2
    BLUE = 3


@unittest.skipIf(SKIP_TEST_CASE, "Skipping optional pydantic tests because the library is not installed.")
class TestConfigurationPydantic(TestBase):
    """
    Tests to check IPv8 pydantic integration.

    Note that this TestCase tests IPv8<->pydantic integration, not if pydantic works as promised.
    """
    FAKE_KEY_BIN = base64.b64encode(b"0" * 74).decode()

    def test_abstract_key(self):
        """
        Check if ``Key`` models are not allowed to be instantiated.
        """
        self.assertRaises(NotImplementedError, Key)
        self.assertRaises(NotImplementedError, Key, alias="keyname")

    def test_implemented_keys(self):
        """
        Check if the child classes of ``Key`` are allowed to be instantiated.
        """
        keys = [
            EphemeralKey(),
            PreloadedKey(bin=TestConfigurationPydantic.FAKE_KEY_BIN),
            FileKey()
        ]

        for key in keys:
            self.assertIsInstance(key, Key)

    def test_inherit_field_keys(self):
        """
        Check if the child classes of ``Key`` inherit the ABC's fields.
        """
        named_keys = [
            EphemeralKey(alias="keyname"),
            PreloadedKey(alias="keyname", bin=TestConfigurationPydantic.FAKE_KEY_BIN),
            FileKey(alias="keyname")
        ]

        for key in named_keys:
            self.assertEqual("keyname", key.alias)

    def test_abstract_walker(self):
        """
        Check if ``Walker`` models are not allowed to be instantiated.
        """
        self.assertRaises(NotImplementedError, Walker)
        self.assertRaises(NotImplementedError, Walker, strategy="strategyname")

    def test_implemented_walkers(self):
        """
        Check if the child classes of ``Walker`` are allowed to be instantiated.
        """
        walkers = [
            RandomWalk(),
            EdgeWalk(),
            RandomChurn(),
            PeriodicSimilarity(),
            PingChurn()
        ]

        for walker in walkers:
            self.assertIsInstance(walker, Walker)

    def test_inherit_field_walkers(self):
        """
        Check if the child classes of ``Walker`` inherit the ABC's fields.
        """
        walkers_peers = [
            RandomWalk(peers=42),
            EdgeWalk(peers=42),
            RandomChurn(peers=42),
            PeriodicSimilarity(peers=42),
            PingChurn(peers=42)
        ]

        for walker in walkers_peers:
            self.assertEqual(42, walker.peers)
            self.assertEqual(walker.__class__.__name__, walker.strategy)

    def test_abstract_bootstrapper(self):
        """
        Check if ``Bootstrapper`` models are not allowed to be instantiated.
        """
        self.assertRaises(NotImplementedError, Bootstrapper)
        self.assertRaises(NotImplementedError, Bootstrapper, kwargs={"class": "boostrappername", "init": {}})

    def test_implemented_bootstrappers(self):
        """
        Check if the child classes of ``Bootstrapper`` are allowed to be instantiated.
        """
        bootstrappers = [
            DispersyBootstrapper(init=DispersyBootstrapperInit()),
            UDPBroadcastBootstrapper(init=UDPBroadcastBootstrapperInit())
        ]

        for bootstrapper in bootstrappers:
            self.assertIsInstance(bootstrapper, Bootstrapper)

    def test_inherit_field_bootstrappers(self):
        """
        Check if the child classes of ``Bootstrapper`` inherit the ABC's fields.
        """
        bootstrappers = [
            DispersyBootstrapper(init=DispersyBootstrapperInit()),
            UDPBroadcastBootstrapper(init=UDPBroadcastBootstrapperInit())
        ]

        for bootstrapper in bootstrappers:
            self.assertEqual(bootstrapper.__class__.__name__, bootstrapper.cls)

    def test_abstract_bootstrapper_init(self):
        """
        Check if ``BootstrapperInit`` models are not allowed to be instantiated.
        """
        self.assertRaises(NotImplementedError, BootstrapperInit)

    def test_default_dict_direct(self):
        """
        Check if directly calling the ``dict()`` method on the base model returns the default dict.
        """
        self.assertDictEqual(default, IPv8Configuration().dict())

    def test_default_dict_cast(self):
        """
        Check if casting the base model to ``dict`` returns the default dict.
        """
        self.assertDictEqual(default, dict(IPv8Configuration()))

    def test_format_schema_single(self):
        """
        Check if the schema for a single BaseModel is correctly generated.
        """
        expected = {
            "Interface": {
                "interface": "string",
                "ip": "string",
                "port": "integer"
            }
        }
        self.assertDictEqual(expected, format_schema_recursive(Interface))

    def test_format_schema_double(self):
        """
        Check if the schema for two BaseModels is correctly generated.
        """
        expected = {
            "Interface": {
                "interface": "string",
                "ip": "string",
                "port": "integer"
            },
            "Key": {
                "alias": "string"
            }
        }
        self.assertDictEqual(expected, format_schema_recursive(Interface, Key))

    def test_format_schema_abstract(self):
        """
        Check if the schema for a single BaseModel that inherits from an ABC is correctly generated.
        """
        expected = {
            "FileKey": {
                "alias": "string",  # Inherited from Key, not defined in FileKey itself
                "generation": "string",
                "file": "string"
            }
        }
        self.assertDictEqual(expected, format_schema_recursive(FileKey))

    def test_format_schema_nested(self):
        """
        Check if the schema for a single BaseModel that nests another BaseModel is correctly generated.
        """
        expected = {
            "UDPBroadcastBootstrapper": {
                "class": "string",
                "init": "#/definitions/BootstrapperInit"
            },
            "BootstrapperInit": {}
        }
        self.assertDictEqual(expected, format_schema_recursive(UDPBroadcastBootstrapper))

    def test_format_schema_nested_list(self):
        """
        Check if the schema for a single BaseModel that nests a list of other BaseModels is correctly generated.
        """
        expected = {
            "BootstrapperInit": {},
            "Bootstrapper": {"class": "string", "init": "#/definitions/BootstrapperInit"},  # test_format_schema_nested
            "Walker": {"init": {}, "peers": "integer", "strategy": "string"},
            "Overlay": {
                "bootstrappers": ["#/definitions/Bootstrapper"],  # List of nested BaseModels
                "class": "string",
                "initialize": {},
                "key": "string",
                "on_start": [],
                "walkers": ["#/definitions/Walker"]  # List of nested BaseModels
            }
        }
        self.assertDictEqual(expected, format_schema_recursive(Overlay))

    def test_format_schema_enum(self):
        """
        Check if schemas for Enums (also allowed inside of pydantic BaseModels) are correctly generated.

        Note: we don't want to perform pydantic imports in this module, so we perform some `globals()` magic instead.
        """
        class MockEnumModel(BaseConfigurationClass):
            color: CustomColor
        globals()["MockEnumModel"] = MockEnumModel

        expected = {
            "MockEnumModel": {"color": "#/definitions/CustomColor"},
            "CustomColor": {
                "RED": 1,
                "GREEN": 2,
                "BLUE": 3
            }
        }
        self.assertDictEqual(expected, format_schema_recursive(MockEnumModel))
