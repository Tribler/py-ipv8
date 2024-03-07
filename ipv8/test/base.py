from __future__ import annotations

import inspect
import os
import shutil
import sys
import threading
import time
import unittest
import uuid
from asyncio import AbstractEventLoop, Task, all_tasks, ensure_future, get_running_loop, iscoroutine, sleep
from contextlib import contextmanager
from functools import partial
from typing import TYPE_CHECKING, Awaitable, Callable, Coroutine, Generic, Type, TypeVar, cast

from ..lazy_community import PacketDecodingError, lazy_wrapper, lazy_wrapper_unsigned
from ..messaging.interfaces.lan_addresses.interfaces import get_providers
from ..messaging.serialization import PackError
from ..overlay import Overlay
from ..peer import Peer
from ..types import Community, Payload
from .mocking.endpoint import MockEndpointListener, internet
from .mocking.ipv8 import MockIPv8

if TYPE_CHECKING:
    from ..community import CommunitySettings
    from ..peerdiscovery.network import Network
    from ..types import Address, Endpoint, PrivateKey, PublicKey


def _on_packet_fragile_cb(self: Community, packet: tuple[Address, bytes], warn_unknown: bool = True) -> None:
    """
    A fragile version of on_packet that crashes on message handling failures.

    These failures won't actually cause IPv8 to crash in production, but you should probably handle these.

    Add overlay classes to use in production mode to the ``production_overlay_classes`` list.
    Filter nodes to run in production mode by overwriting ``TestBase.patch_overlays``.
    """
    result = self.decode_map[packet[1][22]](*packet)
    if iscoroutine(result):
        aw_result = cast(Awaitable, result)
        self.register_anonymous_task('on_packet', ensure_future(aw_result))


class TranslatedMockEndpointListener(MockEndpointListener):
    """
    Automagically translate received packets into messages.

    The magic depends on three assumptions:
     - The requested overlay messages have a ``msg_id`` specified.
     - The requested overlay messages can be decoded using a single ``Payload``.
     - The requested overlay messages follow the ``lazy_wrapper_*`` standard.
    """

    def __init__(self, overlay: Community, message_classes: list[type[Payload]],
                 message_filter: list[type[Payload]] | None, main_thread: bool = False) -> None:
        """
        Create a new TranslatedMockEndpointListener.
        """
        super().__init__(overlay.endpoint, main_thread)

        self.overlay = overlay
        self.message_class_map = {}
        self.message_filter_set = set()

        for message_class in message_classes:
            assert hasattr(message_class, "msg_id"), "assertReceivedBy only works with Payloads that have a msg_id!"
            self.message_class_map[message_class.msg_id] = message_class

        for message_class in (message_filter or []):
            assert hasattr(message_class, "msg_id"), "assertReceivedBy can only filter Payloads that have a msg_id!"
            self.message_filter_set.add(message_class.msg_id)

        self.received_messages = []

    def on_packet(self, packet: tuple[Address, bytes]) -> None:
        """
        Callback for when a new packet is received by an endpoint.
        """
        super().on_packet(packet)

        msg_id = packet[1][len(self.overlay.get_prefix()):][0]

        # If we have a filter: ignore messages that are not part of the filter.
        if self.message_filter_set and (msg_id not in self.message_filter_set):
            return

        # Fetch the Payload class we are decoding into.
        requested_class = self.message_class_map.get(msg_id)
        assert requested_class is not None, f"assertReceivedBy received message with unknown id {msg_id}!"

        # Create a fake message handler.
        def trap(_: Community, sender: Peer, *payloads: Payload) -> None:
            trap.sender = sender
            trap.payloads = payloads
        trap.sender = None
        trap.payloads = []

        # Feed messages into the overlay's decoding map. We don't know if it's supposed to be signed or unsigned.
        # We are assuming these messages are lazy_wrapper_* compatible.
        try:
            # Try signed first, as this is a stricter subset.
            lazy_wrapper(requested_class)(trap)(self.overlay, *packet)
        except Exception:  # Not limited to PackError, PacketDecodingError but can also be random crypto errors.
            try:
                lazy_wrapper_unsigned(requested_class)(trap)(self.overlay, *packet)
            except (PackError, PacketDecodingError) as e:
                msg = (f"Failed to decode message with id {msg_id}! "
                       "Check if TranslatedMockEndpointListener's assumptions fit your messages, doc:\n"
                       f"\"\"\"{TranslatedMockEndpointListener.__doc__}\"\"\"")
                raise AssertionError(msg) from e

        # Finally, we have a decoded payload :-)
        self.received_messages += list(trap.payloads)


if sys.version_info[0] == 3 and sys.version_info[1] <= 7:  # noqa: YTT201, YTT203
    # unittest.IsolatedAsyncioTestCase does not exist below Python 3.8, use asynctest instead
    import asynctest
    TestCaseClass = asynctest.TestCase
    USE_ASYNC_TEST = True
else:
    TestCaseClass = unittest.IsolatedAsyncioTestCase
    USE_ASYNC_TEST = False

OT = TypeVar("OT", bound=Overlay)


class TestBase(TestCaseClass, Generic[OT]):
    """
    Base TestCase to allow easy testing of IPv8 overlays.
    """

    __testing__ = True
    __lockup_timestamp__ = 0
    __asynctest_compatibility_mode__ = USE_ASYNC_TEST

    # The time after which the whole test suite is os.exited
    MAX_TEST_TIME = 10

    def __init__(self, methodName: str = 'runTest') -> None:  # noqa: N803
        """
        Create a new base test class to manage test nodes, connections, overlays and temporary files.
        """
        super().__init__(methodName)
        self.nodes = []
        self.overlay_class: type[OT] | None = None
        internet.clear()
        self._tempdirs = []
        self.production_overlay_classes = []
        self._uncaught_async_failure = None

    @property
    def __loop(self) -> AbstractEventLoop:
        """
        Return the asyncio event loop used for the test case.
        """
        if hasattr(self, "_asyncioTestLoop"):
            # Python 3.8, 3.9, and 3.10.
            return self._asyncioTestLoop
        # Python 3.11 (and up?).
        return self._asyncioRunner.get_loop()

    loop = getattr(TestCaseClass, "loop", __loop)

    def __call_internal_in_context(self, func: Callable | Coroutine) -> None:
        """
        Call setUp or tearDown within the unittest.IsolatedAsyncioTestCase context.

        This is not used for asynctest compatibility mode.
        """
        if hasattr(self, "_asyncioTestContext"):
            # Python 3.11 (and up?).
            self._asyncioTestContext.run(func)
        else:
            # Python 3.8, 3.9, and 3.10.
            self._callTestMethod(func)

    def _callSetUp(self) -> None:  # noqa: N802
        # In Python 3.11+ this function has side effects:
        self.loop  # noqa: B018
        if inspect.iscoroutinefunction(self.setUp):
            self._callAsync(self.setUp)
        else:
            self.__call_internal_in_context(self.setUp)

    def _callTearDown(self) -> None:  # noqa: N802
        if inspect.iscoroutinefunction(self.tearDown):
            self._callAsync(self.tearDown)
        else:
            self.__call_internal_in_context(self.tearDown)

    def initialize(self, overlay_class: type[Community], node_count: int, settings: CommunitySettings | None = None,
                   create_dht: bool = False, enable_statistics: bool = False) -> None:
        """
        Spawn a given number of nodes with a particular overlay class and introduce them to each other.

        WARNING: Peers are directly added into each other's Network. This skips sending messages (efficient!).
                 HOWEVER, custom logic based on introduction requests and responses may therefore be skipped.
        """
        self.overlay_class = overlay_class
        self.nodes = [self.create_node(settings, create_dht, enable_statistics) for _ in range(node_count)]

        # Add nodes to each other.
        for node in self.nodes:
            for other in self.nodes:
                if other == node:
                    continue
                private_peer = other.my_peer
                public_peer = Peer(private_peer.public_key, private_peer.address)
                node.network.add_verified_peer(public_peer)
                node.network.discover_services(public_peer, [overlay_class.community_id])

        # Make packet handling fragile.
        for i in range(len(self.nodes)):
            self.patch_overlays(i)

    def _patch_overlay(self, overlay: Overlay) -> None:
        """
        Perform patches on an overlay for testing purposes.

        By default, this patches out the general try-except in the packet handler, allowing crashes.
        """
        if overlay and overlay.__class__ not in self.production_overlay_classes:
            overlay.on_packet = partial(_on_packet_fragile_cb, overlay)

    def patch_overlays(self, i: int) -> None:
        """
        Method to make the packet handlers of a particular node fragile.

        If you want to disable fragile packet handling for an entire class over overlays, add the class to the
        production_overlay_classes list.

        If you want to disable fragile packet handling for a particular node, overwrite this method.
        """
        self._patch_overlay(self.node(i).overlay)
        self._patch_overlay(self.node(i).dht)
        for overlay in self.node(i).overlays:
            self._patch_overlay(overlay)

    def _cb_exception(self, loop: AbstractEventLoop, context: dict) -> None:
        """
        Callback for asyncio exceptions.

        Do not call `self.fail` or `pytest.fail` or any other failure mechanism in here.
        These methods work by raising an Exception, which will silently fail as this is not the main loop.
        """
        # Only fail on the first failure, to not cause exception shadowing on compound errors.
        if self._uncaught_async_failure is None:
            self._uncaught_async_failure = context

    def setUp(self) -> None:
        """
        Perform the base setup per unit test. Always call this before running your own setUp code!
        """
        self.loop.set_debug(True)
        self.loop.set_exception_handler(self._cb_exception)
        get_providers().clear()
        super().setUp()
        TestBase.__lockup_timestamp__ = time.time()

    async def tearDown(self) -> None:
        """
        Tear down all the overlays, remove all files and check if any errors "escaped" the unit test scope.
        Always call this after your own tearDown!
        """
        try:
            for node in self.nodes:
                await node.stop()
            internet.clear()
        finally:
            while self._tempdirs:
                shutil.rmtree(self._tempdirs.pop(), ignore_errors=True)
        # Now that everyone has calmed down, sweep up the remaining callbacks and check if they failed.
        # [port] ``asynctest.helpers.exhaust_callbacks`` no longer works in Python 3.10
        while self.loop._ready:  # noqa: SLF001
            await sleep(0)
        # [end of ``asynctest.helpers.exhaust_callbacks`` port]
        if self._uncaught_async_failure is not None:
            raise self._uncaught_async_failure["exception"]
        self.loop.set_exception_handler(None)  # None is equivalent to the default handler
        if self.__asynctest_compatibility_mode__:
            super().tearDown()
        else:
            await super().asyncTearDown()

    @classmethod
    def setUpClass(cls: TestBase) -> None:  # noqa: C901
        """
        Perform the base setup for this entire test case. Always call this before running your own setUpClass code!

        This code is responsible for detecting deadlocks in - and in between - tests. However, if you're running
        ``pytest`` you should use the ``pytest-timeout`` plugin instead.
        """
        TestBase.__lockup_timestamp__ = time.time()

        # pytest has its own timeout.
        if "PYTEST_CURRENT_TEST" not in os.environ:
            def check_loop() -> None:
                while time.time() - TestBase.__lockup_timestamp__ < cls.MAX_TEST_TIME:
                    time.sleep(2)
                    # If the test class completed normally, exit
                    if not cls.__testing__:
                        return
                # If we made it here, there is a serious issue which we cannot recover from.
                # Most likely the threadpool got into a deadlock while shutting down.
                import traceback
                print("The test-suite locked up! Force quitting! Thread dump:", file=sys.stderr)  # noqa: T201
                for tid, stack in sys._current_frames().items():  # noqa: SLF001
                    if tid != threading.current_thread().ident:
                        print("THREAD#%d" % tid, file=sys.stderr)  # noqa: T201
                        for line in traceback.format_list(traceback.extract_stack(stack)):
                            print("|", line[:-1].replace('\n', '\n|   '), file=sys.stderr)  # noqa: T201

                try:
                    tasks = all_tasks(get_running_loop())
                    if tasks:
                        print("Pending tasks:")  # noqa: T201
                        for task in tasks:
                            print(">     %s" % task)  # noqa: T201
                except RuntimeError:
                    print("Failed to acquire the pending tasks. Your event loop may already be closed!")  # noqa: T201

                # Our test suite catches the SIGINT signal, this allows it to print information before force exiting.
                # If we were to hard exit here (through os._exit) we would lose this additional information.
                import signal
                os.kill(os.getpid(), signal.SIGINT)
                # But sometimes it just flat out refuses to die (sys.exit will also not work in this case).
                # So we double kill ourselves:
                time.sleep(5.0)  # Just in case anyone is listening to our signal and wishes to log some stats quickly.
                os._exit(1)
            t = threading.Thread(target=check_loop)
            t.daemon = True
            t.start()

    @classmethod
    def tearDownClass(cls: TestBase) -> None:
        """
        Signal that our test case completed without incident. Always call this after your own tearDownClass!

        This - indirectly - stops setUpClass() from forcibly shutting down your tests.
        """
        cls.__testing__ = False

    def create_node(self, settings: CommunitySettings | None = None, create_dht: bool = False,
                    enable_statistics: bool = False) -> MockIPv8:
        """
        Create a new IPv8-like container to store node related information.
        """
        return MockIPv8("low", cast(Type[Community], self.overlay_class), settings, create_dht, enable_statistics)

    def add_node_to_experiment(self, node: MockIPv8) -> None:
        """
        Add a new node to this experiment (use `create_node()`).
        """
        for other in self.nodes:
            private_peer = other.my_peer
            public_peer = Peer(private_peer.public_key, private_peer.address)
            node.network.add_verified_peer(public_peer)
            node.network.discover_services(public_peer, node.overlay.community_id)
        self.nodes.append(node)

    @staticmethod
    def is_background_task(task: Task) -> bool:
        """
        Check if the given task is to be ignored.
        """
        # Only in Python 3.8+ will we have a get_name function
        name = task.get_name() if hasattr(task, 'get_name') else getattr(task, 'name', f'Task-{id(task)}')
        return name.endswith('_check_tasks')

    async def deliver_messages(self, timeout: float = .1) -> None:
        """
        Allow peers to communicate.

        The strategy is as follows:
         1. Measure the amount of existing asyncio tasks
         2. After 10 milliseconds, check if we are below 2 tasks twice in a row
         3. If not, go back to handling calls (step 2) or return, if the timeout has been reached

        :param timeout: the maximum time to wait for messages to be delivered
        """
        rtime = 0
        probable_exit = False

        while rtime < timeout:
            await sleep(.01)
            rtime += .01
            if len([task for task in all_tasks() if not self.is_background_task(task)]) < 2:
                if probable_exit:
                    break
                probable_exit = True
            else:
                probable_exit = False

    async def introduce_nodes(self) -> None:
        """
        Force all known nodes to send IntroductionRequest messages to each other.
        """
        for node in self.nodes:
            for other in self.nodes:
                if other != node:
                    node.overlay.walk_to(other.endpoint.wan_address)
        await self.deliver_messages()

    def temporary_directory(self) -> str:
        """
        Create a directory that temporary files can be written to.

        WARNING: If your test suite crashes, these files will be left behind (this is by design).
        """
        rndstr = '_temp_' + uuid.uuid4().hex
        d = os.path.abspath(self.__class__.__name__ + rndstr)
        self._tempdirs.append(d)
        os.makedirs(d)
        return d

    def address(self, i: int) -> Address:
        """
        The endpoint address of node i.
        """
        return self.peer(i).address

    def endpoint(self, i: int) -> Endpoint:
        """
        The endpoint of node i.
        """
        return self.nodes[i].endpoint

    def key_bin(self, i: int) -> bytes:
        """
        The serialized public key material of node i.
        """
        return self.nodes[i].my_peer.public_key.key_to_bin()

    def key_bin_private(self, i: int) -> bytes:
        """
        The serialized PRIVATE key material of node i.
        """
        return self.nodes[i].my_peer.key.key_to_bin()

    def mid(self, i: int) -> bytes:
        """
        The SHA-1 encoding (20 bytes) of the public key of node 1.
        """
        return self.nodes[i].my_peer.mid

    def my_peer(self, i: int) -> Peer:
        """
        The PRIVATE peer instance of node i, containing the PRIVATE KEY.

        When communicating peer info between peers, you should normally use ``peer(i)`` instead.
        """
        return self.nodes[i].overlay.my_peer

    def network(self, i: int) -> Network:
        """
        The Network instance of node i.
        """
        return self.nodes[i].network

    def node(self, i: int) -> MockIPv8:
        """
        The node identified by i.
        """
        return self.nodes[i]

    def overlay(self, i: int) -> OT:
        """
        The overlay belonging to node i.
        """
        return self.nodes[i].overlay

    def peer(self, i: int) -> Peer:
        """
        A public Peer object representing node i.
        """
        return Peer(self.nodes[i].my_peer.public_key.key_to_bin(), self.nodes[i].endpoint.wan_address)

    def private_key(self, i: int) -> PrivateKey:
        """
        The PRIVATE key object of node i.
        """
        return self.nodes[i].my_peer.key

    def public_key(self, i: int) -> PublicKey:
        """
        The public key object of node i.
        """
        return self.nodes[i].my_peer.public_key

    @contextmanager
    def assertReceivedBy(self, i: int, message_classes: list[type[Payload]], ordered: bool = True,  # noqa: N802
                         message_filter: list[type[Payload]] | None = None) -> list[Payload]:
        """
        Assert that a node i receives messages of a given type, potentially unordered or while ignoring other messages.

        :param i: the node id that needs to receive messages
        :param message_classes: the messages classes that you expect the node to receive
        :param ordered: whether the message classes are received ordered or unordered
        :param message_filter: what message classes to store (others are silently ignored)
        """
        requested_overlay = cast(Community, self.overlay(i))
        requested_endpoint = self.endpoint(i)

        endpoint_listener = TranslatedMockEndpointListener(requested_overlay, message_classes, message_filter)
        try:
            # Give a reference to the list, allows:
            #  1. Access to the received messages as they are coming in (within the ``with`` block).
            #  2. Access to the final list of received messages (after the ``with`` block).
            yield endpoint_listener.received_messages
        finally:
            received_messages = endpoint_listener.received_messages
            # Cleanup
            requested_endpoint.remove_listener(endpoint_listener)
            del endpoint_listener
            # Assertions
            if ordered:
                self.assertListEqual(message_classes, [message.__class__ for message in received_messages])
            else:
                # Count the occurrences of certain message types
                requested_classes = {}
                for message in message_classes:
                    requested_classes[message.__name__] = requested_classes.get(message.__name__, 0) + 1
                received_classes = {}
                for message in received_messages:
                    received_classes[message.__class__.__name__] = received_classes.get(message.__class__.__name__,
                                                                                        0) + 1
                # Can happen if received classes are a subset of the requested classes:
                self.assertSetEqual(set(requested_classes.keys()), set(received_classes.keys()),
                                    f"Not all classes received: requested {requested_classes}, got {received_classes}")
                # Check the counts for each class:
                self.assertSetEqual(set(requested_classes.items()), set(received_classes.items()))


__all__ = ["TestBase", "TranslatedMockEndpointListener"]
