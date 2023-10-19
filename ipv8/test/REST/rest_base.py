from __future__ import annotations

from asyncio import Future, Transport
from threading import RLock
from typing import TYPE_CHECKING, Any, Awaitable, Callable, cast

from aiohttp import BaseConnector, ClientRequest, ClientSession, ClientTimeout, web
from aiohttp.client_proto import ResponseHandler
from aiohttp.web_protocol import RequestHandler

from ...community import CommunitySettings
from ...configuration import get_default_configuration
from ...keyvault.crypto import ECCrypto
from ...messaging.anonymization.endpoint import TunnelEndpoint
from ...messaging.interfaces.endpoint import EndpointListener
from ...messaging.interfaces.udp.endpoint import UDPv4Address
from ...peer import Peer
from ...peerdiscovery.network import Network
from ...REST.rest_manager import RESTManager
from ...test.mocking.discovery import MockWalk
from ...test.mocking.endpoint import AutoMockEndpoint, MockEndpoint
from ...util import maybe_coroutine, succeed
from ..base import TestBase

if TYPE_CHECKING:
    from ssl import SSLContext

    from aiohttp.tracing import Trace
    from aiohttp.web_runner import BaseRunner
    from aiohttp.web_server import Server

    from ...peerdiscovery.discovery import DiscoveryStrategy
    from ...types import Address, Community


class IPv8Transport(Transport, EndpointListener):
    """
    Transport to route over the fake IPv8 internet instead of the actual Internet.
    """

    def __init__(self, callback: Callable[[bytes], None], host: str | None = None, port: int | None = None,
                 server_port: int = 80) -> None:
        """
        Either transport to localhost and the server port or to a client with a not-pre-known host and port.
        """
        self.callback = callback
        Transport.__init__(self)
        if host is not None:
            self.endpoint = MockEndpoint(UDPv4Address(host, port), UDPv4Address(host, port))
            self.remote = None
        else:
            self.endpoint = AutoMockEndpoint()
            self.remote = UDPv4Address("127.0.0.1", server_port)
        EndpointListener.__init__(self, self.endpoint)
        self.endpoint.add_listener(self)
        self.endpoint.prefixlen = 0
        self.endpoint.open()

    def is_closing(self) -> bool:
        """
        Whether we are in the process of shutting down.
        """
        return not self.endpoint.is_open()

    def is_reading(self) -> bool:
        """
        Whether we are open.
        """
        return self.endpoint.is_open()

    def close(self) -> None:
        """
        Close our transport.
        """
        self.endpoint.close()

    def on_packet(self, packet: tuple[Address, bytes]) -> None:
        """
        Callback for when the fake IPv8 internet sends us a message.

        We forward this call to the registered callback.
        """
        address, data = packet
        self.remote = address
        self.callback(data)

    def write(self, data: bytes) -> None:
        """
        Write to the other end of this transport.
        """
        self.endpoint.send(self.remote, data)


class MockServer:
    """
    Fake server to hijack TCP sessions and route them over the IPv8 fake internet.
    """

    START_PORT = 80

    def __init__(self, server: Server) -> None:
        """
        Rip the information from the real server and hook it into our IPv8 endpoints.
        """
        super().__init__()
        self.port, MockServer.START_PORT = MockServer.START_PORT, MockServer.START_PORT + 1
        self.transport = IPv8Transport(self.received_data, "127.0.0.1", self.port)
        self.handler = RequestHandler(server, loop=server._loop)  # noqa: SLF001
        self.handler.connection_made(self.transport)

    def close(self) -> None:
        """
        Close this fake server (no action required).
        """

    def shutdown(self, timeout: float) -> Future[bool]:
        """
        Shut down this fake server (no action required).
        """
        return succeed(True)

    def received_data(self, data: bytes) -> None:
        """
        Forward all received data to our handler.
        """
        self.handler.data_received(data)


class MockedSite(web.TCPSite):
    """
    Pretend to host a TCP site (actually UDP over fake IPv8 internet).
    """

    async def start(self) -> None:
        """
        Start our nefarious rerouting.
        """
        self._server = self._runner.server
        await web.BaseSite.start(self)

    async def stop(self) -> None:
        """
        The `wait_for` implementation of our super does not work.

        Instead, we perform our own light-weight shutdown.
        """
        self._runner._check_site(self)  # noqa: SLF001
        await self._runner.shutdown()
        self._runner._unreg_site(self)  # noqa: SLF001


class MockedRESTManager(RESTManager):
    """
    Hook a fake site into the real rest manager.
    """

    async def start_site(self, runner: BaseRunner, host: str, port: int, ssl_context: SSLContext | None) -> None:
        """
        Start accepting connections to the REST API.
        """
        runner._server = MockServer(runner.server)  # noqa: SLF001
        self.site = MockedSite(runner, host, port, ssl_context=ssl_context)
        await self.site.start()


class MockRestIPv8:
    """
    Manager for IPv8 related objects during REST tests.

    Note that this is not the same as an IPv8 instance, neither is it the same as a MockIPv8 instance! However, many of
    the same functionalities are offered.
    """

    def __init__(self, crypto_curve: str, overlay_classes: list[type[Community]],
                 settings: list[CommunitySettings]) -> None:
        """
        Create a new MockRestIPv8 and forward arguments to the created overlay classes.
        """
        self.endpoint = AutoMockEndpoint()
        self.endpoint.open()
        self.configuration = get_default_configuration()
        self.configuration["working_directory"] = ":memory:"
        self.network = Network()
        self.my_peer = Peer(ECCrypto().generate_key(crypto_curve))
        base_settings = CommunitySettings(my_peer=self.my_peer, endpoint=self.endpoint, network=self.network)
        for setting in settings:
            setting.__dict__.update(base_settings.__dict__)
        self.overlays = [overlay_cls(settings[i]) for i, overlay_cls in enumerate(overlay_classes)]
        self.strategies: list[tuple[DiscoveryStrategy, int]] = [(MockWalk(overlay), 20) for overlay in self.overlays]
        self.rest_manager = None
        self.rest_port = 0
        self.overlay_lock = RLock()

    def get_overlay(self, overlay_cls: type[Community]) -> Community | None:
        """
        Get any loaded overlay instance from a given class type, if it exists.
        """
        return next((o for o in self.overlays if isinstance(o, overlay_cls)), None)

    def add_strategy(self, overlay: Community, strategy: DiscoveryStrategy, target_peers: int) -> None:
        """
        Register a strategy to call every tick unless a target number of peers has been reached.
        If the ``target_peers`` is equal to ``-1``, the strategy is always called.
        """
        with self.overlay_lock:
            self.overlays.append(overlay)
            self.strategies.append((strategy, target_peers))

    def unload_overlay(self, instance: Community) -> Awaitable:
        """
        Unregister and unload a given community instance.
        """
        self.overlays = [overlay for overlay in self.overlays if overlay != instance]
        self.strategies = [(strategy, target_peers) for (strategy, target_peers) in self.strategies
                           if strategy.overlay != instance]
        return maybe_coroutine(instance.unload)

    async def produce_anonymized_endpoint(self) -> TunnelEndpoint:
        """
        Create an anonymized endpoint.
        """
        endpoint = TunnelEndpoint(AutoMockEndpoint())
        endpoint.open()
        return endpoint

    async def start_api(self) -> None:
        """
        Start the REST API.
        """
        self.rest_manager = MockedRESTManager(self)
        await self.rest_manager.start(0)
        self.rest_port = cast(MockServer, self.rest_manager.site._server).port  # noqa: SLF001

    async def stop(self) -> None:
        """
        Stop serving the REST API.
        """
        await self.rest_manager.stop()
        self.endpoint.close()
        for overlay in self.overlays:
            await overlay.unload()


class MockConnector(BaseConnector):
    """
    Connector that routes over the fake IPv8 internet.
    """

    async def _create_connection(self, req: ClientRequest, traces: list[Trace],
                                 timeout: ClientTimeout) -> ResponseHandler:
        handler = ResponseHandler(self._loop)
        handler.connection_made(IPv8Transport(handler.data_received, server_port=req.port))
        return handler


class RESTTestBase(TestBase):
    """
    HTTP request superclass, which defines the common behavior between the different types of HTTP REST requests.
    """

    async def initialize(self, overlay_classes: list[type[Community]], node_count: int,
                         settings: list[CommunitySettings]) -> None:
        """
        Initialize a given number of nodes with instances of the given Community classes.
        """
        self.overlay_classes = overlay_classes
        self.nodes = [await self.create_node(settings) for _ in range(node_count)]

        for node in self.nodes:
            for other in self.nodes:
                if other == node:
                    continue
                private_peer = other.my_peer
                public_peer = Peer(private_peer.public_key, private_peer.address)
                for overlay_class in overlay_classes:
                    node.network.discover_services(public_peer, overlay_class.community_id)

    async def create_node(self, settings: list[CommunitySettings]) -> MockRestIPv8:
        """
        Create a new MockRestIPv8 and start its REST API.
        """
        ipv8 = MockRestIPv8("curve25519", self.overlay_classes, settings)
        await ipv8.start_api()
        return ipv8

    def node(self, i: int) -> MockRestIPv8:
        """
        MockRestIPv8 is not actually a MockIPv8. So, we bend the rules here a little bit.
        """
        return cast(MockRestIPv8, super().node(i))

    async def introduce_nodes(self) -> None:
        """
        Have each node send an introduction request to each other node.
        """
        for node in self.nodes:
            for other in self.nodes:
                if other != node:
                    for overlay in node.overlays:
                        overlay.walk_to(other.endpoint.wan_address)
        await self.deliver_messages()

    async def make_request(self, node: MockRestIPv8, endpoint: str, request_type: str,  # noqa: PLR0913
                           arguments: dict[str, str] | None = None, json_response: bool = True,
                           json: dict | None = None, expected_status: int = 200) -> Any:  # noqa: ANN401
        """
        Forward an HTTP request of the specified type to a url, with the specified set of arguments.

        :param node: the destination node
        :param endpoint: the endpoint of this request (i.e. http://<interface>:<port>/<endpoint>)
        :param request_type: the type of request (GET, POST, PUT, DELETE, etc.)
        :param arguments: the arguments to be attached to the request. This should be a dictionary or None
        :param json_response: whether the response is expected to be JSON
        :param json: a JSON-serializable dictionary that is sent when making the request
        :param expected_status: the status code returned in the response, defaults to 200
        :return: a dictionary object with the response
        """
        # Using localhost in the URL will cause aiohttp to first try ::1, causing a 1s delay for each request
        url = 'http://127.0.0.1:%d/%s' % (node.rest_port, endpoint)
        headers = {'User-Agent': 'aiohttp'}

        async with ClientSession(connector=MockConnector()) as session, \
                   session.request(request_type, url, json=json, params=arguments, headers=headers) as response:
                self.assertEqual(response.status, expected_status,
                                 "Expected HTTP status code %d, got %d" % (expected_status, response.status))
                return await response.json(content_type=None) if json_response else await response.read()
