import functools
from asyncio import Transport
from threading import RLock

from aiohttp import ClientSession, web, BaseConnector
from aiohttp.client_proto import ResponseHandler
from aiohttp.web_protocol import RequestHandler

from ..base import TestBase
from ...REST.rest_manager import RESTManager
from ...configuration import get_default_configuration
from ...keyvault.crypto import ECCrypto
from ...messaging.anonymization.endpoint import TunnelEndpoint
from ...messaging.interfaces.endpoint import EndpointListener
from ...messaging.interfaces.udp.endpoint import UDPv4Address
from ...peer import Peer
from ...peerdiscovery.network import Network
from ...test.mocking.discovery import MockWalk
from ...test.mocking.endpoint import AutoMockEndpoint, MockEndpoint
from ...util import maybe_coroutine, succeed


def partial_cls(cls, *args, **kwargs):
    class PartialCls(cls):
        __init__ = functools.partialmethod(cls.__init__, *args, **kwargs)
    PartialCls.__name__ = cls.__name__
    return PartialCls


class IPv8Transport(Transport, EndpointListener):

    def __init__(self, callback, host=None, port=None, server_port=80):
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
        return not self.endpoint.is_open()

    def is_reading(self) -> bool:
        return self.endpoint.is_open()

    def close(self) -> None:
        self.endpoint.close()

    def on_packet(self, packet):
        address, data = packet
        self.remote = address
        self.callback(data)

    def write(self, data) -> None:
        self.endpoint.send(self.remote, data)


class MockServer:

    START_PORT = 80

    def __init__(self, server):
        super().__init__()
        self.port, MockServer.START_PORT = MockServer.START_PORT, MockServer.START_PORT + 1
        self.transport = IPv8Transport(self.received_data, "127.0.0.1", self.port)
        self.handler = RequestHandler(server, loop=server._loop)
        self.handler.connection_made(self.transport)

    def close(self):
        pass

    def shutdown(self, timeout):
        return succeed(True)

    def received_data(self, data):
        self.handler.data_received(data)


class MockedSite(web.TCPSite):

    async def start(self) -> None:
        self._server = self._runner.server
        await web.BaseSite.start(self)


class MockedRESTManager(RESTManager):

    async def start_site(self, runner, host, port, ssl_context):
        runner._server = MockServer(runner.server)
        self.site = MockedSite(runner, host, port, ssl_context=ssl_context)
        await self.site.start()


class MockRestIPv8(object):
    def __init__(self, crypto_curve, overlay_classes, *args, **kwargs):
        self.endpoint = AutoMockEndpoint()
        self.endpoint.open()
        self.configuration = get_default_configuration()
        self.configuration["working_directory"] = ":memory:"
        self.network = Network()
        self.my_peer = Peer(ECCrypto().generate_key(crypto_curve))
        self.overlays = [overlay_cls(self.my_peer, self.endpoint, self.network, *args, **kwargs)
                         for overlay_cls in overlay_classes]
        self.strategies = [(MockWalk(overlay), 20) for overlay in self.overlays]
        self.rest_manager = None
        self.rest_port = 0
        self.overlay_lock = RLock()

    def get_overlay(self, overlay_cls):
        return next((o for o in self.overlays if isinstance(o, overlay_cls)), None)

    def add_strategy(self, overlay, strategy, target_peers):
        with self.overlay_lock:
            self.overlays.append(overlay)
            self.strategies.append((strategy, target_peers))

    def unload_overlay(self, instance):
        self.overlays = [overlay for overlay in self.overlays if overlay != instance]
        self.strategies = [(strategy, target_peers) for (strategy, target_peers) in self.strategies
                           if strategy.overlay != instance]
        return maybe_coroutine(instance.unload)

    async def produce_anonymized_endpoint(self):
        endpoint = TunnelEndpoint(AutoMockEndpoint())
        endpoint.open()
        return endpoint

    async def start_api(self):
        self.rest_manager = MockedRESTManager(self)
        await self.rest_manager.start(0)
        self.rest_port = self.rest_manager.site._server.port

    async def stop(self, stop_loop=True):
        await self.rest_manager.stop()
        self.endpoint.close()
        for overlay in self.overlays:
            await overlay.unload()


class MockConnector(BaseConnector):

    async def _create_connection(self, req, traces, timeout) -> ResponseHandler:
        handler = ResponseHandler(self._loop)
        handler.connection_made(IPv8Transport(handler.data_received, server_port=req.port))
        return handler


class RESTTestBase(TestBase):
    """
    HTTP request superclass, which defines the common behavior between the different types of HTTP REST requests
    """

    async def initialize(self, overlay_classes, node_count, *args, **kwargs):
        self.overlay_classes = overlay_classes
        self.nodes = [await self.create_node(*args, **kwargs) for _ in range(node_count)]

        for node in self.nodes:
            for other in self.nodes:
                if other == node:
                    continue
                private_peer = other.my_peer
                public_peer = Peer(private_peer.public_key, private_peer.address)
                for overlay_class in overlay_classes:
                    node.network.discover_services(public_peer, overlay_class.community_id)

    async def create_node(self, *args, **kwargs):
        ipv8 = MockRestIPv8(u"curve25519", overlay_classes=self.overlay_classes, *args, **kwargs)
        await ipv8.start_api()
        return ipv8

    async def introduce_nodes(self):
        for node in self.nodes:
            for other in self.nodes:
                if other != node:
                    for overlay in node.overlays:
                        overlay.walk_to(other.endpoint.wan_address)
        await self.deliver_messages()

    async def make_request(self, node, endpoint, request_type, arguments=None, json_response=True, json=None,
                           expected_status=200):
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

        async with ClientSession(connector=MockConnector()) as session:
            async with session.request(request_type, url, json=json, params=arguments, headers=headers) as response:
                self.assertEqual(response.status, expected_status,
                                 "Expected HTTP status code %d, got %d" % (expected_status, response.status))
                return await response.json(content_type=None) if json_response else await response.read()
