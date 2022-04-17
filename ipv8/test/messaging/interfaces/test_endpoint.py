from unittest.mock import patch

from netifaces import AF_INET

from ...base import TestBase
from ...mocking.endpoint import AutoMockEndpoint
from ....messaging.interfaces.endpoint import EndpointListener

FAKE_ADDRESSES = {
    'interface1': {AF_INET: [{'addr': '10.0.0.2', 'netmask': '0.0.0.0', 'broadcast': '255.255.255.255'}]},
    'interface2': {AF_INET: [{'addr': '192.168.15.1', 'netmask': '255.255.255.0', 'broadcast': '192.168.15.255'}]},
    'interface3': {AF_INET: [{'addr': '127.0.0.1', 'netmask': '255.0.0.0', 'broadcast': '127.255.255.255'}]}
}


class TestableEndpointListener(EndpointListener):
    def on_packet(self, packet):
        pass


class TestEndpointListener(TestBase):

    @patch('netifaces.interfaces', lambda: FAKE_ADDRESSES)
    @patch('netifaces.ifaddresses', lambda iface: FAKE_ADDRESSES[iface])
    def test_get_interface_addresses(self):
        """Test that the _get_interface_addresses method returns all interfaces except the one with netmask 0.0.0.0"""
        listener = TestableEndpointListener(AutoMockEndpoint())
        interfaces = list(listener._get_interface_addresses())
        self.assertNotIn("0.0.0.0", [interface.netmask for interface in interfaces])
        self.assertEqual(len(FAKE_ADDRESSES) - 1, len(interfaces))  # all except the one with netmask 0.0.0.0
