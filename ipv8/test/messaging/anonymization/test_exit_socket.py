from binascii import unhexlify
from unittest.mock import Mock

from .test_datachecker import dht_pkt, ipv8_pkt, tracker_pkt, tunnel_pkt, utp_pkt
from ...base import TestBase
from ....messaging.anonymization.tunnel import PEER_FLAG_EXIT_BT, PEER_FLAG_EXIT_IPV8, TunnelExitSocket


class TestExitSocket(TestBase):

    async def test_is_allowed(self):
        """
        Check if the ExitSocket correctly detects forbidden packets.
        """
        overlay = Mock(_prefix=unhexlify('000281ded07332bdc775aa5a46f96de9f8f390bbc9f3'))
        exit_socket = TunnelExitSocket(0, None, overlay)

        overlay.settings.peer_flags = {}
        self.assertFalse(exit_socket.is_allowed(tracker_pkt))
        self.assertFalse(exit_socket.is_allowed(dht_pkt))
        self.assertFalse(exit_socket.is_allowed(utp_pkt))
        self.assertFalse(exit_socket.is_allowed(ipv8_pkt))
        self.assertTrue(exit_socket.is_allowed(tunnel_pkt))

        overlay.settings.peer_flags = {PEER_FLAG_EXIT_BT}
        self.assertTrue(exit_socket.is_allowed(tracker_pkt))
        self.assertTrue(exit_socket.is_allowed(dht_pkt))
        self.assertTrue(exit_socket.is_allowed(utp_pkt))
        self.assertFalse(exit_socket.is_allowed(ipv8_pkt))
        self.assertTrue(exit_socket.is_allowed(tunnel_pkt))

        overlay.settings.peer_flags = {PEER_FLAG_EXIT_IPV8}
        self.assertFalse(exit_socket.is_allowed(tracker_pkt))
        self.assertFalse(exit_socket.is_allowed(dht_pkt))
        self.assertFalse(exit_socket.is_allowed(utp_pkt))
        self.assertTrue(exit_socket.is_allowed(ipv8_pkt))
        self.assertTrue(exit_socket.is_allowed(tunnel_pkt))

        overlay.settings.peer_flags = {PEER_FLAG_EXIT_BT, PEER_FLAG_EXIT_IPV8}
        self.assertTrue(exit_socket.is_allowed(tracker_pkt))
        self.assertTrue(exit_socket.is_allowed(dht_pkt))
        self.assertTrue(exit_socket.is_allowed(utp_pkt))
        self.assertTrue(exit_socket.is_allowed(ipv8_pkt))
        self.assertTrue(exit_socket.is_allowed(tunnel_pkt))

        await exit_socket.close()
