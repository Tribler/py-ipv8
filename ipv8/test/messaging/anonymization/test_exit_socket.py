from binascii import unhexlify
from unittest.mock import Mock

from ....keyvault.private.libnaclkey import LibNaCLSK
from ....messaging.anonymization.exit_socket import TunnelExitSocket
from ....messaging.anonymization.tunnel import PEER_FLAG_EXIT_BT, PEER_FLAG_EXIT_IPV8
from ....peer import Peer
from ...base import TestBase
from .test_datachecker import dht_pkt, ipv8_pkt, tracker_pkt, tunnel_pkt, utp_pkt


class TestExitSocket(TestBase):
    """
    Tests related to the exit socket.
    """

    async def test_is_allowed(self) -> None:
        """
        Check if the ExitSocket correctly detects forbidden packets.
        """
        get_prefix = Mock(return_value=unhexlify('000281ded07332bdc775aa5a46f96de9f8f390bbc9f3'))
        overlay = Mock(get_prefix=get_prefix)
        exit_socket = TunnelExitSocket(0, Mock(peer=Peer(LibNaCLSK(b"\x00" * 64))), overlay)

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
