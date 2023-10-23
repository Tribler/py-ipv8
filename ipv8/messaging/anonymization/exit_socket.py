from __future__ import annotations

import logging
import socket
import sys
from asyncio import CancelledError, DatagramProtocol, DatagramTransport, Future, ensure_future, get_running_loop
from collections import deque
from struct import unpack_from
from traceback import format_exception
from typing import TYPE_CHECKING, Callable, cast

from ...taskmanager import TaskManager
from ..interfaces.udp.endpoint import DomainAddress, UDPv4Address, UDPv6Address
from .tunnel import PEER_FLAG_EXIT_BT, PEER_FLAG_EXIT_IPV8, Hop, RoutingObject

if TYPE_CHECKING:
    from ipv8.messaging.anonymization.community import TunnelCommunity
    from ipv8.types import Address


class DataChecker:
    """
    Class to verify that only IPv8-allowed traffic is being forwarded.
    """

    @staticmethod
    def could_be_utp(data: bytes) -> bool:
        """
        Check if this data could be uTP (see also https://www.bittorrent.org/beps/bep_0029.html).

        Packets should be 20 bytes or larger.

        The type should be 0..4:
         - 0: ST_DATA
         - 1: ST_FIN
         - 2: ST_STATE
         - 3: ST_RESET
         - 4: ST_SYN

        The version should be 1.

        The extension should be 0..3:
         - 0: No extension
         - 1: Selective ACK
         - 2: Deprecated
         - 3: Close reason
        """
        if len(data) < 20:
            return False
        byte1, byte2 = unpack_from('!BB', data)
        # Type and version
        if not (0 <= (byte1 >> 4) <= 4 and (byte1 & 15) == 1):
            return False
        # Extension
        if not (0 <= byte2 <= 3):
            return False
        return True

    @staticmethod
    def could_be_udp_tracker(data: bytes) -> bool:
        """
        Check if the data could be a UDP-based tracker.
        """
        # For the UDP tracker protocol the action field is either at position 0 or 8, and should be 0..3
        if len(data) >= 8 and (0 <= unpack_from('!I', data, 0)[0] <= 3)\
                or len(data) >= 12 and (0 <= unpack_from('!I', data, 8)[0] <= 3):
            return True
        return False

    @staticmethod
    def could_be_dht(data: bytes) -> bool:
        """
        Check if the data contain a bencoded dictionary.
        """
        try:
            if len(data) > 1 and data[0:1] == b'd' and data[-1:] == b'e':
                return True
        except TypeError:
            pass
        return False

    @staticmethod
    def could_be_bt(data: bytes) -> bool:
        """
        Check if the data could be any BitTorrent traffic.
        """
        return (DataChecker.could_be_utp(data)
                or DataChecker.could_be_udp_tracker(data)
                or DataChecker.could_be_dht(data))

    @staticmethod
    def could_be_ipv8(data: bytes) -> bool:
        """
        Check if the data is likely IPv8 overlay traffic.
        """
        return len(data) >= 23 and data[0:1] == b'\x00' and data[1:2] in [b'\x01', b'\x02']


class TunnelProtocol(DatagramProtocol):
    """
    Protocol used by TunnelExitSocket.
    """

    def __init__(self, received_cb: Callable, local_addr: Address) -> None:
        """
        Create a new TunnelProtocol.
        """
        self.received_cb = received_cb
        self.local_addr = local_addr
        self.logger = logging.getLogger(self.__class__.__name__)

    async def open(self) -> DatagramTransport:  # noqa: A003
        """
        Opens a datagram endpoint and returns the Transport.
        """
        transport, _ = await get_running_loop().create_datagram_endpoint(lambda: self,
                                                                         local_addr=self.local_addr)

        listen_addr = transport.get_extra_info('socket').getsockname()[:2]
        self.logger.info('Listening on %s:%s', *listen_addr)
        return cast(DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: Address) -> None:
        """
        Callback for when data is received by the socket.
        """
        self.received_cb(data, addr)


class TunnelExitSocket(RoutingObject, TaskManager):
    """
    Socket for exit nodes that communicates with the outside world.
    """

    def __init__(self, circuit_id: int, hop: Hop, overlay: TunnelCommunity) -> None:
        """
        Create a new exit socket.
        """
        RoutingObject.__init__(self, circuit_id)
        TaskManager.__init__(self)
        self.hop = hop
        self.overlay = overlay
        self.transport_ipv4: DatagramTransport | None = None
        self.transport_ipv6: DatagramTransport | None = None
        self.queue: deque[tuple[bytes, Address]] = deque(maxlen=10)
        self.enabled = False

    def enable(self) -> None:
        """
        Allow data to be sent.

        This creates the datagram endpoints that allows us to send messages.
        """
        if not self.enabled:
            self.enabled = True

            async def create_transports() -> None:
                self.transport_ipv4 = await TunnelProtocol(self.datagram_received_ipv4, ('0.0.0.0', 0)).open()
                self.transport_ipv6 = await TunnelProtocol(self.datagram_received_ipv6, ('::', 0)).open()

                # Send any packets that have been waiting while the transports were being created
                while self.queue:
                    self.sendto(*self.queue.popleft())

            self.register_task("create_transports", create_transports)

    def sendto(self, data: bytes, destination: Address) -> None:
        """
        Send o message over our datagram transporter.
        """
        if not self.is_allowed(data):
            return

        # Since this call comes from the TunnelCommunity, we assume the destination
        # address is either UDPv4Address/UDPv6Address/DomainAddress
        if isinstance(destination, DomainAddress):
            def on_address(future: Future[Address]) -> None:
                try:
                    ip_address = future.result()
                except (CancelledError, Exception) as e:
                    self.logger.exception("Can't resolve ip address for %s. Failure: %s", destination[0], e)
                    return
                self.sendto(data, ip_address)

            task = ensure_future(self.resolve(destination))
            # If this fails, the TaskManager logs the packet.
            self.register_anonymous_task("resolving_%r" % destination[0], task,
                                         ignore=(OSError, ValueError)).add_done_callback(on_address)
            return

        transport = self.transport_ipv6 if isinstance(destination, UDPv6Address) else self.transport_ipv4

        if not transport:
            self.queue.append((data, destination))
            return

        transport.sendto(data, destination)
        self.bytes_up += len(data)
        self.beat_heart()

    async def resolve(self, address: Address) -> Address:
        """
        Using asyncio's getaddrinfo since the aiodns resolver seems to have issues.
        Returns [(family, type, proto, canonname, sockaddr)].
        """
        info_list = await get_running_loop().getaddrinfo(address[0], 0)
        # For the time being we prefer dealing with IPv4 addresses.
        info_list.sort(key=lambda x: x[0])
        ip = info_list[0][-1][0]
        family = info_list[0][0]
        if family == socket.AF_INET6:
            return UDPv6Address(ip, address[1])
        return UDPv4Address(ip, address[1])

    def datagram_received_ipv4(self, data: bytes, source: Address) -> None:
        """
        Callback for when data is received by the IPv4 socket.
        """
        self.datagram_received(data, UDPv4Address(*source))

    def datagram_received_ipv6(self, data: bytes, source: Address) -> None:
        """
        Callback for when data is received by the IPv6 socket.
        """
        if source[0][:7] == '::ffff:':
            # We're not processing mapped IPv4, we have a separate endpoint for that.
            return
        self.datagram_received(data, UDPv6Address(*source[:2]))

    def datagram_received(self, data: bytes, source: Address) -> None:
        """
        Callback for when data is received by a IPv4/IPv6 socket.
        """
        self.bytes_down += len(data)
        if self.is_allowed(data):
            try:
                self.tunnel_data(source, data)
            except Exception:
                self.logger.exception("Exception occurred while handling incoming exit node data!\n%s",
                                      ''.join(format_exception(*sys.exc_info())))
        else:
            self.logger.warning("Dropping forbidden packets to exit socket with circuit_id %d", self.circuit_id)

    def is_allowed(self, data: bytes) -> bool:
        """
        Check if the captured data is not malicious junk.
        """
        is_bt = DataChecker.could_be_bt(data)
        is_ipv8 = DataChecker.could_be_ipv8(data)

        if not (is_bt and PEER_FLAG_EXIT_BT in self.overlay.settings.peer_flags) \
           and not (is_ipv8 and PEER_FLAG_EXIT_IPV8 in self.overlay.settings.peer_flags) \
           and not (is_ipv8 and self.overlay.get_prefix() == data[:22]):
            self.logger.warning("Dropping data packets, refusing to be an exit node (BT=%s, IPv8=%s)", is_bt, is_ipv8)
            return False
        return True

    def tunnel_data(self, source: Address, data: bytes) -> None:
        """
        Send data back over the tunnel that we are exiting for.
        """
        self.logger.debug("Tunnel data to origin %s for circuit %s", ('0.0.0.0', 0), self.circuit_id)
        self.overlay.send_data(self.hop.address, self.circuit_id, ('0.0.0.0', 0), source, data)

    async def close(self) -> None:
        """
        Closes the UDP socket if enabled and cancels all pending tasks.

        :return: A deferred that fires once the UDP socket has closed.
        """
        # The resolution tasks can't be cancelled, so we need to wait for
        # them to finish.
        await self.shutdown_task_manager()
        if self.transport_ipv4:
            self.transport_ipv4.close()
            self.transport_ipv4 = None
        if self.transport_ipv6:
            self.transport_ipv6.close()
            self.transport_ipv6 = None
