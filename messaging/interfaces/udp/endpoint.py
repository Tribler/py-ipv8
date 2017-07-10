import errno
from select import select
import socket
import sys
import threading
from time import time

from messaging.interfaces.endpoint import DataTooBigException, Endpoint, EndpointClosedException

if sys.platform == 'win32':
    SOCKET_BLOCK_ERRORCODE = 10035  # WSAEWOULDBLOCK
else:
    SOCKET_BLOCK_ERRORCODE = errno.EWOULDBLOCK

UDP_MAX_SIZE = 2 ** 16 - 60


class UDPEndpoint(Endpoint):
    """
    UDP implementation for sending messages over the Internet.
    """

    def __init__(self, port, ip="0.0.0.0"):
        """
        Bind an interface to the WWW on a certain port (and IP).

        :param port: the port to use
        :type port: int
        :param ip: the interface to bind to
        :type ip: string
        """
        super(UDPEndpoint, self).__init__()

        self._port = port
        self._ip = ip

        self._thread = None
        self._socket = None

        self._sendqueue_lock = threading.RLock()
        self._sendqueue = []

        self._running = False

    def assert_open(self):
        """
        Check if the underlying socket is open, or raise an exception.

        :raises: EndpointClosedException if the socket is closed
        """
        if not self.is_open():
            raise EndpointClosedException()

    def is_open(self):
        """
        Check if the underlying socket is open.
        """
        return self._socket and self._running

    def get_address(self):
        """
        Get the address for this Endpoint.
        """
        self.assert_open()
        return self._socket.getsockname()

    def send(self, socket_address, packet):
        """
        Send a UDP packet to a socket_address.

        :param socket_address: the socket_address to send the packet to
        :param packet: the packet to send to the socket_address
        :return: whether sending was successful
        """
        self.assert_open()

        if len(packet) > UDP_MAX_SIZE:
            raise DataTooBigException(len(packet), UDP_MAX_SIZE)

        try:
            self._socket.sendto(packet, socket_address)
        except socket.error:
            with self._sendqueue_lock:
                did_have_senqueue = bool(self._sendqueue)
                self._sendqueue.append((time(), socket_address, packet))

            # If we did not have a sendqueue, then we need to call process_sendqueue in order send these messages
            if not did_have_senqueue:
                self._process_sendqueue()

        return True

    def open(self):
        """
        Open this Endpoint for sending and receiving packets.
        """
        for _ in xrange(10000):
            try:
                self._logger.debug("Listening at %d", self._port)
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 870400)
                self._socket.bind((self._ip, self._port))
                self._socket.setblocking(0)

                self._port = self._socket.getsockname()[1]
            except socket.error:
                self._logger.debug("Listening failed at %d", self._port)
                self._port += 1
                continue
            break

        self._running = True
        self._thread = threading.Thread(name="UDPEndpoint", target=self._loop)
        self._thread.daemon = True
        self._thread.start()
        return True

    def close(self, timeout=10.0):
        """
        Close this Endpoint for sending and receiving.
        :param timeout: the maximum amount of time to wait for the socket to close
        :return: whether closing occurred naturally
        """
        self._running = False
        result = True

        if timeout > 0.0:
            self._thread.join(timeout)

            if self._thread.is_alive():
                self._logger.error("the endpoint thread is still running (after waiting %f seconds)", timeout)
                result = False

        else:
            if self._thread.is_alive():
                self._logger.error("the endpoint thread is still running "
                                   "(use timeout > 0.0 to ensure the thread stops)")
                result = False

        try:
            self._socket.close()
        except socket.error as exception:
            self._logger.exception("%s", exception)
            result = False

        return result

    def _loop(self):
        """
        The loop handling sending and receiving messages over this Endpoint.
        """
        self.assert_open()

        recvfrom = self._socket.recvfrom
        socket_list = [self._socket.fileno()]

        prev_sendqueue = 0
        while self._running:
            # This is a tricky, if we are running on the DAS4 whenever a socket is ready for writing all processes of
            # this node will try to write. Therefore, we have to limit the frequency of trying to write a bit.
            if self._sendqueue and (time() - prev_sendqueue) > 0.1:
                read_list, write_list, _ = select(socket_list, socket_list, [], 0.1)
            else:
                read_list, write_list, _ = select(socket_list, [], [], 0.1)

            # Furthermore, if we are allowed to send, process sendqueue immediately
            if write_list:
                self._process_sendqueue()
                prev_sendqueue = time()

            if read_list:
                packets = []
                try:
                    while True:
                        (data, sock_addr) = recvfrom(65535)
                        if data:
                            packets.append((sock_addr, data))
                        else:
                            break

                except socket.error as e:
                    if e.errno != errno.EAGAIN:
                        self._logger.debug('socket error: %s' % repr(e))

                finally:
                    if packets:
                        for packet in packets:
                            self.notify_listeners(packet)

    def _process_sendqueue(self):
        """
        Send any outstanding/previously undeliverable messages.
        """
        self.assert_open()

        with self._sendqueue_lock:
            if self._sendqueue:
                index = 0
                NUM_PACKETS = min(max(50, len(self._sendqueue) / 10), len(self._sendqueue))
                self._logger.debug("%d left in sendqueue, trying to send %d packets",
                                   len(self._sendqueue), NUM_PACKETS)

                allowed_timestamp = time() - 300

                for i in xrange(NUM_PACKETS):
                    queued_at, sock_addr, data = self._sendqueue[i]
                    if queued_at > allowed_timestamp:
                        try:
                            self._socket.sendto(data, sock_addr)
                            index += 1
                        except socket.error as e:
                            if e[0] != SOCKET_BLOCK_ERRORCODE:
                                self._logger.warning("could not send %d to %s (%d in sendqueue)",
                                                     len(data), sock_addr, len(self._sendqueue))
                            break
                    else:
                        index += 1

                self._sendqueue = self._sendqueue[index:]
                if self._sendqueue:
                    self._logger.debug("%d left in sendqueue", len(self._sendqueue))
