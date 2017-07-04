import abc
import logging

from twisted.internet import reactor


class Endpoint(object):
    """
    Interface for sending messages over the Internet.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._listeners = []

    def add_listener(self, listener):
        """
        Add an EndpointListener to our listeners.

        :raises: IllegalEndpointListenerError if the provided listener is not an EndpointListener
        """
        if not isinstance(listener, EndpointListener):
            raise IllegalEndpointListenerError(listener)
        self._listeners.append(listener)

    def remove_listener(self, listener):
        """
        Remove a listener from our listeners, if it is registered.
        """
        self._listeners = [l for l in self._listeners if l != listener]

    def notify_listeners(self, packet):
        """
        Send data to all listeners.

        :param data: the data to send to all listeners.
        """
        for listener in self._listeners:
            if listener.use_main_thread:
                reactor.callFromThread(listener.on_packet, packet)
            else:
                reactor.callInThread(listener.on_packet, packet)

    @abc.abstractmethod
    def assert_open(self):
        pass

    @abc.abstractmethod
    def get_address(self):
        pass

    @abc.abstractmethod
    def send(self, socket_address, packet):
        pass

    @abc.abstractmethod
    def open(self):
        pass

    @abc.abstractmethod
    def close(self, timeout=0.0):
        pass


class EndpointListener(object):
    """
    Handler for messages coming in through an Endpoint.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, main_thread=False):
        """
        Create a new listener.

        :param main_thread: run the callback of this listener on the main thread.
        """
        self._use_main_thread = main_thread

    @property
    def use_main_thread(self):
        """
        Does the callback of this listener need to be executed on the main thread.
        """
        return self._use_main_thread

    @abc.abstractmethod
    def on_packet(self, packet):
        """
        Callback for when data is received on this endpoint.

        :param packet: the received packet, in (source, binary string) format.
        """
        pass


class IllegalEndpointListenerError(RuntimeError):
    """
    Exception raised when an EndpointListener instance was expected, but not supplied.
    """

    def __init__(self, other):
        message = '%s is not an instance of %s' % (type(other), str(EndpointListener.__name__))
        super(IllegalEndpointListenerError, self).__init__(message)


class EndpointClosedException(Exception):
    """
    Exception raised when an endpoint is expected to be open, but is closed.
    """

    def __init__(self, endpoint):
        super(EndpointClosedException, self).__init__('%s is unexpectedly closed' % type(endpoint))

class DataTooBigException(Exception):
    """
    Exception raised when the data being sent exceeds the maximum size.
    """

    def __init__(self, size, max_size):
        super(DataTooBigException, self).__init__('Tried to send packet of size %s > MAX_SIZE(%d)' % (size, max_size))
