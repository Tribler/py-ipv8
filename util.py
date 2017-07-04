import Queue
import logging
import traceback
from socket import error as socket_error
from socket import inet_aton, socket, AF_INET, SOCK_DGRAM
from struct import unpack_from

from twisted.internet import reactor, defer
from twisted.python import failure
from twisted.python.threadable import isInIOThread

logger = logging.getLogger(__name__)

MEMORY_DUMP_INTERVAL = float(60 * 60)

#
# Various decorators
#

def call_on_reactor_thread(func):
    def helper(*args, **kargs):
        if isInIOThread():
            # TODO(emilon): Do we really want it to block if its on the reactor thread?
            return func(*args, **kargs)
        else:
            return reactor.callFromThread(func, *args, **kargs)
    helper.__name__ = func.__name__
    return helper


def blocking_call_on_reactor_thread(func):
    def helper(*args, **kargs):
        return blockingCallFromThread(reactor, func, *args, **kargs)
    helper.__name__ = func.__name__
    return helper


def blockingCallFromThread(reactor, f, *args, **kwargs):
    """
    Improved version of twisted's blockingCallFromThread that shows the complete
    stacktrace when an exception is raised on the reactor's thread.
    If being called from the reactor thread already, just return the result of execution of the callable.
    """
    if isInIOThread():
            return f(*args, **kwargs)
    else:
        queue = Queue.Queue()

        def _callFromThread():
            result = defer.maybeDeferred(f, *args, **kwargs)
            result.addBoth(queue.put)
        reactor.callFromThread(_callFromThread)
        result = queue.get()
        if isinstance(result, failure.Failure):
            other_thread_tb = traceback.extract_tb(result.getTracebackObject())
            this_thread_tb = traceback.extract_stack()
            logger.error("Exception raised on the reactor's thread %s: \"%s\".\n Traceback from this thread:\n%s\n"
                         " Traceback from the reactor's thread:\n %s", result.type.__name__, result.getErrorMessage(),
                         ''.join(traceback.format_list(this_thread_tb)), ''.join(traceback.format_list(other_thread_tb)))
            result.raiseException()
        return result

#
# IP address validation functions
#


def is_valid_address(address):
    """
    Returns True when ADDRESS is valid.

    ADDRESS must be supplied as a (HOST string, PORT integer) tuple.

    An address is valid when it meets the following criteria:
    - HOST must be non empty
    - HOST must be non '0.0.0.0'
    - PORT must be > 0
    - HOST must be 'A.B.C.D' where A, B, and C are numbers higher or equal to 0 and lower or
      equal to 255.  And where D is higher than 0 and lower than 255
    """
    assert isinstance(address, tuple), type(address)
    assert len(address) == 2, len(address)
    assert isinstance(address[0], str), type(address[0])
    assert isinstance(address[1], int), type(address[1])

    if address[0] == "":
        return False

    if address[0] == "0.0.0.0":
        return False

    if address[1] <= 0:
        return False

    try:
        binary = inet_aton(address[0])
    except socket_error:
        return False

    # ending with .0
    # Niels: is now allowed, subnet mask magic call actually allow for this
    #        if binary[3] == "\x00":
    #            return False

    # ending with .255
    # Niels: same for this one, if the netmask is /23 a .255 could indicate 011111111 which is allowed
    #        if binary[3] == "\xff":
    #            return False

    return True


def is_valid_address_or_log(sock_addr, data):
    if is_valid_address(sock_addr):
        return True
    else:
        logging.error("Packet contains invalid address: (%s, %d), data: %s" % (sock_addr[0], sock_addr[1], data))
        return False


def get_lan_address_without_netifaces():
    """
    # Get the local ip address by creating a socket for a (random) internet ip
    :return: the local ip address
    """
    try:
        s = socket(AF_INET, SOCK_DGRAM)
        s.connect(("192.0.2.0", 80)) # TEST-NET-1, guaranteed to not be connected => no callbacks
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except socket_error as exception:
        logger.error(exception)
        return "0.0.0.0"


def address_is_lan_without_netifaces(address):
    """
    Checks if the given ip address is either our own address or in one of the subnet defined for local network usage
    :param address: ip v4 address to be checked
    :return: True if the adrress is a lan address, False otherwise
    """
    if address == get_lan_address_without_netifaces():
        return True
    else:
        lan_subnets = (("192.168.0.0", 16),
                  ("172.16.0.0", 12),
                  ("10.0.0.0", 8))
        return any(address_in_subnet(address, subnet) for subnet in lan_subnets)


def address_in_subnet(address, subnet):
    """
    Checks whether a given address is in a given subnet
    :param address: an ip v4 address as a string formatted as four pairs of decimals separated by dots
    :param subnet: a tuple consisting of the main address of the subnet formatted as above, and the subnet formatted as
    an int with the number of significant bits in the address.
    :return: True if the address is in the subnet, False otherwise
    """
    address = unpack_from(">L", inet_aton(address))[0]
    (subnet_main, netmask) = subnet
    subnet_main = unpack_from(">L", inet_aton(subnet_main))[0]
    address >>= 32-netmask
    subnet_main >>= 32-netmask
    return address == subnet_main
