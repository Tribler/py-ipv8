from __future__ import absolute_import
from __future__ import print_function

from collections import deque, namedtuple
from os import makedirs, path, rename
from random import randint
from shutil import rmtree
from subprocess import call
from sys import exit as _exit
from time import sleep, time

from six.moves import xrange
from twisted.internet import reactor
from twisted.internet.defer import Deferred, DeferredList

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import sys
    sys.path.append(path.abspath(path.join(path.dirname(__file__), "..")))

from ipv8.ipv8 import IPv8
from ipv8.configuration import get_default_configuration
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.overlay import Overlay
from ipv8.peer import Peer


test_results = {}
TestResult = namedtuple('TestResult', ['bytes_received', 'bytes_sent', 'packets_received', 'packets_sent'])
TestResultPair = namedtuple('TestResultPair', ['initiator', 'counterparty'])


class LoadOverlay(Overlay):

    def __init__(self, master_peer, my_peer, endpoint, network, window=1, packet_size=1000, packets=10000):
        """
        Create the overlay to pump through packets.

        :param window: the window size for packets (1 is synchronous)
        :param packet_size: the size of each packet
        :param packets: the number of packets to send in the experiment
        """
        super(LoadOverlay, self).__init__(master_peer, my_peer, endpoint, network)

        init_time = time()
        self.bytes_received = deque([(init_time, 0)])
        self.bytes_sent = deque([(init_time, 0)])
        self.packets_received = deque([(init_time, 0)])
        self.packets_sent = deque([(init_time, 0)])

        self.window = window
        self.packets = packets
        self.packet_content = "".join(chr(randint(0,255)) for _ in range(packet_size))
        self.packet_size = packet_size

        self.done = Deferred()

    def send(self, address):
        self.endpoint.send(address, self.packet_content)
        self.packets_sent.append((time(), self.packets_sent[-1][1] + 1))
        self.bytes_sent.append((time(), self.bytes_sent[-1][1] + self.packet_size))

    def on_packet(self, packet):
        source_address, data = packet
        self.packets_received.append((time(), self.packets_received[-1][1] + 1))
        self.bytes_received.append((time(), self.bytes_received[-1][1] + len(data)))
        self.window += 1

        if len(self.packets_received) < self.packets:
            while self.window > 0 and len(self.packets_sent) < self.packets:
                self.send(source_address)
                self.window -= 1
        elif not self.done.called:
            while self.window > 0 and len(self.packets_sent) < self.packets:
                self.send(source_address)
                self.window -= 1
            self.done.callback(self)

    def walk_to(self, address):
        pass

    def get_new_introduction(self, from_peer=None):
        return None

    def get_peers(self):
        return []


def setup_test(window=1, packet_size=1000, packets=10000):
    """
    Create two nodes who will be sending packets to each other.

    :param window: the window size for packets (1 is synchronous)
    :param packet_size: the size of each packet
    :param packets: the number of packets to send in the experiment
    :return: the deferred that fires once the experiment is complete
    """
    configuration = get_default_configuration()
    configuration['overlays'] = []
    configuration['keys'] = []

    master_peer = Peer(default_eccrypto.generate_key(u"low"))

    peer_ipv8 = IPv8(configuration)
    peer_ipv8.keys = {'my_peer': Peer(default_eccrypto.generate_key(u"low"))}
    peer_ipv8.overlays = [LoadOverlay(master_peer, peer_ipv8.keys['my_peer'], peer_ipv8.endpoint, peer_ipv8.network,
                                      window, packet_size, packets)]

    counterparty_ipv8 = IPv8(configuration)
    counterparty_ipv8.keys = {'my_peer': Peer(default_eccrypto.generate_key(u"low"))}
    counterparty_ipv8.overlays = [LoadOverlay(master_peer, counterparty_ipv8.keys['my_peer'],
                                              counterparty_ipv8.endpoint, counterparty_ipv8.network, 0,
                                              packet_size, packets)]

    peer_ipv8.overlays[0].send(counterparty_ipv8.endpoint.get_address())

    return DeferredList([peer_ipv8.overlays[0].done, counterparty_ipv8.overlays[0].done])


def on_synchronous_results(results):
    """
    We got the results of the first, synchronous, experiment.
    Start the next experiment.

    :param results: the two overlays
    """
    global test_results
    (_, overlay1), (__, overlay2) = results
    test_results["synchronous"] = TestResultPair(
        TestResult(overlay1.bytes_received, overlay1.bytes_sent, overlay1.packets_received, overlay1.packets_sent),
        TestResult(overlay2.bytes_received, overlay2.bytes_sent, overlay2.packets_received, overlay2.packets_sent)
    )
    test_asynchronous()


def on_asynchronous_results(results):
    """
    We got the results of the second, asynchronous, experiment.
    This is the last experiment, stop the reactor.

    :param results: the two overlays
    """
    global test_results
    (_, overlay1), (__, overlay2) = results
    test_results["asynchronous"] = TestResultPair(
        TestResult(overlay1.bytes_received, overlay1.bytes_sent, overlay1.packets_received, overlay1.packets_sent),
        TestResult(overlay2.bytes_received, overlay2.bytes_sent, overlay2.packets_received, overlay2.packets_sent)
    )
    reactor.callFromThread(reactor.stop)


def test_synchronous():
    """
    Start a synchronous test: 1kb packets, 100000 packets total.
    """
    setup_test(1, 1000, 20000).addCallback(on_synchronous_results)


def test_asynchronous():
    """
    Start an asynchronous test: 1kb packets, 100000 packets total.
    """
    setup_test(20, 1000, 20000).addCallback(on_asynchronous_results)


def run_tests():
    """
    Run the synchronous and asynchronous tests (one triggers the other).
    """
    test_synchronous()


# Start the tests and wait for them to finish.
reactor.callWhenRunning(run_tests)
reactor.run()

# Gather all the results.
prefix = "./endpoint_stresstest_results/"
old_prefix = None
try:
    makedirs(prefix)
except:
    old_prefix = path.abspath(prefix) + '_old'
    rmtree(old_prefix, ignore_errors=True)
    rename(path.abspath(prefix), old_prefix)
    makedirs(prefix)
for experiment, pair in test_results.items():
    for peer in ['initiator', 'counterparty']:
        for metric in ['bytes_received', 'bytes_sent', 'packets_received', 'packets_sent']:
            filename = prefix + "%s_%s_%s.csv" % (experiment, metric, peer)
            with open(filename, 'w') as f:
                f.write("time,count\n")
                value = getattr(getattr(pair, peer), metric)
                for time, count in value:
                    f.write("%f,%d\n" % (time, count))

# Allow the operating system to properly close the files and use R to plot.
sleep(2.0)
rcmd = "Rscript --vanilla %s \"%s\"" % (path.join(path.dirname(__file__), "endpoint_stresstest_plot.R"),
                                        path.abspath(prefix) + path.sep)
if old_prefix:
    rcmd += " \"%s\"" % (path.abspath(old_prefix) + path.sep)
retcode = call(rcmd, shell=True)

if retcode > 0:
    print("Error! Stresstest found significant slowdown:")
    binretcode = bin(retcode)[2:]
    errmap = {
        0: 'data_rcv_initiator',
        1: 'data_rcv_counterparty',
        2: 'data_snd_initiator',
        3: 'data_snd_counterparty',
        4: 'data_arcv_initiator',
        5: 'data_arcv_counterparty',
        6: 'data_asnd_initiator',
        7: 'data_asnd_counterparty'
    }
    for i in xrange(len(binretcode)):
        if binretcode[i] == '1':
            print("Significant slowdown in %s" % errmap[i])
else:
    print("Stresstest found no significant slowdown")

# This should be the last block of code in the file
if retcode > 0:
    _exit(1)
else:
    _exit(0)
