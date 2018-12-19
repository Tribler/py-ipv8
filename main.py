import thread
import threading
from base64 import b64encode

from twisted.internet import reactor

from pyipv8.ipv8.REST.rest_manager import RESTManager
from pyipv8.ipv8_service import IPv8
from pyipv8.ipv8.configuration import get_default_configuration

for i in [1, 2]:
    configuration = get_default_configuration()
    # If we actually want to communicate between two different peers
    # we need to assign them different keys.
    # We will generate an EC key called 'my peer' which has 'medium'
    # security and will be stored in file 'ecI.pem' where 'I' is replaced
    # by the peer number (1 or 2).
    configuration['keys'] = [{
        'alias': "my peer",
        'generation': u"medium",
        'file': u"ec%d.pem" % i
    }]
    # Give each peer a separate working directory
    working_directory_overlays = ['BOBChainCommunity']
    for overlay in configuration['overlays']:
        if overlay['class'] in working_directory_overlays:
            overlay['initialize'] = {'working_directory': 'state_%d' % i}

    # Start the IPv8 service
    ipv8 = IPv8(configuration)
    rest_manager = RESTManager(ipv8)
    rest_manager.start(14410 + i)

    # Print the peer for reference
    print "Starting peer", b64encode(ipv8.keys["my peer"].mid)


def book_apartment():
    print("Book apartment")


night_cap = 8

# Start the Twisted reactor: this is the engine scheduling all of the
# asynchronous calls.
reactor.run()
