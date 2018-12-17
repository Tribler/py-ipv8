import thread
import threading

from twisted.internet import reactor

import pyipv8.gui_holder
from pyipv8.ipv8_service import IPv8
from pyipv8.ipv8.configuration import get_default_configuration
import tkinter as tk

# Create an IPv8 object with the default settings.
# It will come to life once the Twisted reactor starts running.
IPv8(get_default_configuration())
# Start the Twisted reactor: this is the engine scheduling all of the
# asynchronous calls.

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
    IPv8(configuration)


def book_apartment():
    print("Book apartment")


night_cap = 8

reactor.run()
