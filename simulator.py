import csv
import hashlib
import os
import sys
import thread
import ttk

from twisted.internet import reactor

from pyipv8.controller import Controller
from pyipv8.ipv8.REST.rest_manager import RESTManager
from pyipv8.ipv8.attestation.trustchain.database import TrustChainDB
from pyipv8.ipv8_service import IPv8

try:
    import tkinter as tk
except ImportError:
    import Tkinter as tk

import socket
def get_open_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("",0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port


config = {
    'address': '0.0.0.0',
    'port': 8090,
    'keys': [{
        'alias': "discovery",
        'generation': u"medium",
        'file': u"keys/discovery.pem"
    }],
    'logger': {
        'level': "INFO"
    },
    'walker_interval': 0.5,
    'overlays': [
        {
            'class': 'DiscoveryCommunity',
            'key': "discovery",
            'walkers': [
                {
                    'strategy': "RandomWalk",
                    'peers': 20,
                    'init': {
                        'timeout': 3.0
                    }
                },
                {
                    'strategy': "RandomChurn",
                    'peers': -1,
                    'init': {
                        'sample_size': 8,
                        'ping_interval': 10.0,
                        'inactive_time': 27.5,
                        'drop_time': 57.5
                    }
                }
            ],
            'initialize': {},
            'on_start': [
                ('resolve_dns_bootstrap_addresses',)
            ]
        }
    ]
}


# Start the IPv8 service
ipv8 = IPv8.__new__(IPv8)
controller = Controller(ipv8)
ipv8.__init__(config)
rest_manager = RESTManager(ipv8)


if len(sys.argv) > 1:
    rest_manager.start(int(sys.argv[1]))
else:
    rest_manager.start(14410)


#rest_manager.start(get_open_port())


def open_gui():
    root = tk.Tk()
    root.geometry("500x500")
    entry_filename = tk.Entry(root)
    entry_filename.pack()
    lbl_overbookings = tk.Label(root, text="Overbookings: ")
    lbl_overbookings.pack()

    def simulate():
        with open(os.path.join("simulation", entry_filename.get() or "bookings_500_per_50_filter.csv"), 'r') as file:
            reader = csv.reader(file, delimiter=';')
            firstline = True
            for booking in reader:
                if firstline:
                    firstline = False
                    continue
                row = int(booking[0])
                ota = booking[1]
                address = {
                    "country": "a",
                    "state": "b",
                    "city": "c",
                    "street": "d",
                    "number": int(booking[2].split("_")[1])
                }
                start_date = booking[3]
                end_date = booking[4]
                print(", ".join(booking))

    button = tk.Button(root,
                       text="Simulate",
                       command=simulate)
    button.pack()
    tk.Label(root, text="Overbookings:").pack()

    root.mainloop()


thread.start_new_thread(open_gui, (controller))
# Start the Twisted reactor: this is the engine scheduling all of the
# asynchronous calls.
reactor.run()
