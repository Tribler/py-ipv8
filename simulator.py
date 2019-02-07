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


def open_gui(controller):
    root = tk.Tk()
    root.geometry("500x500")
    lbl_warning = tk.Label(root, text="Warning: Will remove all blocks")
    lbl_warning.pack()
    entry_filename = tk.Entry(root)
    entry_filename.pack()
    lbl_successfull = tk.Label(root, text="Succesful booking: ")
    lbl_successfull.pack()
    lbl_overbookings = tk.Label(root, text="Overbookings: ")
    lbl_overbookings.pack()
    lbl_nightcapped = tk.Label(root, text="Nightcapped Bookings: ")
    lbl_nightcapped.pack()

    def simulate():
        controller.remove_all_created_blocks()
        successfulBookings = 0
        overBookings = 0
        nightcapBookings = 0
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
                    "country": booking[2].split("_")[1],
                    "state": booking[2].split("_")[1],
                    "city": booking[2].split("_")[1],
                    "street": booking[2].split("_")[1],
                    "number": booking[2].split("_")[1]
                }
                start_date = booking[3]
                end_date = booking[4]

                try:
                    controller.get_bookings(address)
                except AttributeError:
                    controller.create_community(address["country"], address["state"], address["city"],
                                                address["street"], address["number"])
                finally:
                    result = controller.book_apartment(address, start_date, end_date)
                    if result == 0: successfulBookings += 1
                    elif result == 1: overBookings += 1
                    elif result == 2: nightcapBookings += 1

        lbl_successfull.config(text="SuccessfulBookings: " + str(successfulBookings))
        lbl_overbookings.config(text="Overbookings: " + str(overBookings))
        lbl_nightcapped.config(text="Nightcapped Bookings: " + str(nightcapBookings))

    button = tk.Button(root,
                       text="Simulate",
                       command=simulate)
    button.pack()

    root.mainloop()

thread.start_new_thread(open_gui, (controller,))
# Start the Twisted reactor: this is the engine scheduling all of the
# asynchronous calls.
reactor.run()