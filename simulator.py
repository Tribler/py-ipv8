import csv
import hashlib
import os
import ttk

from pyipv8.ipv8.attestation.trustchain.database import TrustChainDB

try:
    import tkinter as tk
except ImportError:
    import Tkinter as tk

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


persistence = TrustChainDB('', 'bobchain')
button = tk.Button(root,
                   text="Simulate",
                   command=simulate)
button.pack()
tk.Label(root, text="Overbookings:").pack()

root.mainloop()
