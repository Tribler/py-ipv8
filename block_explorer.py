from pyipv8.ipv8.attestation.trustchain.database import TrustChainDB

try:
    import tkinter as tk
except ImportError:
    import Tkinter as tk

root = tk.Tk()
root.geometry("500x500")
listbox = tk.Listbox(root, width=50, height=28)


def refresh():
    listbox.delete(0, 'end')
    for block in persistence.get_all_blocks():
        if block.type != "tribler_bandwidth":
            listbox.insert(tk.END, str(block.transaction).replace('u\'', '').replace('\'', ''))


persistence = TrustChainDB('', 'bobchain')
button = tk.Button(root,
                   text="Refresh",
                   command=refresh)
button.pack()
tk.Label(root, text="Blocks:").pack()
listbox.pack()
refresh()

root.mainloop()