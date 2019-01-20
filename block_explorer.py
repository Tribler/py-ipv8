import hashlib
import ttk

from pyipv8.ipv8.attestation.trustchain.database import TrustChainDB

try:
    import tkinter as tk
except ImportError:
    import Tkinter as tk

root = tk.Tk()
root.geometry("500x500")
treeview = ttk.Treeview(root, height=28)


def refresh():
    treeview.delete(*treeview.get_children())
    pbhash_to_tree = {}  # Property hash
    for block in persistence.get_all_blocks():
        if block.type != "tribler_bandwidth":
            t = block.transaction
            if "country" in t:
                pbhash_to_tree[block.public_key] = \
                    treeview.insert("", "end", text=str(block.transaction).replace('u\'', '').replace('\'', ''))
                treeview.item(pbhash_to_tree[block.public_key], open=True)
            else:
                treeview.insert(pbhash_to_tree[block.public_key], "end",
                                text=str(block.transaction).replace('u\'', '').replace('\'', ''))


persistence = TrustChainDB('', 'bobchain')
button = tk.Button(root,
                   text="Refresh",
                   command=refresh)
button.pack()
tk.Label(root, text="Blocks:").pack()
treeview.pack(expand=tk.YES, fill=tk.BOTH)
refresh()

root.mainloop()
