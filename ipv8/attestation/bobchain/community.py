"""
The TrustChain Community is the first step in an incremental approach in building a new reputation system.
This reputation system builds a tamper proof interaction history contained in a chain data-structure.
Every node has a chain and these chains intertwine by blocks shared by chains.
"""
from __future__ import absolute_import

from datetime import datetime
from functools import wraps
from threading import RLock

import tkinter as tk
from twisted.internet.task import LoopingCall

from pyipv8 import gui_holder
from pyipv8.ipv8.attestation.trustchain.block import ANY_COUNTERPARTY_PK
from pyipv8.ipv8.attestation.trustchain.community import TrustChainCommunity

receive_block_lock = RLock()


def synchronized(f):
    """
    Due to database inconsistencies, we can't allow multiple threads to handle a received_half_block at the same time.
    """

    @wraps(f)
    def wrapper(self, *args, **kwargs):
        with receive_block_lock:
            return f(self, *args, **kwargs)

    return wrapper


class BOBChainCommunity(TrustChainCommunity):
    bobChainCommunity = None

    def __init__(self, *args, **kwargs):
        super(BOBChainCommunity, self).__init__(*args, **kwargs)

    def book_apartment(self):
        blocks = self.persistence.get_blocks_with_type("property")
        for block in blocks:
            start_day = block.transaction["start_day"].split("-")
            end_day = block.transaction["end_day"].split("-")
            start_day_tuple = (int(start_day[0]), int(start_day[1]), int(start_day[2]))
            end_day_tuple = (int(end_day[0]), int(end_day[1]), int(end_day[2]))
            current_day = datetime.now()
            current_day_tuple = (current_day.year, current_day.month, current_day.day)
            if start_day_tuple <= current_day_tuple <= end_day_tuple:
                print "Overbooking!"
                return
        self.sign_block(
            block_type=b"property",
            transaction=
            {
                b"property_id": 42,
                b"start_day": datetime.now().strftime("%Y-%m-%d"),  # 2000-01-31
                b"end_day": "2999-01-01",
            },
            public_key=ANY_COUNTERPARTY_PK,
            peer=None
        )
        print "Booked apartment"

    def get_apartments(self):
        result = set()
        for block in self.persistence.get_blocks_with_type("property"):
            property_id = block.transaction["property_id"]
            if property_id not in result:
                result.add(property_id)
        return result

    def publish_license(self):
        self.persistence.add_block()

    def started(self):
        def print_peers():
            print "I am: ", self.my_peer, "\nI know: ", [str(p) for p in self.get_peers()]

        BOBChainCommunity.bobChainCommunity = self
        # We register a Twisted task with this overlay.
        # This makes sure that the task ends when this overlay is unloaded.
        # We call the 'print_peers' function every 5.0 seconds, starting now.
        self.register_task("print_peers", LoopingCall(print_peers)).start(5.0, True)

        # self.persistence.execute("INSERT INTO option(key, value) VALUES('database_version', '0')")
        # self.persistence.commit()

        window = tk.Toplevel(gui_holder.root)
        window.geometry("500x500")
        frame = MainFrame(window)
        frame.pack(side="top", fill="both", expand=True)


class Page(tk.Frame):
    window_title = ""

    def __init__(self, *args, **kwargs):
        tk.Frame.__init__(self, *args, **kwargs)

    def show(self):
        self.lift()
        self.winfo_toplevel().title(self.window_title)


class PageLogin(object, Page):
    window_title = "Login"

    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)

    def init(self, page_government, page_home_owner, page_ota):
        self.page_government = page_government
        self.page_home_owner = page_home_owner
        self.page_ota = page_ota

    def show(self):
        super(PageLogin, self).show()
        b1 = tk.Button(self, text="Government", command=self.page_government.show)
        b2 = tk.Button(self, text="Home owner", command=self.page_home_owner.show)
        b3 = tk.Button(self, text="OTA", command=self.page_ota.show)

        b1.pack(side="top", fill="both")
        b2.pack(side="top", fill="both")
        b3.pack(side="top", fill="both")


class PageGovernment(object, Page):
    window_title = "Government"

    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)

    def init(self, get_apartments, publish_license):
        self.get_apartments = get_apartments
        self.publish_license = publish_license
        tk.Label(self, text="Registered properties")
        self.listbox = tk.Listbox(self)
        self.listbox.pack()

        tk.Label(self, text="Country").pack()
        entry_country = tk.Entry(self)
        entry_country.pack()

        tk.Label(self, text="State").pack()
        entry_state = tk.Entry(self)
        entry_state.pack()

        tk.Label(self, text="City").pack()
        entry_city = tk.Entry(self)
        entry_city.pack()

        tk.Label(self, text="Street").pack()
        entry_street = tk.Entry(self)
        entry_street.pack()

        tk.Label(self, text="Number").pack()
        entry_number = tk.Entry(self)
        entry_number.pack()

        button = tk.Button(self,
                           text="Publish license",
                           command=lambda: self.publish_license(
                               entry_country.get(),
                               entry_state.get(),
                               entry_city.get(),
                               entry_street.get(),
                               entry_number.get()
                           ))
        button.pack()

    def show(self):
        super(PageGovernment, self).show()
        for property_id in self.get_apartments():
            self.listbox.insert(tk.END, "Property: " + str(property_id))
        self.get_apartments()

class PageHomeOwner(object,Page):
    window_title = "Home Owner"

    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)

    def init(self):
        pass


class PageOTA(Page):
    window_title = "OTA"

    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)

    def init(self, page_book_apartment):
        self.page_book_apartment = page_book_apartment

    def show(self):
        button = tk.Button(self,
                           text="Book apartment",
                           command=self.page_book_apartment.show)
        button.pack()


class PageBookApartment(object, Page):
    window_title = "Book apartment"

    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)

    def init(self, get_apartments, book_apartment):
        self.get_apartments = get_apartments
        self.book_apartment = book_apartment

    def show(self):
        super(PageBookApartment, self).show()
        self.listbox = tk.Listbox(self)
        self.listbox.pack()

        button = tk.Button(self,
                           text="Book apartment",
                           command=self.book_apartment)
        button.pack()
        for property_id in self.get_apartments():
            self.listbox.insert(tk.END, "Property: " + str(property_id))
        self.get_apartments()


class MainFrame(tk.Frame):
    page_login = None
    page_government = None
    page_home_owner = None
    page_ota = None
    page_book_apartment = None

    def __init__(self, *args, **kwargs):
        tk.Frame.__init__(self, *args, **kwargs)
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)

        self.page_login = PageLogin(self)
        self.page_government = PageGovernment(self)
        self.page_home_owner = PageHomeOwner(self)
        self.page_ota = PageOTA(self)
        self.page_book_apartment = PageBookApartment(self)

        self.page_login.init(self.page_government, self.page_home_owner, self.page_ota)
        self.page_government.init(lambda: BOBChainCommunity.bobChainCommunity.get_apartments(),
                                  lambda: BOBChainCommunity.bobChainCommunity.publish_license())
        self.page_home_owner.init()
        self.page_ota.init(self.page_book_apartment)
        self.page_book_apartment.init(lambda: BOBChainCommunity.bobChainCommunity.get_apartments(),
                                      lambda: BOBChainCommunity.bobChainCommunity.book_apartment())

        self.page_login.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        self.page_government.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        self.page_home_owner.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        self.page_ota.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        self.page_book_apartment.place(in_=container, x=0, y=0, relwidth=1, relheight=1)

        self.page_login.show()
