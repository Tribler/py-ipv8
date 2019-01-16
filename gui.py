import tkSimpleDialog

from pyipv8 import NewCommunityRegisteredEvent

try:
    import tkinter as tk
except ImportError:
    import Tkinter as tk

import tkMessageBox

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

    def init(self, page_government, page_home_owner, page_ota, clear_database):
        self.page_government = page_government
        self.page_home_owner = page_home_owner
        self.page_ota = page_ota
        self.clear_database = clear_database

    def show(self):
        super(PageLogin, self).show()
        b1 = tk.Button(self, text="Government", command=self.page_government.show)
        b2 = tk.Button(self, text="Home owner", command=self.page_home_owner.show)
        b3 = tk.Button(self, text="OTA", command=self.page_ota.show)
        btn_clear_database = tk.Button(self, text="Clear database", command=self.clear_database)

        b1.pack(side="top", fill="both")
        b2.pack(side="top", fill="both")
        b3.pack(side="top", fill="both")
        btn_clear_database.pack(side="top", fill="both")


class PageGovernment(object, Page):
    window_title = "Government"

    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)
        self.property_details = []

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

        NewCommunityRegisteredEvent.event.append(self.refresh_listbox)

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

    def refresh_listbox(self):
        self.listbox.delete(0, 'end')
        self.property_details = []
        for country, states in self.get_apartments().items():
            community_id = {"country": country}
            for state, cities in states.items():
                community_id["state"] = state
                for city, streets in cities.items():
                    community_id["city"] = city
                    for street, numbers in streets.items():
                        community_id["street"] = street
                        for number in numbers:
                            community_id["number"] = number
                            self.property_details.append(community_id)
                            self.listbox.insert(tk.END, "Property: " + country)

    def show(self):
        super(PageGovernment, self).show()
        self.refresh_listbox()


class PageHomeOwner(object, Page):
    window_title = "Home Owner"

    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)

    def init(self):
        pass


class PageOTA(object, Page):
    window_title = "OTA"

    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)

    def init(self, page_book_apartment):
        self.page_book_apartment = page_book_apartment

    def show(self):
        super(PageOTA, self).show()
        button = tk.Button(self,
                           text="Book property",
                           command=self.page_book_apartment.show)
        button.pack()


class PageBookProperty(object, Page):
    window_title = "Book property"

    def __init__(self, *args, **kwargs):
        Page.__init__(self, *args, **kwargs)

    def init(self, get_properties, book_property, get_bookings):
        self.get_properties = get_properties
        self.book_property = book_property
        self.get_bookings = get_bookings
        self.property_details = []
        self.selected_property = None

    def onPropertySelected(self, event):
        self.selected_property = int(event.widget.curselection()[0])
        self.refresh_bookings()

    def show(self):
        def book_property():
            error = self.book_property(
                    self.property_details[self.lb_properties.curselection()[0]],
                    tkSimpleDialog.askstring("Input", "Enter the start date (yyyy-mm-dd)"),
                    tkSimpleDialog.askstring("Input", "Enter the end date (yyyy-mm-dd)"))
            if error == 0:
                self.refresh_bookings()
            elif error == 1:
                tkMessageBox.showerror("Error", "Overbooking!")
            elif error == 2:
                tkMessageBox.showerror("Error", "Nightcap exceeded!")

        super(PageBookProperty, self).show()
        self.lb_properties = tk.Listbox(self)
        self.lb_properties.bind("<<ListboxSelect>>", self.onPropertySelected)
        self.lb_properties.pack()

        btn_book_apartment = tk.Button(self,
                                       text="Book property",
                                       command=book_property)
        btn_book_apartment.pack()

        self.lb_bookings = tk.Listbox(self, width=50)
        self.lb_bookings.pack()

        self.refresh_properties()

    def refresh_properties(self):
        self.lb_properties.delete(0, 'end')
        self.property_details = []
        for country, states in self.get_properties().items():
            community_id = {"country": country}
            for state, cities in states.items():
                community_id["state"] = state
                for city, streets in cities.items():
                    community_id["city"] = city
                    for street, numbers in streets.items():
                        community_id["street"] = street
                        for number in numbers:
                            community_id["number"] = number
                            self.property_details.append(community_id)
                            self.lb_properties.insert(tk.END, "Property: " + country)

    def refresh_bookings(self):
        self.lb_bookings.delete(0, 'end')
        for booking in self.get_bookings(self.property_details[self.selected_property]):
            self.lb_bookings.insert(tk.END, "Booking: " + booking["start_day"] + " - " + booking["end_day"])


class MainFrame(object, tk.Frame):
    page_login = None
    page_government = None
    page_home_owner = None
    page_ota = None
    page_book_apartment = None
    controller = None

    def __init__(self, *args, **kwargs):
        tk.Frame.__init__(self, *args, **kwargs)
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)

        self.page_login = PageLogin(self)
        self.page_government = PageGovernment(self)
        self.page_home_owner = PageHomeOwner(self)
        self.page_ota = PageOTA(self)
        self.page_book_apartment = PageBookProperty(self)

        self.page_login.init(self.page_government,
                             self.page_home_owner,
                             self.page_ota,
                             lambda: self.controller.remove_all_created_blocks())
        self.page_government.init(lambda: self.controller.get_communities(),
                                  lambda country, state, city, street,
                                         number: self.controller.create_community(country, state, city, street, number))
        self.page_home_owner.init()
        self.page_ota.init(self.page_book_apartment)
        self.page_book_apartment.init(lambda: self.controller.get_communities(),
                                      lambda property_details, start_day, end_day: self.controller.book_apartment(
                                          property_details, start_day, end_day),
                                      lambda property: self.controller.get_bookings(property))

        self.page_login.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        self.page_government.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        self.page_home_owner.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        self.page_ota.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        self.page_book_apartment.place(in_=container, x=0, y=0, relwidth=1, relheight=1)

        self.page_login.show()


def open_gui(controller):
    root = tk.Tk()
    root.geometry("500x500")
    MainFrame.controller = controller
    frame = MainFrame(root)
    frame.pack(side="top", fill="both", expand=True)
    root.mainloop()
