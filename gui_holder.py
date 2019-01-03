import threading
import time

import Tkinter as tk


def delayed_start():
    time.sleep(1)
    root.mainloop()


root = tk.Tk()
root.withdraw()
t1 = threading.Thread(target=delayed_start)
t1.start()
