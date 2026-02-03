import tkinter as tk
from py_xbdm.client import XBDMClient


XBOX_IP = "ENTER_XBOX_IP_HERE" # Replace with your Xbox IP address

xbdm = XBDMClient(XBOX_IP)
xbdm.__enter__()
print("Connected to Xbox")
root = tk.Tk()
root.title("XBDM GUI Test")
info_label = tk.Label(root, text="", justify=tk.CENTER)
info_label.pack(padx=10, pady=10)
def fetch_info():
    console_name = xbdm.console_name()
    cpukey = xbdm.get_cpukey().hex().upper()
    console_type = xbdm.get_console_type()
    console_id = xbdm.get_console_id()
    current_title_id = xbdm.get_current_title_id()
    kernel_version = xbdm.get_kernel_version()
    info_text = (
        f"Console Name: {console_name}\n"
        f"CPU Key: {cpukey}\n"
        f"Console Type: {console_type}\n"
        f"Console ID: {console_id}\n"
        f"Current Title ID: {current_title_id}\n"
        f"Kernel Version: {kernel_version}\n"
    )
    info_label.config(text=info_text)
fetch_button = tk.Button(root, text="Fetch Console Info", command=fetch_info)
fetch_button.pack(pady=5)
root.mainloop()
xbdm.__exit__(None, None, None)
print("Disconnected from Xbox")
