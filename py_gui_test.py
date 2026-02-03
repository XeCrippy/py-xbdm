import tkinter as tk
from py_xbdm.client import XBDMClient


XBOX_IP = "ENTER_YOUR_XBOX_IP" # Replace with your Xbox IP address

def _50_cent_health_patch(enable: bool):
    patch_address = 0x8267DD04
    hook_address = 0x81AA1D30
    original_code = 0x913D0000
    branch_code = 0x4B42402C
    patch_string = "2C0B012C4181000C913D000048BDBFCC3CC081AA60C61E0093A600006000000038C0000048BDBFB4"

    try:
        patch_bytes = bytes.fromhex(patch_string)

        if enable:
            xbdm.write_memory(hook_address, patch_bytes)
            xbdm.write_uint32(patch_address, branch_code)
        else:
            xbdm.write_uint32(patch_address, original_code)
            xbdm.write_memory(hook_address, b'\x00' * len(patch_bytes))
    except Exception as e:
        print(f"Error applying health patch: {e}")

def toggle_health_patch():
    patch_enabled[0] = not patch_enabled[0]
    _50_cent_health_patch(patch_enabled[0])
    status = "enabled" if patch_enabled[0] else "disabled"
    _50_cent_health_button.config(text=f"Infinite Health: ({status})")
    print(f"Health patch {status}")

def mw3_cbuf_sp():
    command = mw3_text_box.get("1.0", tk.END).strip()
    if command:
        try:
            cbuf_address = 0x8228E1F8
            clientIndex = 0
            xbdm.call_void(cbuf_address, [clientIndex, command])
            print(f"Executed command: {command}")
        except Exception as e:
            print(f"Error executing command: {e}")
    

xbdm = XBDMClient(XBOX_IP)
xbdm.__enter__()
print("Connected to Xbox")
root = tk.Tk()
root.title("XBDM GUI Test")
root.geometry("400x450")
root.resizable(False, False)
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
        f"Kernel Version: {kernel_version}"
    )
    info_label.config(text=info_text)


fetch_button = tk.Button(root, text="Fetch Console Info", command=fetch_info)
fetch_button.pack(pady=5)
fetch_button.config(width=20)

title_label = tk.Label(root, text="50 Cent: Blood on the Sand", font=("Arial", 16))
title_label.pack(padx=10, pady=10)

patch_enabled = [False] 
_50_cent_health_button = tk.Button(root, text="Toggle Infinite Health", command=toggle_health_patch)
_50_cent_health_button.pack(pady=5)
_50_cent_health_button.config(width=20)

mw3_label = tk.Label(root, text="Call of Duty: MW3 - Spec Ops", font=("Arial", 16))
mw3_label.pack(padx=10, pady=10)

mw3_label_2 = tk.Label(root, text="Cbuf_AddText", font=("Arial", 10))
mw3_label_2.pack(padx=5, pady=5)

mw3_frame = tk.Frame(root)
mw3_frame.pack(pady=5)
mw3_text_box = tk.Text(mw3_frame, height=1, width=20)
mw3_text_box.pack(side=tk.LEFT, padx=5)
mw3_button = tk.Button(mw3_frame, text="Send Command", command=mw3_cbuf_sp)
mw3_button.pack(side=tk.LEFT, padx=5)
mw3_button.config(width=15)

root.mainloop()
xbdm.__exit__(None, None, None)
print("Disconnected from Xbox")
