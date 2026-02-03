from py_xbdm.client import XBDMClient

XBOX_IP = "ENTER_YOUR_XBOX_IP" # Replace with your Xbox IP address

with XBDMClient(XBOX_IP) as xbdm:
    print("Connected to: " + xbdm.console_name())
    cpukey = xbdm.get_cpukey()
    print("CPU Key: " + cpukey.hex().upper())
    console_type = xbdm.get_console_type()
    print("Console Type: " + console_type)
    console_id = xbdm.get_console_id()
    print("Console ID: " + console_id)
    current_title_id = xbdm.get_current_title_id()
    print("Current Title ID: " + current_title_id)
    kernel_version = xbdm.get_kernel_version()
    print("Kernel Version: " + kernel_version)
    address = 0xC200000C
    value = xbdm.read_memory(address, 4)
    print(f"Value at 0x{address:X}: 0x{value.hex().upper()}")
    cbuf_address = 0x8228E1F8
    clientIndex = 0
    #xbdm.call_void(cbuf_address, [clientIndex, "cg_fov 65"]) # Example function call
    #plugin = xbdm.load_module("HDD:\\cheesedick.xex") # Example load module
    xbdm.write_float(0xC200AAD0, 100.0)
    xbdm.__exit__(None, None, None)
    print("Disconnected")
    input("press enter to exit....")
    
