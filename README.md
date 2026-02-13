# Xbox 360 XBDM Client Library - API Reference

A Python library for Xbox 360 remote debugging and control via XBDM (Xbox Debug Monitor) protocol.

## Installation
`Required for screenshot functions`
```bash
pip install numpy pillow
```
## Console Prerequisites 
`- xbdm.xex and JRPC2.xex set as plugins`
`- functions that send a command that start with `consolefeatures ver=2....` are JRPC specific. XDRPC uses a similar command for RPC`

## Core Class: XBDMClient

### Initialization & Connection

- **`__init__(host=discovery.xbox_ip())`** — Initialize client with console IP
- **`__enter__()`** — Context manager entry; connects and reads banner
- **`__exit__(exc_type, exc, tb)`** — Context manager exit; closes connection
- **`close()`** — Manually close the connection
- **`reconnect(host=discovery.xbox_ip())`** — Reconnect to a console

### Console Information

- **`console_name() -> str`** — Get console debug name
- **`get_console_id() -> str`** — Get console hardware ID
- **`get_console_type() -> str`** — Get console type/version
- **`get_kernel_version() -> str`** — Get kernel version
- **`get_current_title_id() -> str`** — Get currently running title ID
- **`get_cpukey() -> bytes`** — Get console CPU key (16 bytes)

### Module Management

- **`get_modules() -> list`** — List all loaded modules with base, size, etc.
- **`load_module(module_path: str) -> int`** — Load a module from filesystem
- **`unload_module(module: str)`** — Unload a loaded module

### Memory Operations

#### Reading

- **`read_memory(address: int, size: int) -> bytes`** — Read raw bytes
- **`read_cstring(address: int, max_length: int = 256) -> str`** — Read null-terminated ASCII string
- **`read_wstring(address: int, max_length: int = 256) -> str`** — Read null-terminated UTF-16LE string
- **`read_u16(address: int) -> int`** — Read 16-bit unsigned integer
- **`read_u32(address: int) -> int`** — Read 32-bit unsigned integer
- **`read_u64(address: int) -> int`** — Read 64-bit unsigned integer
- **`read_float(address: int) -> float`** — Read 32-bit float
- **`read_double(address: int) -> float`** — Read 64-bit double

#### Writing

- **`write_memory(address: int, data: bytes)`** — Write raw bytes
- **`write_string(address: int, string: str)`** — Write UTF-8 string
- **`write_wstring(address: int, string: str)`** — Write UTF-16LE string
- **`write_u16(address: int, value: int)`** — Write 16-bit unsigned integer
- **`write_u32(address: int, value: int)`** — Write 32-bit unsigned integer
- **`write_u64(address: int, value: int)`** — Write 64-bit unsigned integer
- **`write_float(address: int, value: float)`** — Write 32-bit float
- **`write_double(address: int, value: float)`** — Write 64-bit double
- **`write_float_vector2(address: int, x: float, y: float)`** — Write 2D float vector
- **`write_float_vector3(address: int, x: float, y: float, z: float)`** — Write 3D float vector
- **`write_u16_array(address: int, values: list)`** — Write array of 16-bit integers
- **`write_u32_array(address: int, values: list)`** — Write array of 32-bit integers
- **`write_u64_array(address: int, values: list)`** — Write array of 64-bit integers
- **`zero_memory(address: int, size: int)`** — Zero-fill memory region

### Function Calling

- **`resolve_function(module_name: str, ordinal: int) -> int`** — Get function address by module name and ordinal
- **`call_function(address: int, args, return_type=INT, system_thread=True)`** — Call function at address with args, return hex string
- **`call_int(address: int, args, system_thread=True) -> int`** — Call function and return as integer
- **`call_void(address: int, args=[], system_thread=True)`** — Call function with no return value

### Code Injection

- **`write_hook(address: int, destination: int, linked: bool)`** — Write PowerPC function hook

### File System Operations

- **`get_directory_contents(remote_path: str) -> list`** — List directory entries with metadata
- **`is_directory(path: str) -> bool`** — Check if path is a directory
- **`create_directory(remotePath: str) -> bool`** — Create a directory
- **`delete_file(remote_path: str, is_directory: bool = False)`** — Delete file or directory
- **`send_file(local_path: str, remote_path: str)`** — Upload file to console
- **`send_directory(local_path: str, remote_path: str)`** — Recursively upload directory
- **`receive_file(remote_path: str, local_path: str)`** — Download file from console
- **`receive_directory(remote_path: str, local_path: str)`** — Recursively download directory

### Screenshot Capture

- **`screenshot(output_path: str | None = None, rawmode: str = "BGRA", untile_mode: str = "xg") -> str`**
  - Capture framebuffer screenshot from console
  - Returns: path to saved PNG file
  - `output_path`: custom save directory (defaults to Pictures or temp)
  - `rawmode`: pixel format ("BGRA", "RGBA", "ARGB", "ABGR")
  - `untile_mode`: Xbox GPU tiling algorithm ("xg" or "morton")
  - **Automatically handles:**
    - Xbox 360 Xenos GPU framebuffer untiling (18x faster via NumPy)
    - Pixel format conversion
    - Display vs. framebuffer resolution
    - Offset render targets
    - Android `/storage/emulated/0/Pictures/` paths
    - Windows `%USERPROFILE%\Pictures\` paths

### Debugging

- **`debug_go()`** — Resume console execution
- **`debug_stop()`** — Pause console execution

### System Control

- **`shutdown_console()`** — Shut down the console
- **`set_system_time(unix_time: int)`** — Set console system time (Unix epoch)
- **`synchronize_time()`** — Sync console time to PC clock
- **`xnotify(text: str, type: int = 34)`** — Show notification on console

### Protocol & Utilities

- **`send_command(command: str)`** — Send raw XBDM command, get response
- **`send_binary(data: bytes)`** — Send raw binary data
- **`send_multiline_command(command: str) -> list`** — Send command expecting multi-line response
- **`encode_argument(arg)`** — Encode argument for function calls
- **`timet_to_filetime(unix_time: int) -> int`** — Convert Unix time to Windows FILETIME
- **`parse_hex_field(text: str, key: str) -> int`** — Extract hex value from response
- **`screenshot_name() -> str`** — Generate timestamped filename

---

## Constants

```python
# Function return types
XBDMClient.VOID        = 0
XBDMClient.INT         = 1
XBDMClient.FLOAT       = 3
XBDMClient.BYTE        = 4
XBDMClient.STRING      = 2
XBDMClient.UINT64      = 8

# Array types
XBDMClient.INT_ARRAY   = 5
XBDMClient.FLOAT_ARRAY = 6
XBDMClient.BYTE_ARRAY  = 7
XBDMClient.UINT64_ARRAY= 9
```

---

## Usage Examples

### Basic Connection

```python
from py_xbdm.client import XBDMClient

with XBDMClient(discovery.xbox_ip()) as xbdm:
    print(xbdm.console_name())
    print(xbdm.get_console_id())
```

### Reading Memory

```python
data = xbdm.read_memory(0x80000000, 16)
value = xbdm.read_u32(0x80000000)
string = xbdm.read_cstring(0x80000000, max_length=256)
```

### Calling Functions

```python
# Resolve function address
addr = xbdm.resolve_function("xboxkrnl.exe", 409)

# Call with arguments
result = xbdm.call_int(addr, [arg1, arg2, arg3])
```

### Taking Screenshots

```python
# Default behavior (to Pictures folder)
path = xbdm.screenshot()

# Custom location
path = xbdm.screenshot("/custom/path/screenshots")

# Different pixel formats
path = xbdm.screenshot(rawmode="RGBA")
```

### File Operations

```python
# Upload
xbdm.send_file("local_file.bin", "hdd:\\local.bin")

# Download
xbdm.receive_file("hdd:\\console_file.bin", "local_copy.bin")

# List directory
files = xbdm.get_directory_contents("hdd:\\")
for f in files:
    print(f"{f['name']} - {'dir' if f['is_directory'] else 'file'}")
```

---

## Features

✅ **Full XBDM Protocol Support** — Memory read/write, function calls, file transfers  
✅ **Screenshot Capture** — Xbox 360 Xenos GPU untiling with 18x NumPy acceleration  
✅ **Cross-Platform** — Windows, Android, Linux support  
✅ **Module Loading** — Load and unload console modules  
✅ **File System** — Full directory traversal and transfer  
✅ **Debug Control** — Pause/resume execution, set breakpoints  
✅ **System Control** — Time sync, notifications, shutdown  

---

## Error Handling

All methods raise `RuntimeError` on protocol errors. Always use try/except when calling methods that interact with the console:

```python
try:
    xbdm.screenshot()
except RuntimeError as e:
    print(f"Screenshot failed: {e}")
```

---

## Notes

- All multi-byte writes use big-endian (PowerPC)
- Screenshots are automatically saved as PNG with proper color space conversion
- Android paths default to `/storage/emulated/0/Pictures/Solace 360 Screenshots/`

---

## Credits & References

### Dependencies

- **[NumPy](https://numpy.org/)** — High-performance array computing; used for vectorized Xbox 360 framebuffer untiling (18x speedup)
- **[Pillow (PIL)](https://python-pillow.org/)** — Python Imaging Library; handles framebuffer image conversion, cropping, and PNG encoding

### Technical References

- **[Xenia Xbox 360 Emulator](https://github.com/xenia-project/xenia)** — Open-source Xbox 360 emulator; `texture_address::Tiled2D` untiling algorithm adapted from Xenia's GPU texture address calculations
- **Xbox 360 Xenos GPU** — Framebuffer tiling uses XG (XBox Graphics) 2D tiled addressing with bank/pipe interleaving
- **XBDM Protocol** — Xbox Debug Monitor protocol for remote debugging and console control

### Acknowledgments

- Framebuffer untiling algorithm based on reverse engineering by Xenia project contributors
- Xbox 360 tiling mathematics derived from AMD GPU addressing specifications
- Features inspired by community Xbox modding tools and emulator development

---

*This library is provided as-is for educational and development purposes.*







